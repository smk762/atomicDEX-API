#[cfg(not(target_arch = "wasm32"))]
use crate::utxo::rpc_clients::UtxoRpcClientEnum;
use crate::utxo::rpc_clients::{BlockHashOrHeight, EstimateFeeMethod};
use crate::utxo::utxo_common;
use crate::utxo::utxo_standard::UtxoStandardCoin;
use crate::{MarketCoinOps, MmCoin};
#[cfg(not(target_arch = "wasm32"))]
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::hash_types::Txid;
use bitcoin_hashes::Hash;
use common::executor::spawn;
use common::{block_on, log};
use futures::compat::Future01CompatExt;
use lightning::chain::{chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator},
                       Filter, WatchedOutput};
use rpc::v1::types::H256;

impl FeeEstimator for UtxoStandardCoin {
    // Gets estimated satoshis of fee required per 1000 Weight-Units.
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        let conf = &self.as_ref().conf;
        // TODO: Maybe default_fee and confirmation targets can be set in coin configs or lightning configs (would require to move lightning config to coin config) instead
        let default_fee = match confirmation_target {
            // fetch background feerate
            ConfirmationTarget::Background => 253,
            // fetch normal feerate (~6 blocks)
            ConfirmationTarget::Normal => 2000,
            // fetch high priority feerate
            ConfirmationTarget::HighPriority => 5000,
        } * 4;

        let n_blocks = match confirmation_target {
            // fetch background feerate
            ConfirmationTarget::Background => 12,
            // fetch normal feerate (~6 blocks)
            ConfirmationTarget::Normal => 6,
            // fetch high priority feerate
            ConfirmationTarget::HighPriority => 1,
        };
        let fee_per_kb = block_on(
            self.as_ref()
                .rpc_client
                .estimate_fee_sat(
                    self.decimals(),
                    &EstimateFeeMethod::SmartFee,
                    &conf.estimate_fee_mode,
                    n_blocks,
                )
                .compat(),
        )
        .unwrap_or(default_fee);
        (fee_per_kb as f64 / 4.0).ceil() as u32
    }
}

impl BroadcasterInterface for UtxoStandardCoin {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let tx_hex = encode::serialize_hex(tx);
        log::debug!("Trying to broadcast transaction: {}", tx_hex);
        let tx_id = tx.txid();
        let fut = self.send_raw_tx(&tx_hex);
        spawn(async move {
            match fut.compat().await {
                Ok(id) => log::info!("Transaction broadcasted successfully: {:?} ", id),
                Err(e) => log::error!("Broadcast transaction {} failed: {}", tx_id, e),
            }
        });
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn find_watched_output_spend_with_header(
    coin: &UtxoStandardCoin,
    output: WatchedOutput,
) -> Option<(BlockHeader, usize, Transaction, u64)> {
    let client = &coin.as_ref().rpc_client;

    // For native clients LDK uses the Listen interface instead of the filter and confirm interfaces which are used for electrum clients.
    // That's why find_watched_output_spend_with_header should be used only with electrum clients
    // https://docs.rs/lightning/0.0.103/lightning/chain/trait.Confirm.html
    // https://docs.rs/lightning/0.0.103/lightning/chain/trait.Listen.html
    let electrum_client = match client {
        UtxoRpcClientEnum::Electrum(e) => e,
        UtxoRpcClientEnum::Native(_) => {
            log::error!("find_watched_output_spend_with_header should be used only with electrum clients!");
            return None;
        },
    };

    let block_hash = output.block_hash.map(|h| H256::from(h.as_hash().into_inner()));

    // from_block parameter is not used in find_output_spend for electrum clients
    // That's why its not a problem if the block hash is none in WatchedOutput
    // the block hash parameter in WatchedOutput is used by LDK only to indicate for the implementation of register_output
    // if to look for if the output is spent or not, thus removing the need for doing an unnecessary call while implementing
    // register_output. LDK assigns block hash a value or not depending on where it's used in LDK code.
    let output_spend = match client
        .find_output_spend(
            output.outpoint.txid.as_hash().into_inner().into(),
            output.script_pubkey.as_ref(),
            output.outpoint.index.into(),
            BlockHashOrHeight::Hash(block_hash.unwrap_or_default()),
        )
        .compat()
        .await
    {
        Ok(Some(output)) => output,
        _ => return None,
    };

    match output_spend.spent_in_block {
        BlockHashOrHeight::Height(height) => {
            match electrum_client.blockchain_block_header(height as u64).compat().await {
                Ok(header) => {
                    let header = encode::deserialize(&header).expect("Can't deserialize block header");
                    Some((
                        header,
                        output_spend.input_index,
                        output_spend.spending_tx.into(),
                        height as u64,
                    ))
                },
                Err(_) => None,
            }
        },
        BlockHashOrHeight::Hash(_) => None,
    }
}

impl Filter for UtxoStandardCoin {
    // Watches for this transaction on-chain
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        block_on(utxo_common::register_tx(&self.as_ref(), txid, script_pubkey));
    }

    // Watches for any transactions that spend this output on-chain
    fn register_output(&self, output: WatchedOutput) -> Option<(usize, Transaction)> {
        block_on(utxo_common::register_output(&self.as_ref(), output.clone()));

        let block_hash = match output.block_hash {
            Some(h) => H256::from(h.as_hash().into_inner()),
            None => return None,
        };

        let client = &self.as_ref().rpc_client;
        // Although this works for both native and electrum clients as the block hash is available,
        // the filter interface which includes register_output and register_tx should be used for electrum clients only,
        // this is the reason for initializing the filter as an option in the start_lightning function as it will be None
        // when implementing lightning for native clients
        let output_spend_fut = client.find_output_spend(
            output.outpoint.txid.as_hash().into_inner().into(),
            output.script_pubkey.as_ref(),
            output.outpoint.index.into(),
            BlockHashOrHeight::Hash(block_hash),
        );

        match block_on(output_spend_fut.compat()) {
            Ok(Some(spent_output_info)) => Some((spent_output_info.input_index, spent_output_info.spending_tx.into())),
            Ok(None) => None,
            Err(e) => {
                log::error!("Error when calling register_output: {}", e);
                None
            },
        }
    }
}
