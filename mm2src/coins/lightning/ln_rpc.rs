use crate::utxo::rpc_clients::{electrum_script_hash, ElectrumClient, UtxoRpcClientEnum, UtxoRpcClientOps};
use crate::utxo::utxo_common;
use crate::utxo::utxo_standard::UtxoStandardCoin;
#[cfg(not(target_arch = "wasm32"))]
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::hash_types::Txid;
use common::executor::spawn;
use common::{block_on, log};
use futures::compat::Future01CompatExt;
use hex::FromHex;
use lightning::chain::{chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator},
                       Filter, WatchedOutput};
use rpc::v1::types::Bytes as BytesJson;

impl FeeEstimator for ElectrumClient {
    // Gets estimated satoshis of fee required per 1000 Weight-Units.
    // TODO: use fn estimate_fee instead of fixed number when starting work on opening channels
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        match confirmation_target {
            // fetch background feerate
            ConfirmationTarget::Background => 253,
            // fetch normal feerate (~6 blocks)
            ConfirmationTarget::Normal => 2000,
            // fetch high priority feerate
            ConfirmationTarget::HighPriority => 5000,
        }
    }
}

impl BroadcasterInterface for ElectrumClient {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let tx_hex = encode::serialize_hex(tx);
        let tx_bytes =
            BytesJson::new(Vec::from_hex(tx_hex.clone()).expect("Transaction serialization should not fail!"));
        log::debug!("Trying to broadcast transaction: {}", tx_hex);
        let tx_id = tx.txid();
        let fut = self.blockchain_transaction_broadcast(tx_bytes);
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
    let client = match &coin.as_ref().rpc_client {
        UtxoRpcClientEnum::Electrum(e) => e.clone(),
        UtxoRpcClientEnum::Native(_) => {
            log::error!("As of now Only electrum client is supported for lightning");
            return None;
        },
    };

    let script_hash = hex::encode(electrum_script_hash(output.script_pubkey.as_ref()));
    let history = client
        .scripthash_get_history(&script_hash)
        .compat()
        .await
        .unwrap_or_default();

    if history.len() < 2 {
        return None;
    }

    for item in history.iter() {
        let transaction = match coin
            .as_ref()
            .rpc_client
            .get_verbose_transaction(&item.tx_hash.clone())
            .compat()
            .await
        {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        let maybe_spend_tx: Transaction = match encode::deserialize(&transaction.hex.clone().into_vec()) {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        for (index, input) in maybe_spend_tx.input.iter().enumerate() {
            if input.previous_output.txid == output.outpoint.txid
                && input.previous_output.vout == output.outpoint.index as u32
            {
                match transaction.height {
                    Some(height) => match client.blockchain_block_header(height).compat().await {
                        Ok(header) => {
                            let header = encode::deserialize(&header).expect("Can't deserialize block header");
                            return Some((header, index, maybe_spend_tx, height));
                        },
                        Err(_) => continue,
                    },
                    None => continue,
                }
            }
        }
    }
    None
}

pub async fn find_watched_output_spend(coin: &UtxoStandardCoin, output: WatchedOutput) -> Option<(usize, Transaction)> {
    let client = match &coin.as_ref().rpc_client {
        UtxoRpcClientEnum::Electrum(e) => e.clone(),
        UtxoRpcClientEnum::Native(_) => {
            log::error!("As of now Only electrum client is supported for lightning");
            return None;
        },
    };

    let script_hash = hex::encode(electrum_script_hash(output.script_pubkey.as_ref()));
    let history = client
        .scripthash_get_history(&script_hash)
        .compat()
        .await
        .unwrap_or_default();

    if history.len() < 2 {
        return None;
    }

    for item in history.iter() {
        let transaction = match client.get_transaction_bytes(item.tx_hash.clone()).compat().await {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        let maybe_spend_tx: Transaction = match encode::deserialize(transaction.as_slice()) {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        for (index, input) in maybe_spend_tx.input.iter().enumerate() {
            if input.previous_output.txid == output.outpoint.txid
                && input.previous_output.vout == output.outpoint.index as u32
            {
                return Some((index, maybe_spend_tx));
            }
        }
    }
    None
}

impl Filter for UtxoStandardCoin {
    // Watches for this transaction on-chain
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        block_on(utxo_common::register_tx(&self.as_ref(), txid, script_pubkey));
    }

    // Watches for any transactions that spend this output on-chain
    fn register_output(&self, output: WatchedOutput) -> Option<(usize, Transaction)> {
        block_on(utxo_common::register_output(&self.as_ref(), output.clone()));

        output.block_hash?;

        block_on(find_watched_output_spend(&self, output))
    }
}
