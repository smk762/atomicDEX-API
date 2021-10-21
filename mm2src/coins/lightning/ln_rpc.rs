use crate::utxo::rpc_clients::{electrum_script_hash, ElectrumClient, UtxoRpcClientEnum, UtxoRpcClientOps, UtxoRpcError};
use crate::utxo::utxo_common;
use crate::utxo::utxo_standard::UtxoStandardCoin;
use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::hash_types::{BlockHash, Txid};
use common::block_on;
use common::log::error;
use common::mm_error::prelude::MapToMmFutureExt;
use futures::compat::Future01CompatExt;
use lightning::chain::{chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator},
                       Filter, WatchedOutput};
use lightning_block_sync::{AsyncBlockSourceResult, BlockHeaderData, BlockSource};
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
        let tx_bytes = BytesJson::from(encode::serialize_hex(tx).as_bytes());
        let _ = Box::new(
            self.blockchain_transaction_broadcast(tx_bytes)
                .map_to_mm_fut(UtxoRpcError::from),
        );
    }
}

impl Filter for UtxoStandardCoin {
    // Watches for this transaction on-chain
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        utxo_common::register_tx(&self.as_ref(), txid, script_pubkey)
    }

    // Watches for any transactions that spend this output on-chain
    fn register_output(&self, output: WatchedOutput) -> Option<(usize, Transaction)> {
        utxo_common::register_output(&self.as_ref(), output.clone());

        output.block_hash?;

        let client = match &self.as_ref().rpc_client {
            UtxoRpcClientEnum::Electrum(e) => e.clone(),
            UtxoRpcClientEnum::Native(_) => {
                error!("As of now Only electrum client is supported for lightning");
                return None;
            },
        };
        let script_hash = hex::encode(electrum_script_hash(output.script_pubkey.as_ref()));
        let history = block_on(client.scripthash_get_history(&script_hash).compat()).unwrap_or_default();

        if history.len() < 2 {
            return None;
        }

        for item in history.iter() {
            let transaction = match block_on(client.get_transaction_bytes(item.tx_hash.clone()).compat()) {
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
}

impl BlockSource for ElectrumClient {
    // Retrieves the header corresponding to header_hash
    #[allow(clippy::needless_lifetimes)]
    fn get_header<'a>(
        &'a mut self,
        _header_hash: &'a BlockHash,
        _height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        unimplemented!()
    }

    // Retrieves the block corresponding to header_hash
    #[allow(clippy::needless_lifetimes)]
    fn get_block<'a>(&'a mut self, _header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
        unimplemented!()
    }

    // Retrieve the best known block hash and height
    #[allow(clippy::needless_lifetimes)]
    fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> { unimplemented!() }
}
