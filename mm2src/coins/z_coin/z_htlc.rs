use super::z_rpc::{ZOperationStatus, ZOperationTxid, ZSendManyItem};
use super::ZCoin;
use crate::utxo::rpc_clients::UtxoRpcError;
use crate::utxo::utxo_common::payment_script;
use bigdecimal::BigDecimal;
use bitcrypto::dhash160;
use chain::Transaction as UtxoTx;
use common::executor::Timer;
use common::mm_error::prelude::*;
use derive_more::Display;
use futures::compat::Future01CompatExt;
use keys::{Address, Error as KeysError, Public};
use script::Script;
use secp256k1_bindings::SecretKey;
use serialization::deserialize;
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::consensus;
use zcash_primitives::constants::mainnet as z_mainnet_constants;
use zcash_primitives::legacy::Script as ZCashScript;
use zcash_primitives::transaction::builder::{Builder as ZTxBuilder, Error as ZTxBuilderError};
use zcash_primitives::transaction::components::{Amount, OutPoint as ZCashOutpoint, TxOut};
use zcash_proofs::prover::LocalTxProver;

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum ZSendHtlcError {
    ParseOtherPubFailed(KeysError),
    #[display(fmt = "z operation failed with statuses {:?}", _0)]
    ZOperationFailed(Vec<ZOperationStatus<ZOperationTxid>>),
    ZOperationStatusesEmpty,
    RpcError(UtxoRpcError),
}

impl From<KeysError> for ZSendHtlcError {
    fn from(keys: KeysError) -> ZSendHtlcError { ZSendHtlcError::ParseOtherPubFailed(keys) }
}

impl From<UtxoRpcError> for ZSendHtlcError {
    fn from(rpc: UtxoRpcError) -> ZSendHtlcError { ZSendHtlcError::RpcError(rpc) }
}

/// Sends HTLC output from the coin's z_addr
pub async fn z_send_htlc(
    coin: &ZCoin,
    time_lock: u32,
    other_pub: &[u8],
    secret_hash: &[u8],
    amount: BigDecimal,
) -> Result<UtxoTx, MmError<ZSendHtlcError>> {
    let taker_pub = Public::from_slice(other_pub).map_to_mm(ZSendHtlcError::from)?;
    let payment_script = payment_script(time_lock, secret_hash, coin.utxo_arc.key_pair.public(), &taker_pub);
    let hash = dhash160(&payment_script);
    let htlc_address = Address {
        prefix: coin.utxo_arc.conf.p2sh_addr_prefix,
        t_addr_prefix: coin.utxo_arc.conf.p2sh_t_addr_prefix,
        hash,
        checksum_type: coin.utxo_arc.conf.checksum_type,
    };

    let from_addr = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &coin.z_addr);
    let send_item = ZSendManyItem {
        amount,
        op_return: Some(payment_script.to_vec().into()),
        address: htlc_address.to_string(),
    };

    let op_id = coin.z_rpc().z_send_many(&from_addr, vec![send_item]).compat().await?;

    loop {
        let operation_statuses = coin.z_rpc().z_get_send_many_status(&[&op_id]).compat().await?;

        match operation_statuses.first() {
            Some(ZOperationStatus::Executing { .. }) | Some(ZOperationStatus::Queued { .. }) => {
                Timer::sleep(1.).await;
                continue;
            },
            Some(ZOperationStatus::Failed { .. }) => {
                break Err(MmError::new(ZSendHtlcError::ZOperationFailed(operation_statuses)));
            },
            Some(ZOperationStatus::Success { result, .. }) => {
                let tx_bytes = coin
                    .rpc_client()
                    .get_transaction_bytes(result.txid.clone())
                    .compat()
                    .await?;
                let tx: UtxoTx = deserialize(tx_bytes.0.as_slice()).expect("rpc returns valid tx bytes");
                break Ok(tx);
            },
            None => break Err(MmError::new(ZSendHtlcError::ZOperationStatusesEmpty)),
        }
    }
}

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum ZP2SHSpendError {
    ZTxBuilderError(ZTxBuilderError),
    Rpc(UtxoRpcError),
}

impl From<ZTxBuilderError> for ZP2SHSpendError {
    fn from(tx_builder: ZTxBuilderError) -> ZP2SHSpendError { ZP2SHSpendError::ZTxBuilderError(tx_builder) }
}

impl From<UtxoRpcError> for ZP2SHSpendError {
    fn from(rpc: UtxoRpcError) -> ZP2SHSpendError { ZP2SHSpendError::Rpc(rpc) }
}

/// Spends P2SH output 0 to the coin's z_addr
pub async fn z_p2sh_spend(
    coin: &ZCoin,
    p2sh_tx: UtxoTx,
    tx_locktime: u32,
    input_sequence: u32,
    redeem_script: Script,
    script_data: Script,
) -> Result<UtxoTx, MmError<ZP2SHSpendError>> {
    let current_block = coin.utxo_arc.rpc_client.get_block_count().compat().await? as u32;
    let mut tx_builder = ZTxBuilder::new(consensus::MAIN_NETWORK, current_block.into());
    tx_builder.set_lock_time(tx_locktime);

    let secp_secret =
        SecretKey::from_slice(&*coin.utxo_arc.key_pair.private().secret).expect("Keypair contains a valid secret key");

    let outpoint = ZCashOutpoint::new(p2sh_tx.hash().into(), 0);
    let tx_out = TxOut {
        value: Amount::from_u64(p2sh_tx.outputs[0].value).expect("p2sh_tx transaction always contains valid amount"),
        script_pubkey: ZCashScript(redeem_script.to_vec()),
    };
    tx_builder
        .add_transparent_input(
            secp_secret,
            outpoint,
            input_sequence,
            ZCashScript(script_data.to_vec()),
            tx_out,
        )
        .map_to_mm(ZP2SHSpendError::from)?;
    tx_builder
        .add_sapling_output(
            None,
            coin.z_addr.clone(),
            Amount::from_u64(p2sh_tx.outputs[0].value - 1000).unwrap(),
            None,
        )
        .map_to_mm(ZP2SHSpendError::from)?;
    let prover = LocalTxProver::bundled();
    let (zcash_tx, _) = tx_builder
        .build(consensus::BranchId::Sapling, &prover)
        .map_to_mm(ZP2SHSpendError::from)?;
    let mut tx_buffer = Vec::with_capacity(1024);
    zcash_tx.write(&mut tx_buffer).unwrap();
    let refund_tx: UtxoTx = deserialize(tx_buffer.as_slice()).expect("librustzcash should produce a valid tx");
    coin.rpc_client()
        .send_raw_transaction(tx_buffer.into())
        .compat()
        .await?;
    Ok(refund_tx)
}
