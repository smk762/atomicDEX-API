use crate::utxo::rpc_clients::{NativeClient, UtxoRpcClientEnum, UtxoRpcError, UtxoRpcFut};
use bigdecimal::BigDecimal;
use common::jsonrpc_client::{JsonRpcClient, JsonRpcRequest};
use common::mm_error::prelude::*;
use common::mm_number::MmNumber;
use rpc::v1::types::{Bytes as BytesJson, H256 as H256Json, H264 as H264Json};
use serde_json::{self as json, Value as Json};

#[derive(Debug, Serialize)]
pub struct ZSendManyItem {
    pub amount: BigDecimal,
    #[serde(rename = "opreturn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return: Option<BytesJson>,
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct ZOperationTxid {
    pub txid: H256Json,
}

#[derive(Debug, Deserialize)]
pub struct ZOperationHex {
    pub hex: BytesJson,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status")]
#[serde(rename_all = "lowercase")]
pub enum ZOperationStatus<T> {
    Success {
        id: String,
        creation_time: u64,
        result: T,
        execution_secs: f64,
        method: String,
        params: Json,
    },
    Executing {
        id: String,
        creation_time: u64,
        method: String,
        params: Json,
    },
    Failed {
        id: String,
        creation_time: u64,
        method: String,
        params: Json,
        error: Json,
    },
}

#[derive(Debug, Serialize)]
pub struct ZSendManyHtlcParams {
    pub pubkey: H264Json,
    pub refund_pubkey: H264Json,
    pub secret_hash: BytesJson,
    pub input_txid: H256Json,
    pub input_index: usize,
    pub input_amount: BigDecimal,
    pub locktime: u32,
}

pub trait ZRpcOps {
    fn z_get_balance(&self, address: &str, min_conf: u32) -> UtxoRpcFut<MmNumber>;

    fn z_get_send_many_status(&self, op_ids: &[&str]) -> UtxoRpcFut<Vec<ZOperationStatus<ZOperationTxid>>>;

    fn z_get_send_many_template_status(&self, op_ids: &[&str]) -> UtxoRpcFut<Vec<ZOperationStatus<ZOperationHex>>>;

    fn z_send_many(&self, from_address: &str, send_to: Vec<ZSendManyItem>) -> UtxoRpcFut<String>;

    // ./komodo-cli -ac_name=VAMPIRE z_sendmany_template "RK9rNQ4j6MUPwKXWtcM6QXj9mSYortUSEc" '[{"address":"zs1pqy7pmstkq24sxu77uczjqmm58rquzvhslnct6cnlhjz8jm686w2huel93lx2kdk7c9yx2lvty2", "amount":0.9999}]' '{"pubkey":"037310a8fb9fd8f198a1a21db830252ad681fccda580ed4101f3f6bfb98b34fab5", "refund_pubkey":"031c632dad67a611de77d9666cbc61e65957c7d7544c25e384f4e76de729e6a1bf", "secret_hash":"b78f0b837e2c710f8b28e59d06473d489e5315c8", "input_txid":"0000000000000000000000000000000000000000000000000000000000000000", "input_index":0, "input_amount":"100000000", "locktime":1619038949}'
    fn z_send_many_template(
        &self,
        from_addr: &str,
        to: Vec<ZSendManyItem>,
        htlc_params: ZSendManyHtlcParams,
    ) -> UtxoRpcFut<String>;
}

impl ZRpcOps for NativeClient {
    fn z_get_balance(&self, address: &str, min_conf: u32) -> UtxoRpcFut<MmNumber> {
        let fut = rpc_func!(self, "z_getbalance", address, min_conf);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_get_send_many_status(&self, op_ids: &[&str]) -> UtxoRpcFut<Vec<ZOperationStatus<ZOperationTxid>>> {
        let fut = rpc_func!(self, "z_getoperationstatus", op_ids);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_get_send_many_template_status(&self, op_ids: &[&str]) -> UtxoRpcFut<Vec<ZOperationStatus<ZOperationHex>>> {
        let fut = rpc_func!(self, "z_getoperationstatus", op_ids);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_send_many(&self, from_address: &str, send_to: Vec<ZSendManyItem>) -> UtxoRpcFut<String> {
        let fut = rpc_func!(self, "z_sendmany", from_address, send_to);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_send_many_template(
        &self,
        from_addr: &str,
        to: Vec<ZSendManyItem>,
        htlc_params: ZSendManyHtlcParams,
    ) -> UtxoRpcFut<String> {
        let fut = rpc_func!(self, "z_sendmany_template", from_addr, to, htlc_params);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }
}

impl AsRef<dyn ZRpcOps + Send + Sync> for UtxoRpcClientEnum {
    fn as_ref(&self) -> &(dyn ZRpcOps + Send + Sync + 'static) {
        match self {
            UtxoRpcClientEnum::Native(native) => native,
            UtxoRpcClientEnum::Electrum(_) => panic!("Electrum client does not support ZRpcOps"),
        }
    }
}
