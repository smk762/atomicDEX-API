use crate::utxo::rpc_clients::{NativeClient, UtxoRpcClientEnum, UtxoRpcError, UtxoRpcFut};
use bigdecimal::BigDecimal;
use common::jsonrpc_client::{JsonRpcClient, JsonRpcRequest};
use common::mm_error::prelude::*;
use common::mm_number::MmNumber;
use rpc::v1::types::{Bytes as BytesJson, H256 as H256Json};
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
pub struct ZOperationResult {
    pub txid: H256Json,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status")]
#[serde(rename_all = "lowercase")]
pub enum ZOperationStatus {
    Success {
        id: String,
        creation_time: u64,
        result: ZOperationResult,
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

pub trait ZRpcOps {
    fn z_get_balance(&self, address: &str, min_conf: u32) -> UtxoRpcFut<MmNumber>;

    fn z_get_operation_status(&self, op_ids: &[&str]) -> UtxoRpcFut<Vec<ZOperationStatus>>;

    fn z_send_many(&self, from_address: &str, send_to: Vec<ZSendManyItem>) -> UtxoRpcFut<String>;

    fn z_send_many_template(&self) -> UtxoRpcFut<BytesJson>;
}

impl ZRpcOps for NativeClient {
    fn z_get_balance(&self, address: &str, min_conf: u32) -> UtxoRpcFut<MmNumber> {
        let fut = rpc_func!(self, "z_getbalance", address, min_conf);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_get_operation_status(&self, op_ids: &[&str]) -> UtxoRpcFut<Vec<ZOperationStatus>> {
        let fut = rpc_func!(self, "z_getoperationstatus", op_ids);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_send_many(&self, from_address: &str, send_to: Vec<ZSendManyItem>) -> UtxoRpcFut<String> {
        let fut = rpc_func!(self, "z_sendmany", from_address, send_to);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_send_many_template(&self) -> UtxoRpcFut<BytesJson> { unimplemented!() }
}

impl AsRef<dyn ZRpcOps + Send + Sync> for UtxoRpcClientEnum {
    fn as_ref(&self) -> &(dyn ZRpcOps + Send + Sync + 'static) {
        match self {
            UtxoRpcClientEnum::Native(native) => native,
            UtxoRpcClientEnum::Electrum(_) => panic!("Electrum client does not support ZRpcOps"),
        }
    }
}
