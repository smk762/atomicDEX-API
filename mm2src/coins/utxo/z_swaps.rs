use crate::utxo::rpc_clients::{ElectrumClient, NativeClient, UtxoRpcError, UtxoRpcFut};
use crate::utxo::UtxoArc;
use bigdecimal::BigDecimal;
use common::jsonrpc_client::{JsonRpcClient, JsonRpcRequest};
use common::mm_error::prelude::*;
use rpc::v1::types::Bytes as BytesJson;
use serde_json::{self as json};

#[derive(Clone, Debug)]
pub struct ZAddrCoin {
    utxo_arc: UtxoArc,
}

#[derive(Serialize)]
pub struct ZSendManyItem {
    amount: BigDecimal,
    #[serde(rename = "op_return")]
    #[serde(skip_serializing_if = "Option::is_none")]
    op_return: Option<BytesJson>,
    address: String,
}

pub trait ZRpcOps {
    fn z_send_many(&self, from_address: &str, send_to: Vec<ZSendManyItem>) -> UtxoRpcFut<String>;

    fn z_send_many_template(&self) -> UtxoRpcFut<BytesJson>;
}

impl ZRpcOps for NativeClient {
    fn z_send_many(&self, from_address: &str, send_to: Vec<ZSendManyItem>) -> UtxoRpcFut<String> {
        let fut = rpc_func!(self, "z_send_many", from_address, send_to);
        Box::new(fut.map_to_mm_fut(UtxoRpcError::from))
    }

    fn z_send_many_template(&self) -> UtxoRpcFut<BytesJson> { unimplemented!() }
}

impl ZRpcOps for ElectrumClient {
    fn z_send_many(&self, _from_address: &str, _send_to: Vec<ZSendManyItem>) -> UtxoRpcFut<String> { unimplemented!() }

    fn z_send_many_template(&self) -> UtxoRpcFut<BytesJson> { unimplemented!() }
}
