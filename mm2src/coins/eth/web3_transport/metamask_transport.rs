use crate::eth::web3_transport::Web3SendOut;
use crate::RpcTransportEventHandlerShared;
use crypto::MetamaskWeak;
use jsonrpc_core::{Call, Params};
use mm2_err_handle::prelude::*;
use mm2_metamask::{detect_metamask_provider, Eip1193Provider, MetamaskError, MetamaskResult};
use serde_json::Value as Json;
use std::fmt;
use web3::error::{Error, TransportError};
use web3::helpers::build_request;
use web3::{RequestId, Transport};

#[derive(Clone)]
pub struct MetamaskTransport {
    eip1193: Eip1193Provider,
    // TODO use `even_handlers` properly.
    _event_handlers: Vec<RpcTransportEventHandlerShared>,
}

impl MetamaskTransport {
    pub fn detect(event_handlers: Vec<RpcTransportEventHandlerShared>) -> MetamaskResult<MetamaskTransport> {
        let eip1193 = detect_metamask_provider()?;
        Ok(MetamaskTransport {
            eip1193,
            _event_handlers: event_handlers,
        })
    }
}

impl Transport for MetamaskTransport {
    type Out = Web3SendOut;

    fn prepare(&self, method: &str, params: Vec<Json>) -> (RequestId, Call) { self.eip1193.prepare(method, params) }

    fn send(&self, id: RequestId, request: Call) -> Self::Out { self.eip1193.send(id, request) }
}

impl fmt::Debug for MetamaskTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "MetamaskTransport") }
}
