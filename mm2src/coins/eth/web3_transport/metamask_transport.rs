use crate::eth::web3_transport::Web3SendOut;
use crate::RpcTransportEventHandlerShared;
use crypto::MetamaskWeak;
use jsonrpc_core::Call;
use mm2_metamask::{detect_metamask_provider, Eip1193Provider, MetamaskResult, MetamaskSession};
use serde_json::Value as Json;
use std::fmt;
use std::sync::Arc;
use web3::{RequestId, Transport};

pub struct EthConfig {
    pub chain_id: u64,
}

#[derive(Clone)]
pub struct MetamaskTransport {
    inner: Arc<MetamaskTransportInner>,
}

struct MetamaskTransportInner {
    metamask_weak: MetamaskWeak,
    eth_config: EthConfig,
    eip1193: Eip1193Provider,
    // TODO use `even_handlers` properly.
    _event_handlers: Vec<RpcTransportEventHandlerShared>,
}

impl MetamaskTransport {
    pub fn detect(
        metamask_weak: MetamaskWeak,
        chain_id: u64,
        event_handlers: Vec<RpcTransportEventHandlerShared>,
    ) -> MetamaskResult<MetamaskTransport> {
        let eip1193 = detect_metamask_provider()?;
        let inner = MetamaskTransportInner {
            metamask_weak,
            eth_config: EthConfig { chain_id },
            eip1193,
            _event_handlers: event_handlers,
        };
        Ok(MetamaskTransport { inner: Arc::new(inner) })
    }
}

impl Transport for MetamaskTransport {
    type Out = Web3SendOut;

    fn prepare(&self, method: &str, params: Vec<Json>) -> (RequestId, Call) {
        self.inner.eip1193.prepare(method, params)
    }

    fn send(&self, id: RequestId, request: Call) -> Self::Out {
        let selfi = self.clone();
        let fut = async move { selfi.send_impl(id, request).await };
        Box::pin(fut)
    }
}

impl fmt::Debug for MetamaskTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "MetamaskTransport") }
}

impl MetamaskTransport {
    async fn send_impl(&self, id: RequestId, request: Call) -> Result<Json, web3::Error> {
        // Hold the mutex guard until the request is finished.
        let _rpc_lock = self.request_preparation().await?;
        self.inner.eip1193.send(id, request).await
    }

    /// Checks if the MetaMask wallet is targeted to [`EthConfig::chain_id`],
    /// TODO and the ETH account is still the same, i.e. [`EthCoin::my_address`].
    ///
    /// Please note [`MetamaskCtx::check_active_eth_account`] is relatively chip operation.
    async fn request_preparation(&self) -> Result<MetamaskSession<'_>, web3::Error> {
        let metamask_ctx = self
            .inner
            .metamask_weak
            .upgrade()
            .ok_or_else(|| web3_transport_err("MetaMask context is not initialized".to_string()))?;

        // Lock the MetaMask session and keep it until the RPC is not finished.
        let metamask_session = MetamaskSession::lock(&self.inner.eip1193).await;

        let expected_chain_id = self.inner.eth_config.chain_id;
        let current_chain_id = metamask_ctx.get_current_chain_id().await?;

        if current_chain_id != expected_chain_id {
            metamask_session.wallet_switch_ethereum_chain(expected_chain_id).await?;
        }

        Ok(metamask_session)
    }
}

fn web3_transport_err(err: String) -> web3::Error { web3::Error::Transport(web3::error::TransportError::Message(err)) }
