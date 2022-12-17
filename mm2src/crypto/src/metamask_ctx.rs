// use crate::metamask_login::{AtomicDEXDomain, AtomicDEXLoginRequest, ADEX_LOGIN_TYPE, ADEX_TYPES};
use mm2_err_handle::prelude::*;
use mm2_metamask::{Eip1193Provider, EthAccount, MetamaskSession};
use std::ops::Deref;
use std::sync::{Arc, Weak};
use web3::Web3;

pub use mm2_metamask::{MetamaskError, MetamaskResult};

#[derive(Clone)]
pub struct MetamaskArc(Arc<MetamaskCtx>);

impl MetamaskArc {
    pub fn new(metamask_ctx: MetamaskCtx) -> MetamaskArc { MetamaskArc(Arc::new(metamask_ctx)) }

    pub fn downgrade(&self) -> MetamaskWeak { MetamaskWeak(Arc::downgrade(&self.0)) }
}

impl Deref for MetamaskArc {
    type Target = MetamaskCtx;

    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Clone)]
pub struct MetamaskWeak(Weak<MetamaskCtx>);

impl MetamaskWeak {
    pub fn upgrade(&self) -> Option<MetamaskArc> { self.0.upgrade().map(MetamaskArc) }
}

pub struct MetamaskCtx {
    eth_account: EthAccount,
    /// We'll possibly use it later.
    #[allow(dead_code)]
    web3: Web3<Eip1193Provider>,
    // eth_account_pubkey: String,
}

impl MetamaskCtx {
    pub async fn init() -> MetamaskResult<MetamaskCtx> {
        let eip_transport = Eip1193Provider::detect().or_mm_err(|| MetamaskError::EthProviderNotFound)?;

        let eth_account = {
            let metamask_session = MetamaskSession::lock(&eip_transport).await;
            metamask_session.eth_request_account().await?
        };

        // Uncomment this to finish MetaMask login.
        // TODO figure out how to serialize the source message into bytes and feed it to `ethkey::recover`.
        // HINT: https://github.com/MetaMask/eth-sig-util/blob/d1f01ba799de734d84cdf599d19a215f8fecb5b2/src/sign-typed-data.ts#L449
        // https://github.com/MetaMask/eth-sig-util/blob/d1f01ba799de734d84cdf599d19a215f8fecb5b2/src/sign-typed-data.ts#L551
        //
        // let request = AtomicDEXLoginRequest::new(domain.name.clone());
        // let signature = metamask_provider.sign_typed_data_v4(
        //     eth_account.address.clone(),
        //     &ADEX_TYPES,
        //     domain,
        //     request,
        //     ADEX_LOGIN_TYPE,
        // );

        let web3 = Web3::new(eip_transport);
        Ok(MetamaskCtx { eth_account, web3 })
    }

    pub fn eth_account(&self) -> &EthAccount { &self.eth_account }

    /// Checks if the `MetamaskCtx::eth_account` is still active.
    /// This is required to check before sending transactions.
    /// TODO finish this by subscribing to `accountsChanged` event.
    pub async fn check_active_eth_account(&self) -> MetamaskResult<&EthAccount> { Ok(&self.eth_account) }

    /// Returns an active chain ID.
    /// TODO finish this by subscribing to `chainChanged` event.
    pub async fn get_current_chain_id(&self) -> Result<u64, web3::Error> { Ok(0x1) }
}
