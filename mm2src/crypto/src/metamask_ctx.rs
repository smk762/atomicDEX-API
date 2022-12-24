use crate::metamask_login::{adex_eip712_request, AtomicDEXDomain, AtomicDEXLoginRequest};
use ethkey::{Address, Signature};
use mm2_err_handle::prelude::*;
use mm2_eth::{address::address_from_pubkey_uncompressed, recovery::recover_pubkey};
use mm2_metamask::{Eip1193Provider, MetamaskSession};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use web3::types::H520;
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
    eth_account: Address,
    eth_account_str: String,
    /// Please note that this is a normal version of public key (uncompressed).
    eth_account_pubkey: H520,
    /// We'll possibly use it later.
    #[allow(dead_code)]
    web3: Web3<Eip1193Provider>,
}

impl MetamaskCtx {
    /// TODO take `domain_name`, `url` and check the version.
    pub async fn init() -> MetamaskResult<MetamaskCtx> {
        let eip_transport = Eip1193Provider::detect().or_mm_err(|| MetamaskError::EthProviderNotFound)?;

        let (eth_account, eth_account_str, eth_account_pubkey) = {
            let metamask_session = MetamaskSession::lock(&eip_transport).await;
            let eth_account_str = metamask_session.eth_request_account().await?;
            let eth_account = Address::from_str(&eth_account_str)
                .map_to_mm(|e| MetamaskError::ErrorDeserializingMethodResult(e.to_string()))?;

            let domain = AtomicDEXDomain {
                name: "AtomicDEX".to_string(),
                url: "https://atomicdex.io".to_string(),
                version: "1.0".to_string(),
            };
            let request = AtomicDEXLoginRequest::with_domain_name(domain.name.clone());
            let (hash, sig) = metamask_session
                .sign_typed_data_v4(eth_account_str.clone(), adex_eip712_request(domain, request))
                .await?;

            let sig = sig.strip_prefix("0x").unwrap_or(&sig);
            let signature = Signature::from_str(&sig)
                .map_to_mm(|_| MetamaskError::Internal(format!("'{sig}' signature is invalid")))?;
            let pubkey = recover_pubkey(hash, signature).mm_err(|_| {
                let error = format!("Couldn't recover a public key from the signature: '{sig}'");
                MetamaskError::Internal(error)
            })?;

            let recovered_address = address_from_pubkey_uncompressed(pubkey);
            if eth_account != recovered_address {
                let error =
                    format!("Recovered address '{recovered_address:?}' should be the same as '{eth_account:?}'");
                return MmError::err(MetamaskError::Internal(error));
            }

            (eth_account, eth_account_str, pubkey)
        };

        let web3 = Web3::new(eip_transport);
        Ok(MetamaskCtx {
            eth_account,
            eth_account_str,
            eth_account_pubkey,
            web3,
        })
    }

    pub fn eth_account(&self) -> Address { self.eth_account }

    pub fn eth_account_str(&self) -> &str { &self.eth_account_str }

    pub fn eth_account_pubkey_uncompressed(&self) -> H520 { self.eth_account_pubkey }

    /// Checks if the `MetamaskCtx::eth_account` is still active.
    /// This is required to check before sending transactions.
    pub fn check_active_eth_account(&self) -> MetamaskResult<&Address> {
        let current_account = self.get_current_eth_account()?;
        if current_account == self.eth_account {
            Ok(&self.eth_account)
        } else {
            MmError::err(MetamaskError::UnexpectedAccountSelected)
        }
    }

    /// Returns an active ETH account.
    /// TODO finish this by subscribing to `accountsChanged` event.
    pub fn get_current_eth_account(&self) -> Result<Address, web3::Error> { Ok(self.eth_account) }

    /// Returns an active chain ID.
    /// TODO finish this by subscribing to `chainChanged` event.
    pub fn get_current_chain_id(&self) -> Result<u64, web3::Error> { Ok(0x1) }
}
