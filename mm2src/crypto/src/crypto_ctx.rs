use crate::hw_client::{HwClient, HwDelayedResponse, HwError, HwResponse};
use common::mm_error::prelude::*;
use common::privkey::{key_pair_from_seed, PrivKeyError};
use derive_more::Display;
use keys::KeyPair;
use primitives::hash::{H160, H264};

pub type CryptoInitResult<T> = Result<T, MmError<CryptoInitError>>;

/// The derivation path generally consists of:
/// `m/purpose'/coin_type'/account'/change/address_index`.
/// For MarketMaker internal purposes, we decided to use a pubkey derived from the following path, where:
/// * `coin_type = 141` - KMD coin;
/// * `account = (2 ^ 31 - 1) = 2147483647` - latest available account index.
///   This number is chosen so that it does not cross with real accounts;
/// * `change = 0`, `address_index = 0` - nothing special.
const MM2_INTERNAL_DERIVATION_PATH: &str = "m/44'/141'/2147483647/0/0";

#[derive(Display)]
pub enum CryptoInitError {
    #[display(fmt = "jeezy says we cant use the nullstring as passphrase and I agree")]
    NullStringPassphrase,
    #[display(fmt = "Invalid passphrase: {}", _0)]
    InvalidPassphrase(PrivKeyError),
    HardwareWalletError(HwError),
    Internal(String),
}

impl From<PrivKeyError> for CryptoInitError {
    fn from(e: PrivKeyError) -> Self { CryptoInitError::InvalidPassphrase(e) }
}

impl From<HwError> for CryptoInitError {
    fn from(e: HwError) -> Self { CryptoInitError::HardwareWalletError(e) }
}

pub enum CryptoResponse<T> {
    Ok(T),
    HwDelayed(HwDelayedResponse<T>),
}

impl<T> From<HwResponse<T>> for CryptoResponse<T> {
    fn from(e: HwResponse<T>) -> Self {
        match e {
            HwResponse::Ok(t) => CryptoResponse::Ok(t),
            HwResponse::Delayed(delayed) => CryptoResponse::HwDelayed(delayed),
        }
    }
}

pub enum CryptoCtx {
    KeyPair {
        /// RIPEMD160(SHA256(x)) where x is secp256k1 pubkey derived from passphrase.
        rmd160: H160,
        /// secp256k1 key pair derived from passphrase.
        /// cf. `key_pair_from_seed`.
        secp256k1_key_pair: KeyPair,
    },
    HardwareWallet {
        /// The pubkey derived from `MM2_INTERNAL_DERIVATION_PATH`.
        mm2_internal_pubkey: H264,
        /// RIPEMD160(SHA256(x)) where x is secp256k1 pubkey derived from `mm2_master_pubkey`.
        rmd160: H160,
        client: Option<HwClient>,
    },
}

impl CryptoCtx {
    pub fn from_passphrase(passphrase: &str) -> CryptoInitResult<CryptoCtx> {
        if passphrase.is_empty() {
            return MmError::err(CryptoInitError::NullStringPassphrase);
        }

        let secp256k1_key_pair = key_pair_from_seed(&passphrase)?;
        let rmd160 = secp256k1_key_pair.public().address_hash();
        Ok(CryptoCtx::KeyPair {
            secp256k1_key_pair,
            rmd160,
        })
    }

    pub async fn with_trezor() -> CryptoInitResult<CryptoResponse<CryptoCtx>> {
        let client = HwClient::trezor().await?;
        // let x = client.
        todo!()
    }
}
