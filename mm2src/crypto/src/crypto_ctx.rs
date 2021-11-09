use crate::hw_client::{EcdsaCurve, HwClient, HwCoin, HwDelayedResponse, HwError, HwResponse};
use bip32::{Error as Bip32Error, ExtendedPublicKey};
use bitcrypto::dhash160;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::privkey::{key_pair_from_seed, PrivKeyError};
use derive_more::Display;
use hw_common::primitives::DerivationPath;
use keys::KeyPair;
use primitives::hash::{H160, H264};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

pub type CryptoInitResult<T> = Result<T, MmError<CryptoInitError>>;
pub type CryptoResult<T> = Result<T, MmError<CryptoError>>;

/// The derivation path generally consists of:
/// `m/purpose'/coin_type'/account'/change/address_index`.
/// For MarketMaker internal purposes, we decided to use a pubkey derived from the following path, where:
/// * `coin_type = 141` - KMD coin;
/// * `account = (2 ^ 31 - 1) = 2147483647` - latest available account index.
///   This number is chosen so that it does not cross with real accounts;
/// * `change = 0`, `address_index = 0` - nothing special.
const MM2_INTERNAL_DERIVATION_PATH: &str = "m/44'/141'/2147483647/0/0";
const MM2_INTERNAL_COIN: HwCoin = HwCoin::Komodo;
const MM2_INTERNAL_ECDSA_CURVE: EcdsaCurve = EcdsaCurve::Secp256k1;

#[derive(Display)]
pub enum CryptoInitError {
    InitializedAlready,
    #[display(fmt = "jeezy says we cant use the nullstring as passphrase and I agree")]
    NullStringPassphrase,
    #[display(fmt = "Invalid passphrase: '{}'", _0)]
    InvalidPassphrase(PrivKeyError),
    #[display(fmt = "Invalid xpub received from a device: '{}'", _0)]
    InvalidXpub(Bip32Error),
    HardwareWalletError(HwError),
    Internal(String),
}

#[derive(Debug, Display)]
pub enum CryptoError {
    NotInitialized,
    Internal(String),
}

impl From<PrivKeyError> for CryptoInitError {
    fn from(e: PrivKeyError) -> Self { CryptoInitError::InvalidPassphrase(e) }
}

impl From<HwError> for CryptoInitError {
    fn from(e: HwError) -> Self {
        match e {
            HwError::Internal(internal) => CryptoInitError::Internal(internal),
            hw => CryptoInitError::HardwareWalletError(hw),
        }
    }
}

impl From<bip32::Error> for CryptoInitError {
    fn from(e: bip32::Error) -> Self { CryptoInitError::InvalidXpub(e) }
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
        client: HwClient,
    },
}

impl CryptoCtx {
    pub fn from_ctx(ctx: &MmArc) -> CryptoResult<Arc<CryptoCtx>> {
        let ctx_field = ctx
            .crypto_ctx
            .lock()
            // `PoisonError` doesn't implement `NotMmError`, so we can't use [`MapToMmResult::map_to_mm`].
            .map_err(|poison| MmError::new(CryptoError::Internal(poison.to_string())))?;
        let ctx = match ctx_field.deref() {
            Some(ctx) => ctx,
            None => return MmError::err(CryptoError::NotInitialized),
        };
        ctx.clone()
            .downcast()
            .map_err(|_| MmError::new(CryptoError::Internal("Error casting the context field".to_owned())))
    }

    pub fn init_with_passphrase(ctx: MmArc, passphrase: &str) -> CryptoInitResult<()> {
        let mut ctx_field = ctx
            .crypto_ctx
            .lock()
            // `PoisonError` doesn't implement `NotMmError`, so we can't use [`MapToMmResult::map_to_mm`].
            .map_err(|poison| MmError::new(CryptoInitError::Internal(poison.to_string())))?;
        if ctx_field.is_some() {
            return MmError::err(CryptoInitError::InitializedAlready);
        }

        if passphrase.is_empty() {
            return MmError::err(CryptoInitError::NullStringPassphrase);
        }

        let secp256k1_key_pair = key_pair_from_seed(&passphrase)?;
        // We can't clone `secp256k1_key_pair`, but it's used later to initialize legacy `MmCtx` fields.
        let secp256k1_key_pair_for_legacy = key_pair_from_seed(&passphrase)?;

        let rmd160 = secp256k1_key_pair.public().address_hash();
        let crypto_ctx = CryptoCtx::KeyPair {
            secp256k1_key_pair,
            rmd160,
        };
        *ctx_field = Some(Arc::new(crypto_ctx));

        // TODO remove initializing legacy fields when lp_swap and lp_ordermatch support CryptoCtx.
        let key_pair = ctx
            .secp256k1_key_pair
            .pin(secp256k1_key_pair_for_legacy)
            .map_to_mm(CryptoInitError::Internal)?;
        ctx.rmd160
            .pin(key_pair.public().address_hash())
            .map_to_mm(CryptoInitError::Internal)?;

        Ok(())
    }

    // TODO replace this function somehow with the following:
    // pub async fn init_with_trezor(ctx: MmArc) -> CryptoInitResult<CryptoResponse<()>>
    // It means, we should replace initialization logic from `lp_native_dex.rs` into this function.
    pub fn init_with_hw_wallet(ctx: MmArc, client: HwClient, mm2_internal_xpub: &str) -> CryptoInitResult<()> {
        let extended_pubkey = ExtendedPublicKey::<secp256k1::PublicKey>::from_str(mm2_internal_xpub)?;
        let mm2_internal_pubkey = H264::from(extended_pubkey.public_key().serialize());

        let mut ctx_field = ctx
            .crypto_ctx
            .lock()
            // `PoisonError` doesn't implement `NotMmError`, so we can't use [`MapToMmResult::map_to_mm`].
            .map_err(|poison| MmError::new(CryptoInitError::Internal(poison.to_string())))?;
        if ctx_field.is_some() {
            return MmError::err(CryptoInitError::InitializedAlready);
        }

        let crypto_ctx = CryptoCtx::HardwareWallet {
            mm2_internal_pubkey,
            rmd160: dhash160(mm2_internal_pubkey.as_slice()),
            client,
        };
        *ctx_field = Some(Arc::new(crypto_ctx));
        Ok(())
    }

    // TODO remove this function when `CryptoCtx::init_with_hw_wallet` is refactored.
    pub async fn request_mm2_internal_pubkey(client: &HwClient) -> CryptoInitResult<CryptoResponse<String>> {
        let path = DerivationPath::from_str(MM2_INTERNAL_DERIVATION_PATH)
            .expect("'MM2_INTERNAL_DERIVATION_PATH' is expected to be valid derivation path");
        let response = client
            .get_public_key(&path, MM2_INTERNAL_COIN, MM2_INTERNAL_ECDSA_CURVE)
            .await?;
        Ok(CryptoResponse::from(response))
    }
}
