use crate::hw_client::{HwClient, HwError};
use crate::hw_ctx::HardwareWalletCtx;
use crate::key_pair_ctx::KeyPairCtx;
use crate::HwWalletType;
use bip32::Error as Bip32Error;
use bitcrypto::dhash160;
use common::mm_ctx::{MmArc, MmWeak};
use common::mm_error::prelude::*;
use common::privkey::{key_pair_from_seed, PrivKeyError};
use derive_more::Display;
use hw_common::primitives::EcdsaCurve;
use keys::Public as PublicKey;
use primitives::hash::H264;
use std::ops::Deref;
use std::sync::Arc;
use trezor::response_channel::TrezorResponseReceiver;
use trezor::TrezorError;

pub type CryptoInitResult<T> = Result<T, MmError<CryptoInitError>>;

/// The derivation path generally consists of:
/// `m/purpose'/coin_type'/account'/change/address_index`.
/// For MarketMaker internal purposes, we decided to use a pubkey derived from the following path, where:
/// * `coin_type = 141` - KMD coin;
/// * `account = (2 ^ 31 - 1) = 2147483647` - latest available account index.
///   This number is chosen so that it does not cross with real accounts;
/// * `change = 0`, `address_index = 0` - nothing special.
pub(crate) const MM2_INTERNAL_DERIVATION_PATH: &str = "m/44'/141'/2147483647/0/0";
pub(crate) const MM2_INTERNAL_ECDSA_CURVE: EcdsaCurve = EcdsaCurve::Secp256k1;

#[derive(Debug, Display)]
pub enum CryptoInitError {
    NotInitialized,
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

impl From<PrivKeyError> for CryptoInitError {
    fn from(e: PrivKeyError) -> Self { CryptoInitError::InvalidPassphrase(e) }
}

impl From<Bip32Error> for CryptoInitError {
    fn from(e: Bip32Error) -> Self { CryptoInitError::InvalidXpub(e) }
}

impl From<HwError> for CryptoInitError {
    fn from(hw: HwError) -> Self { CryptoInitError::HardwareWalletError(hw) }
}

impl From<TrezorError> for CryptoInitError {
    fn from(trezor: TrezorError) -> Self { CryptoInitError::HardwareWalletError(HwError::from(trezor)) }
}

pub enum CryptoCtx {
    KeyPair(KeyPairCtx),
    HardwareWallet(HardwareWalletCtx),
}

impl CryptoCtx {
    pub fn from_ctx(ctx: &MmArc) -> CryptoInitResult<Arc<CryptoCtx>> {
        let ctx_field = ctx
            .crypto_ctx
            .lock()
            // `PoisonError` doesn't implement `NotMmError`, so we can't use [`MapToMmResult::map_to_mm`].
            .map_err(|poison| MmError::new(CryptoInitError::Internal(poison.to_string())))?;
        let ctx = match ctx_field.deref() {
            Some(ctx) => ctx,
            None => return MmError::err(CryptoInitError::NotInitialized),
        };
        ctx.clone()
            .downcast()
            .map_err(|_| MmError::new(CryptoInitError::Internal("Error casting the context field".to_owned())))
    }

    pub fn secp256k1_pubkey(&self) -> PublicKey {
        match self {
            CryptoCtx::KeyPair(key_pair_ctx) => key_pair_ctx.secp256k1_pubkey(),
            CryptoCtx::HardwareWallet(hw_ctx) => hw_ctx.secp256k1_pubkey(),
        }
    }

    pub fn secp256k1_pubkey_hex(&self) -> String { hex::encode(&*self.secp256k1_pubkey()) }

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
        let crypto_ctx = CryptoCtx::KeyPair(KeyPairCtx { secp256k1_key_pair });
        *ctx_field = Some(Arc::new(crypto_ctx));

        // TODO remove initializing legacy fields when lp_swap and lp_ordermatch support CryptoCtx.
        ctx.secp256k1_key_pair
            .pin(secp256k1_key_pair_for_legacy)
            .map_to_mm(CryptoInitError::Internal)?;
        ctx.rmd160.pin(rmd160).map_to_mm(CryptoInitError::Internal)?;

        Ok(())
    }

    pub async fn init_with_trezor(ctx: MmArc) -> TrezorResponseReceiver<CryptoInitResult<()>> {
        let ctx_weak = ctx.weak();
        let trezor = match HwClient::trezor().await {
            Ok(trezor) => trezor,
            Err(e) => {
                let (hw_error, trace) = e.split();
                let init_error = CryptoInitError::from(hw_error);
                return TrezorResponseReceiver::ready(MmError::err_with_trace(init_error, trace));
            },
        };

        HardwareWalletCtx::trezor_mm_internal_pubkey(&trezor).and_then(move |mm_internal_pubkey| {
            CryptoCtx::init_with_hw_wallet_internal_xpub(ctx_weak.clone(), HwWalletType::Trezor, mm_internal_pubkey)
        })
    }

    fn init_with_hw_wallet_internal_xpub(
        ctx_weak: MmWeak,
        hw_wallet_type: HwWalletType,
        mm2_internal_pubkey: H264,
    ) -> CryptoInitResult<()> {
        // const DEFAULT_SECP

        let ctx = match MmArc::from_weak(&ctx_weak) {
            Some(ctx) => ctx,
            None => return MmError::err(CryptoInitError::Internal("MmArc is dropped".to_owned())),
        };

        let mut ctx_field = ctx
            .crypto_ctx
            .lock()
            // `PoisonError` doesn't implement `NotMmError`, so we can't use [`MapToMmResult::map_to_mm`].
            .map_err(|poison| MmError::new(CryptoInitError::Internal(poison.to_string())))?;
        if ctx_field.is_some() {
            return MmError::err(CryptoInitError::InitializedAlready);
        }

        // TODO remove initializing legacy fields when lp_swap and lp_ordermatch support CryptoCtx.
        let rmd160 = dhash160(mm2_internal_pubkey.as_slice());
        ctx.rmd160.pin(rmd160).map_to_mm(CryptoInitError::Internal)?;

        let crypto_ctx = CryptoCtx::HardwareWallet(HardwareWalletCtx {
            mm2_internal_pubkey,
            hw_wallet_type,
        });
        *ctx_field = Some(Arc::new(crypto_ctx));
        Ok(())
    }
}
