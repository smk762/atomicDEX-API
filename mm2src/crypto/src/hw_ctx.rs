use crate::crypto_ctx::{MM2_INTERNAL_DERIVATION_PATH, MM2_INTERNAL_ECDSA_CURVE};
use crate::hw_client::{HwClient, HwError, HwResult};
use crate::trezor::TrezorClient;
use crate::HwWalletType;
use bip32::ExtendedPublicKey;
use common::mm_error::prelude::*;
use hw_common::primitives::DerivationPath;
use keys::Public as PublicKey;
use primitives::hash::H264;
use std::str::FromStr;
use trezor::response_channel::TrezorResponseReceiver;
use trezor::TrezorCoin;

pub(crate) const MM2_TREZOR_INTERNAL_COIN: TrezorCoin = TrezorCoin::Komodo;

pub struct HardwareWalletCtx {
    /// The pubkey derived from `MM2_INTERNAL_DERIVATION_PATH`.
    pub(crate) mm2_internal_pubkey: H264,
    pub(crate) hw_wallet_type: HwWalletType,
}

impl HardwareWalletCtx {
    pub fn hw_wallet_type(&self) -> HwWalletType { self.hw_wallet_type }

    /// Connects to a Trezor device and checks if MM was initialized from this particular device.
    pub async fn trezor(&self) -> TrezorResponseReceiver<HwResult<TrezorClient>> {
        let trezor = match HwClient::trezor().await {
            Ok(trezor) => trezor,
            Err(e) => return TrezorResponseReceiver::ready(Err(e)),
        };
        let expected_pubkey = self.mm2_internal_pubkey;

        HardwareWalletCtx::trezor_mm_internal_pubkey(&trezor).and_then(move |actual_pubkey| {
            if actual_pubkey != expected_pubkey {
                return MmError::err(HwError::FoundUnexpectedDevice {
                    actual_pubkey,
                    expected_pubkey,
                });
            }
            Ok(trezor.clone())
        })
    }

    pub fn secp256k1_pubkey(&self) -> PublicKey { PublicKey::Compressed(self.mm2_internal_pubkey) }

    pub(crate) fn trezor_mm_internal_pubkey(trezor: &TrezorClient) -> TrezorResponseReceiver<HwResult<H264>> {
        let path = DerivationPath::from_str(MM2_INTERNAL_DERIVATION_PATH)
            .expect("'MM2_INTERNAL_DERIVATION_PATH' is expected to be valid derivation path");
        trezor
            .get_public_key(path, MM2_TREZOR_INTERNAL_COIN, MM2_INTERNAL_ECDSA_CURVE)
            .and_then(|mm2_internal_xpub| {
                let extended_pubkey = ExtendedPublicKey::<secp256k1::PublicKey>::from_str(&mm2_internal_xpub)?;
                Ok(H264::from(extended_pubkey.public_key().serialize()))
            })
    }
}
