#[macro_use] extern crate serde_derive;

pub mod client;
pub mod constants;
pub mod error;
mod proto;
pub mod response;
pub mod transport;
pub mod user_interaction;
pub mod utxo;

pub use client::TrezorClient;
pub use error::{OperationFailure, TrezorError, TrezorResult};
pub use hw_common::primitives::{DerivationPath, EcdsaCurve};
pub use response::{ButtonRequest, PinMatrixRequest, TrezorResponse};
pub use user_interaction::{TrezorPinMatrix3x3Response, TrezorUserInteraction};

pub(crate) fn serialize_derivation_path(path: &DerivationPath) -> Vec<u32> {
    path.iter().map(|index| index.0).collect()
}

pub(crate) fn ecdsa_curve_to_string(curve: EcdsaCurve) -> String {
    match curve {
        EcdsaCurve::Secp256k1 => "secp256k1".to_owned(),
    }
}

/// TODO remove it at the next iteration.
#[cfg(target_arch = "wasm32")]
pub mod for_tests {
    use crate::client::TrezorClient;
    use crate::constants::TrezorCoin;
    use crate::transport::webusb::find_devices;
    use common::for_tests::register_wasm_log;
    use common::log::info;
    use common::set_panic_hook;
    use hw_common::primitives::DerivationPath;
    use std::str::FromStr;
    use wasm_bindgen::prelude::*;

    /// TODO remove this static function when Trezor works.
    #[wasm_bindgen]
    pub async fn test_trezor() {
        set_panic_hook();
        register_wasm_log();

        let mut devices = find_devices().await.expect("!find_devices");
        info!(
            "Found {} available, {} not supported devices",
            devices.available.len(),
            devices.not_supported.len()
        );
        let device = devices.available.remove(0);
        let transport = device.connect().await.expect("!connect");
        let client = TrezorClient::init(transport).await.expect("!TrezorClient::init");

        let der_path = DerivationPath::from_str("m/44'/141'/0'/0/0").expect("!DerivationPath::from_str");
        let addr = client
            .get_utxo_address(&der_path, TrezorCoin::Komodo)
            .await
            .expect("!get_komodo_address")
            .ack_all()
            .await
            .expect("!get_komodo_address::ack_all");
        info!("Got KMD '{}' address", addr);

        info!("Success");
    }
}
