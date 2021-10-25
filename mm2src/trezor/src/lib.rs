pub mod client;
pub mod error;
pub mod response;
pub mod transport;

pub use error::{TrezorError, TrezorResult};

// mod constants;
mod proto;

#[cfg(all(not(target_arch = "wasm32"), test))]
mod tests {
    use super::*;
    use client::TrezorClient;
    use common::block_on;
    use hw_common::primitives::KeyDerivationPath;
    use std::str::FromStr;
    use transport::usb::find_devices;

    #[test]
    fn test_trezor() {
        std::env::set_var("RUST_LOG", "DEBUG");
        env_logger::init();
        log::info!("Run test");

        let mut devices = find_devices().unwrap();
        assert!(!devices.is_empty());
        let device = devices.remove(0);
        log::info!("Device: {:?}", device.device_info());
        let transport = device.connect().expect("!connect");

        let mut client = block_on(TrezorClient::init(transport)).expect("!TrezorClient::init");

        let der_path = KeyDerivationPath::from_str("m/44'/141'/0'/0/0").expect("!KeyDerivationPath::from_str");
        let addr = block_on(
            block_on(client.get_utxo_address(&der_path, "Komodo".to_owned()))
                .expect("!get_komodo_address")
                .ack_all(),
        )
        .expect("!get_komodo_address::ack_all");
        log::info!("Got KMD '{}' address", addr);

        log::info!("Success");
    }
}

/// TODO remove it at the next iteration.
#[cfg(target_arch = "wasm32")]
pub mod for_tests {
    use crate::client::TrezorClient;
    use crate::transport::webusb::find_devices;
    use common::for_tests::register_wasm_log;
    use common::log::info;
    use common::set_panic_hook;
    use hw_common::primitives::KeyDerivationPath;
    use std::str::FromStr;
    use wasm_bindgen::prelude::*;

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
        let mut client = TrezorClient::init(transport).await.expect("!TrezorClient::init");

        let der_path = KeyDerivationPath::from_str("m/44'/141'/0'/0/0").expect("!KeyDerivationPath::from_str");
        let addr = client
            .get_utxo_address(&der_path, "Komodo".to_owned())
            .await
            .expect("!get_komodo_address")
            .ack_all()
            .await
            .expect("!get_komodo_address::ack_all");
        info!("Got KMD '{}' address", addr);

        info!("Success");
    }
}
