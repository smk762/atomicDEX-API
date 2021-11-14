use bip32::Error as Bip32Error;
use common::mm_error::prelude::*;
use derive_more::Display;
use primitives::hash::H264;
use trezor::{TrezorClient, TrezorError, TrezorUserInteraction};

pub type HwResult<T> = Result<T, MmError<HwError>>;

#[derive(Debug, Display)]
pub enum HwError {
    NoTrezorDeviceAvailable,
    #[display(
        fmt = "Expected a Hardware Wallet device with '{}' pubkey, found '{}'",
        expected_pubkey,
        actual_pubkey
    )]
    FoundUnexpectedDevice {
        actual_pubkey: H264,
        expected_pubkey: H264,
    },
    DeviceDisconnected,
    #[display(fmt = "'{}' transport not supported", transport)]
    TransportNotSupported {
        transport: String,
    },
    #[display(fmt = "Invalid xpub received from a device: '{}'", _0)]
    InvalidXpub(Bip32Error),
    Failure(String),
    UnderlyingError(String),
    ProtocolError(String),
    UnexpectedUserInteractionRequest(TrezorUserInteraction),
    Internal(String),
}

impl From<TrezorError> for HwError {
    fn from(e: TrezorError) -> Self {
        let error = e.to_string();
        match e {
            TrezorError::TransportNotSupported { transport } => HwError::TransportNotSupported { transport },
            TrezorError::ErrorRequestingAccessPermission(_) => HwError::NoTrezorDeviceAvailable,
            TrezorError::DeviceDisconnected => HwError::DeviceDisconnected,
            TrezorError::UnderlyingError(_) => HwError::UnderlyingError(error),
            TrezorError::ProtocolError(_) | TrezorError::UnexpectedMessageType(_) => HwError::Internal(error),
            // TODO handle the failure correctly later
            TrezorError::Failure(_) => HwError::Failure(error),
            TrezorError::UnexpectedInteractionRequest(req) => HwError::UnexpectedUserInteractionRequest(req),
            TrezorError::Internal(_) => HwError::Internal(error),
        }
    }
}

impl From<Bip32Error> for HwError {
    fn from(e: Bip32Error) -> Self { HwError::InvalidXpub(e) }
}

#[derive(Clone)]
pub enum HwClient {
    Trezor(TrezorClient),
}

impl From<TrezorClient> for HwClient {
    fn from(trezor: TrezorClient) -> Self { HwClient::Trezor(trezor) }
}

#[derive(Clone, Copy, Deserialize)]
pub enum HwWalletType {
    Trezor,
}

impl HwClient {
    #[cfg(target_arch = "wasm32")]
    pub async fn trezor() -> HwResult<TrezorClient> {
        let mut devices = trezor::transport::webusb::find_devices().await?;
        if devices.available.is_empty() {
            return MmError::err(HwError::NoTrezorDeviceAvailable);
        }
        let device = devices.available.remove(0);
        let transport = device.connect().await?;
        let trezor = TrezorClient::init(transport).await?;
        Ok(trezor)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn trezor() -> HwResult<TrezorClient> {
        let mut devices = trezor::transport::usb::find_devices()?;
        if devices.is_empty() {
            return MmError::err(HwError::NoTrezorDeviceAvailable);
        }
        let device = devices.remove(0);
        let transport = device.connect()?;
        let trezor = TrezorClient::init(transport).await?;
        Ok(trezor)
    }
}
