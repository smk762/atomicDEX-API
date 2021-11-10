use common::mm_error::prelude::*;
use derive_more::Display;
use trezor::{ButtonRequest, PinMatrixRequest, TrezorClient, TrezorError, TrezorResponse};

pub use hw_common::primitives::{DerivationPath, EcdsaCurve};
use trezor::constants::TrezorCoin;
pub use trezor::TrezorUserInteraction;

pub type HwResult<T> = Result<T, MmError<HwError>>;

#[derive(Debug, Display, Serialize)]
pub enum HwError {
    NoTrezorDeviceAvailable,
    /// TODO put a device info
    DeviceDisconnected,
    #[display(fmt = "'{}' transport not supported", transport)]
    TransportNotSupported {
        transport: String,
    },
    InvalidPin,
    Failure(String),
    UnderlyingError(String),
    ProtocolError(String),
    UnexpectedUserInteractionRequest(TrezorUserInteraction),
    Internal(String),
}

#[derive(Debug)]
pub enum HwResponse<T> {
    Ok(T),
    Delayed(HwDelayedResponse<T>),
}

#[derive(Debug)]
pub enum HwDelayedResponse<T> {
    TrezorPinMatrixRequest(PinMatrixRequest<T>),
    TrezorButtonRequest(ButtonRequest<T>),
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

impl<T> From<TrezorResponse<T>> for HwResponse<T> {
    fn from(res: TrezorResponse<T>) -> Self {
        match res {
            TrezorResponse::Ok(t) => HwResponse::Ok(t),
            TrezorResponse::ButtonRequest(button) => {
                HwResponse::Delayed(HwDelayedResponse::TrezorButtonRequest(button))
            },
            TrezorResponse::PinMatrixRequest(pin) => {
                HwResponse::Delayed(HwDelayedResponse::TrezorPinMatrixRequest(pin))
            },
        }
    }
}

impl<T: 'static> HwResponse<T> {
    /// Agrees to wait for all `HW button press` requests and returns final `Result`.
    ///
    /// # Error
    ///
    /// Will error if it receives requests, which require input like: `PinMatrixRequest`.
    pub async fn ack_all(self) -> HwResult<T> {
        match self {
            HwResponse::Ok(t) => Ok(t),
            HwResponse::Delayed(HwDelayedResponse::TrezorButtonRequest(button)) => Ok(button.ack_all().await?),
            HwResponse::Delayed(HwDelayedResponse::TrezorPinMatrixRequest(_pin)) => MmError::err(
                HwError::UnexpectedUserInteractionRequest(TrezorUserInteraction::PinMatrix3x3),
            ),
        }
    }
}

/// TODO remove it on the next iteration.
/// I'm planning to remove the `HwClient` abstraction since different devices may have different API and coins.
#[derive(Debug)]
pub enum HwCoin {
    Bitcoin,
    Komodo,
}

impl From<HwCoin> for TrezorCoin {
    fn from(coin: HwCoin) -> Self {
        match coin {
            HwCoin::Bitcoin => TrezorCoin::Bitcoin,
            HwCoin::Komodo => TrezorCoin::Komodo,
        }
    }
}

#[derive(Clone)]
pub enum HwClient {
    Trezor(TrezorClient),
}

#[derive(Deserialize)]
pub enum HwWalletType {
    Trezor,
}

impl HwClient {
    #[cfg(target_arch = "wasm32")]
    pub async fn trezor() -> HwResult<HwClient> {
        let mut devices = trezor::transport::webusb::find_devices().await?;
        if devices.available.is_empty() {
            return MmError::err(HwError::NoTrezorDeviceAvailable);
        }
        let device = devices.available.remove(0);
        let transport = device.connect().await?;
        let trezor = TrezorClient::init(transport).await?;
        Ok(HwClient::Trezor(trezor))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn trezor() -> HwResult<HwClient> {
        let mut devices = trezor::transport::usb::find_devices()?;
        if devices.is_empty() {
            return MmError::err(HwError::NoTrezorDeviceAvailable);
        }
        let device = devices.remove(0);
        let transport = device.connect()?;
        let trezor = TrezorClient::init(transport).await?;
        Ok(HwClient::Trezor(trezor))
    }

    pub async fn get_utxo_address(&self, path: &DerivationPath, coin: HwCoin) -> HwResult<HwResponse<String>> {
        match self {
            HwClient::Trezor(trezor) => {
                let response = trezor.get_utxo_address(path, TrezorCoin::from(coin)).await?;
                Ok(HwResponse::from(response))
            },
        }
    }

    pub async fn get_public_key(
        &self,
        path: &DerivationPath,
        coin: HwCoin,
        ecdsa_curve: EcdsaCurve,
    ) -> HwResult<HwResponse<String>> {
        match self {
            HwClient::Trezor(trezor) => {
                let response = trezor.get_public_key(path, TrezorCoin::from(coin), ecdsa_curve).await?;
                Ok(HwResponse::from(response))
            },
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "hw_name")]
#[serde(rename_all = "lowercase")]
pub enum HwUserInteraction {
    Trezor(TrezorUserInteraction),
}
