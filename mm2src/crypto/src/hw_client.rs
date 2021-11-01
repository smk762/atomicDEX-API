use common::mm_error::prelude::*;
use derive_more::Display;
use trezor::transport::usb as trezor_usb;
use trezor::{ButtonRequest, PinMatrixRequest, TrezorClient, TrezorError, TrezorResponse, TrezorUserInteraction};

pub type HwResult<T> = Result<T, MmError<HwError>>;

#[derive(Debug, Display)]
pub enum HwError {
    NoTrezorDeviceAvailable,
    /// TODO put a device info
    DeviceDisconnected,
    TransportNotSupported {
        transport: String,
    },
    InvalidPin,
    Failure(String),
    UnderlyingError(String),
    ProtocolError(String),
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
            TrezorError::UnexpectedInteractionRequest(_) | TrezorError::Internal(_) => HwError::Internal(error),
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

pub enum HwClient {
    Trezor(TrezorClient),
}

impl HwClient {
    #[cfg(target_arch = "wasm32")]
    pub async fn trezor() -> HwResult<HwClient> {
        MmError::err(HwError::NotSupported(
            "Trezor is not supported in a browser yet".to_owned(),
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn trezor() -> HwResult<HwClient> {
        let mut devices = trezor_usb::find_devices()?;
        if devices.is_empty() {
            return MmError::err(HwError::NoTrezorDeviceAvailable);
        }
        let device = devices.remove(0);
        let transport = device.connect()?;
        let trezor = TrezorClient::init(transport).await?;
        Ok(HwClient::Trezor(trezor))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "hw_name")]
#[serde(rename_all = "lowercase")]
pub enum HwUserInteraction {
    Trezor(TrezorUserInteraction),
}
