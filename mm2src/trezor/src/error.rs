use crate::proto::messages::MessageType;
use crate::proto::messages_common::Failure;
use crate::response::InteractionType;
use common::mm_error::prelude::*;
use derive_more::Display;
use protobuf::error::ProtobufError;

pub type TrezorResult<T> = Result<T, MmError<TrezorError>>;

#[cfg(not(target_arch = "wasm32"))]
use hw_common::transport::UsbError;
#[cfg(target_arch = "wasm32")]
use hw_common::transport::WebUsbError;

#[derive(Debug, Display)]
pub enum TrezorError {
    #[display(fmt = "'{}' transport is not available on this platform", transport)]
    TransportNotSupported {
        transport: String,
    },
    /// Please note it's not the same as `PermissionDenied`.
    /// This error may appear in a browser when the user didn't allow the app to get the list of devices.
    ErrorRequestingAccessPermission(String),
    /// TODO put a device info
    DeviceDisconnected,
    /// The error depends on transport implementation.
    UnderlyingError(String),
    ProtocolError(String),
    #[display(fmt = "Received unexpected message type: {:?}", _0)]
    UnexpectedMessageType(MessageType),
    #[display(fmt = "Failure response: {:?}", _0)]
    FailureResponse(Failure),
    #[display(fmt = "Unexpected interaction request: {:?}", _0)]
    UnexpectedInteractionRequest(InteractionType),
    Internal(String),
}

impl From<ProtobufError> for TrezorError {
    fn from(e: ProtobufError) -> Self { TrezorError::ProtocolError(e.to_string()) }
}

#[cfg(target_arch = "wasm32")]
impl From<WebUsbError> for TrezorError {
    fn from(e: WebUsbError) -> Self {
        match e {
            WebUsbError::NotSupported => TrezorError::TransportNotSupported {
                transport: "WebUSB".to_owned(),
            },
            WebUsbError::ErrorRequestingDevice(e) => TrezorError::ErrorRequestingAccessPermission(e),
            WebUsbError::Internal(e) => TrezorError::Internal(e),
            e => TrezorError::UnderlyingError(e.to_string()),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<UsbError> for TrezorError {
    fn from(e: UsbError) -> Self {
        match e {
            UsbError::DeviceDisconnected => TrezorError::DeviceDisconnected,
            UsbError::Internal(e) => TrezorError::Internal(e),
            e => TrezorError::UnderlyingError(e.to_string()),
        }
    }
}
