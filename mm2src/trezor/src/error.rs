use crate::proto::messages::MessageType;
use crate::proto::messages_common::Failure;
use crate::response::InteractionType;
use common::mm_error::prelude::*;
use derive_more::Display;
use protobuf::error::ProtobufError;

pub type TrezorResult<T> = Result<T, MmError<TrezorError>>;

#[derive(Debug, Display)]
pub enum TrezorError {
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
}

impl From<ProtobufError> for TrezorError {
    fn from(e: ProtobufError) -> Self { TrezorError::ProtocolError(e.to_string()) }
}

#[cfg(target_arch = "wasm32")]
impl From<hw_common::transport::WebUsbError> for TrezorError {
    fn from(e: hw_common::transport::WebUsbError) -> Self { TrezorError::UnderlyingError(e.to_string()) }
}
