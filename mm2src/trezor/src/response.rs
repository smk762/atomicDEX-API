use crate::client::{ResultHandler, TrezorClient};
use crate::proto::messages_common as proto_common;
use crate::proto::TrezorMessage;
use crate::{TrezorError, TrezorResult};
use common::mm_error::prelude::*;
use std::fmt;

pub use crate::proto::messages_common::ButtonRequest_ButtonRequestType as ButtonRequestType;
pub use crate::proto::messages_common::PinMatrixRequest_PinMatrixRequestType as PinMatrixRequestType;

/// The different types of user interactions the Trezor device can request.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum InteractionType {
    Button,
    PinMatrix,
    Passphrase,
    PassphraseState,
}

/// A response from a Trezor device.
///
/// On every message exchange, instead of the expected/desired response,
/// the Trezor can ask for some user interaction, or can send a failure.
#[derive(Debug)]
pub enum TrezorResponse<'a, T, R: TrezorMessage> {
    Ok(T),
    Failure(proto_common::Failure),
    ButtonRequest(ButtonRequest<'a, T, R>),
    PinMatrixRequest(PinMatrixRequest<'a, T, R>),
}

impl<'a, T, R: TrezorMessage> TrezorResponse<'a, T, R> {
    /// Get the actual `Ok` response value or an error if not `Ok`.
    pub fn ok(self) -> TrezorResult<T> {
        match self {
            TrezorResponse::Ok(m) => Ok(m),
            TrezorResponse::Failure(err) => MmError::err(TrezorError::FailureResponse(err)),
            TrezorResponse::ButtonRequest(_) => {
                MmError::err(TrezorError::UnexpectedInteractionRequest(InteractionType::Button))
            },
            TrezorResponse::PinMatrixRequest(_) => {
                MmError::err(TrezorError::UnexpectedInteractionRequest(InteractionType::PinMatrix))
            },
        }
    }

    /// Agrees to wait for all `HW button press` requests and returns final `Result`.
    ///
    /// # Error
    ///
    /// Will error if it receives requests, which require input like: `PinMatrixRequest`.
    pub async fn ack_all(self) -> TrezorResult<T> {
        let mut resp = self;
        loop {
            resp = match resp {
                Self::Ok(val) => {
                    return Ok(val);
                },
                Self::Failure(err) => {
                    return MmError::err(TrezorError::FailureResponse(err));
                },
                Self::ButtonRequest(req) => req.ack().await?,
                Self::PinMatrixRequest(_) => {
                    return MmError::err(TrezorError::UnexpectedInteractionRequest(InteractionType::PinMatrix));
                },
            };
        }
    }

    pub(crate) fn new_button_request(
        message: proto_common::ButtonRequest,
        client: &'a mut TrezorClient,
        result_handler: ResultHandler<'a, T, R>,
    ) -> Self {
        TrezorResponse::ButtonRequest(ButtonRequest {
            message,
            client,
            result_handler,
        })
    }

    pub(crate) fn new_pin_matrix_request(
        message: proto_common::PinMatrixRequest,
        client: &'a mut TrezorClient,
        result_handler: ResultHandler<'a, T, R>,
    ) -> Self {
        TrezorResponse::PinMatrixRequest(PinMatrixRequest {
            message,
            client,
            result_handler,
        })
    }
}

/// A button request message sent by the device.
pub struct ButtonRequest<'a, T, R: TrezorMessage> {
    message: proto_common::ButtonRequest,
    client: &'a mut TrezorClient,
    result_handler: ResultHandler<'a, T, R>,
}

impl<'a, T, R: TrezorMessage> fmt::Debug for ButtonRequest<'a, T, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self.message) }
}

/// A PIN matrix request message sent by the device.
pub struct PinMatrixRequest<'a, T, R: TrezorMessage> {
    message: proto_common::PinMatrixRequest,
    client: &'a mut TrezorClient,
    result_handler: ResultHandler<'a, T, R>,
}

impl<'a, T, R: TrezorMessage> fmt::Debug for PinMatrixRequest<'a, T, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self.message) }
}

impl<'a, T, R: TrezorMessage> ButtonRequest<'a, T, R> {
    /// The type of button request.
    pub fn request_type(&self) -> ButtonRequestType { self.message.get_code() }

    /// Ack the request and get the next message from the device.
    pub async fn ack(self) -> TrezorResult<TrezorResponse<'a, T, R>> {
        let req = proto_common::ButtonAck::new();
        self.client.call(req, self.result_handler).await
    }
}

impl<'a, T, R: TrezorMessage> PinMatrixRequest<'a, T, R> {
    /// The type of PIN matrix request.
    pub fn request_type(&self) -> PinMatrixRequestType { self.message.get_field_type() }

    /// Ack the request with a PIN and get the next message from the device.
    pub async fn ack_pin(self, pin: String) -> TrezorResult<TrezorResponse<'a, T, R>> {
        let mut req = proto_common::PinMatrixAck::new();
        req.set_pin(pin);
        self.client.call(req, self.result_handler).await
    }
}
