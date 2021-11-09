use crate::client::{ResultHandler, TrezorClient};
use crate::proto::messages_common as proto_common;
use crate::proto::TrezorMessage;
use crate::user_interaction::TrezorUserInteraction;
use crate::{TrezorError, TrezorResult};
use common::mm_error::prelude::*;
use futures::FutureExt;
use std::fmt;
use std::future::Future;

pub use crate::proto::messages_common::ButtonRequest_ButtonRequestType as ButtonRequestType;
pub use crate::proto::messages_common::PinMatrixRequest_PinMatrixRequestType as PinMatrixRequestType;

type ButtonHandlerFuture<T> = dyn Future<Output = TrezorResult<TrezorResponse<T>>> + Unpin + Send;
type PinHandlerFuture<T> = dyn Future<Output = TrezorResult<TrezorResponse<T>>> + Unpin + Send;
type PinHandlerFn<T> = dyn FnOnce(String) -> Box<PinHandlerFuture<T>> + Send;

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
pub enum TrezorResponse<T> {
    Ok(T),
    ButtonRequest(ButtonRequest<T>),
    PinMatrixRequest(PinMatrixRequest<T>),
}

impl<T: 'static> TrezorResponse<T> {
    /// Get the actual `Ok` response value or an error if not `Ok`.
    pub fn ok(self) -> TrezorResult<T> {
        match self {
            TrezorResponse::Ok(m) => Ok(m),
            TrezorResponse::ButtonRequest(_) => MmError::err(TrezorError::UnexpectedInteractionRequest(
                TrezorUserInteraction::ButtonRequest,
            )),
            TrezorResponse::PinMatrixRequest(_) => MmError::err(TrezorError::UnexpectedInteractionRequest(
                TrezorUserInteraction::PinMatrix3x3,
            )),
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
                Self::ButtonRequest(req) => req.ack().await?,
                Self::PinMatrixRequest(_) => {
                    return MmError::err(TrezorError::UnexpectedInteractionRequest(TrezorUserInteraction::PinMatrix3x3));
                },
            };
        }
    }

    pub(crate) fn new_button_request<R: TrezorMessage>(
        message: proto_common::ButtonRequest,
        client: TrezorClient,
        result_handler: ResultHandler<T, R>,
    ) -> Self {
        TrezorResponse::ButtonRequest(ButtonRequest {
            message,
            button_handler: ButtonRequest::button_handler_wrapped(client, result_handler),
        })
    }

    pub(crate) fn new_pin_matrix_request<R: TrezorMessage>(
        message: proto_common::PinMatrixRequest,
        client: TrezorClient,
        result_handler: ResultHandler<T, R>,
    ) -> Self {
        TrezorResponse::PinMatrixRequest(PinMatrixRequest {
            message,
            pin_handler: PinMatrixRequest::pin_handler_wrapped(client, result_handler),
        })
    }
}

/// A button request message sent by the device.
pub struct ButtonRequest<T> {
    message: proto_common::ButtonRequest,
    /// This future is [`ButtonRequest::button_handler`] that already captured the required parameters
    /// like `client` and `result_handler`.
    /// This trick allows us to avoid having a `R: TrezorMessage` type parameter for `ButtonRequest` structure.
    button_handler: Box<ButtonHandlerFuture<T>>,
}

impl<T> fmt::Debug for ButtonRequest<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self.message) }
}

/// A PIN matrix request message sent by the device.
pub struct PinMatrixRequest<T> {
    message: proto_common::PinMatrixRequest,
    /// This function is [`PinMatrixRequest::pin_handler`] that already captured the required parameters
    /// like `client` and `result_handler`.
    /// This trick allows us to avoid having a `R: TrezorMessage` type parameter for `PinMatrixRequest` structure.
    pin_handler: Box<PinHandlerFn<T>>,
}

impl<T> fmt::Debug for PinMatrixRequest<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self.message) }
}

impl<T: 'static> ButtonRequest<T> {
    /// The type of button request.
    pub fn request_type(&self) -> ButtonRequestType { self.message.get_code() }

    /// Ack the request and get the next message from the device.
    pub async fn ack(self) -> TrezorResult<TrezorResponse<T>> { self.button_handler.await }

    /// TODO add an optional `timeout` param.
    pub async fn ack_all(self) -> TrezorResult<T> { self.button_handler.await?.ack_all().await }

    async fn button_handler<R: TrezorMessage>(
        client: TrezorClient,
        result_handler: ResultHandler<T, R>,
    ) -> TrezorResult<TrezorResponse<T>> {
        let req = proto_common::ButtonAck::new();
        client.call(req, result_handler).await
    }

    fn button_handler_wrapped<R: TrezorMessage>(
        client: TrezorClient,
        result_handler: ResultHandler<T, R>,
    ) -> Box<ButtonHandlerFuture<T>> {
        Box::new(ButtonRequest::button_handler(client, result_handler).boxed())
    }
}

impl<T: 'static> PinMatrixRequest<T> {
    /// The type of PIN matrix request.
    pub fn request_type(&self) -> PinMatrixRequestType { self.message.get_field_type() }

    /// Ack the request with a PIN and get the next message from the device.
    pub async fn ack_pin(self, pin: String) -> TrezorResult<TrezorResponse<T>> { (self.pin_handler)(pin).await }

    async fn pin_handler<R: TrezorMessage>(
        client: TrezorClient,
        result_handler: ResultHandler<T, R>,
        pin: String,
    ) -> TrezorResult<TrezorResponse<T>> {
        let mut req = proto_common::PinMatrixAck::new();
        req.set_pin(pin);
        client.call(req, result_handler).await
    }

    fn pin_handler_wrapped<R: TrezorMessage>(
        client: TrezorClient,
        result_handler: ResultHandler<T, R>,
    ) -> Box<PinHandlerFn<T>> {
        let pin_handler = move |pin: String| {
            let fut = PinMatrixRequest::pin_handler(client, result_handler, pin);
            let fut: Box<PinHandlerFuture<T>> = Box::new(fut.boxed());
            fut
        };
        Box::new(pin_handler)
    }
}
