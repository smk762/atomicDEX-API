//! This file is inspired by https://github.com/tezedge/tezedge-client/blob/master/trezor_api/src/client.rs

use crate::error::OperationFailure;
use crate::proto::messages::MessageType;
use crate::proto::messages_common as proto_common;
use crate::proto::messages_management as proto_management;
use crate::proto::{ProtoMessage, TrezorMessage};
use crate::response::TrezorResponse;
use crate::transport::Transport;
use crate::{TrezorError, TrezorResult};
use common::mm_error::prelude::*;
use futures::lock::Mutex as AsyncMutex;
use std::ops::Deref;
use std::sync::Arc;

/// Function to be passed to the [`TrezorClient::call`] method
/// to process the Trezor response message into a general-purpose type.
pub(crate) type ResultHandler<T, R> = Box<dyn Fn(R) -> TrezorResult<T> + Send + Sync>;

pub struct TrezorClientImpl {
    transport: AsyncMutex<Box<dyn Transport + Send + Sync + 'static>>,
}

#[derive(Clone)]
pub struct TrezorClient(Arc<TrezorClientImpl>);

impl Deref for TrezorClient {
    type Target = TrezorClientImpl;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl TrezorClient {
    /// Create a `TrezorClient` from the given `transport` and initialize the device
    /// by sending the [Initialize](https://docs.trezor.io/trezor-firmware/common/communication/sessions.html#examples) Protobuf message.
    pub async fn init<T: Transport + Send + Sync + 'static>(transport: T) -> TrezorResult<TrezorClient> {
        let client = TrezorClient(Arc::new(TrezorClientImpl {
            transport: AsyncMutex::new(Box::new(transport)),
        }));
        client.initialize_device().await?;
        Ok(client)
    }

    /// Sends a message and returns a TrezorResponse with either the
    /// expected response message, a failure or an interaction request.
    pub async fn call<T: 'static, S: TrezorMessage, R: TrezorMessage>(
        &self,
        message: S,
        result_handler: ResultHandler<T, R>,
    ) -> TrezorResult<TrezorResponse<T>> {
        let resp = self.call_raw(message).await?;
        match resp.message_type() {
            mt if mt == R::message_type() => {
                let resp_msg = resp.into_message()?;
                Ok(TrezorResponse::Ok(result_handler(resp_msg)?))
            },
            MessageType::Failure => {
                let fail_msg: proto_common::Failure = resp.into_message()?;
                MmError::err(TrezorError::Failure(OperationFailure::from(fail_msg)))
            },
            MessageType::ButtonRequest => {
                let req_msg = resp.into_message()?;
                // trace!("Received ButtonRequest: {:?}", req_msg);
                Ok(TrezorResponse::new_button_request(
                    req_msg,
                    self.clone(),
                    result_handler,
                ))
            },
            MessageType::PinMatrixRequest => {
                let req_msg = resp.into_message()?;
                Ok(TrezorResponse::new_pin_matrix_request(
                    req_msg,
                    self.clone(),
                    result_handler,
                ))
            },
            mtype => MmError::err(TrezorError::UnexpectedMessageType(mtype)),
        }
    }

    /// Sends a message and returns the raw ProtoMessage struct that was
    /// responded by the device.
    async fn call_raw<S: TrezorMessage>(&self, message: S) -> TrezorResult<ProtoMessage> {
        let mut buf = Vec::with_capacity(message.encoded_len());
        message.encode(&mut buf)?;

        let proto_msg = ProtoMessage::new(S::message_type(), buf);
        let mut transport = self.transport.lock().await;
        transport.write_message(proto_msg).await?;
        transport.read_message().await
    }

    /// Initialize the device.
    ///
    /// The Initialize packet will cause the device to stop what it is currently doing
    /// and should work at any time.
    /// Thus, it can also be used to recover from previous errors.
    ///
    /// # Usage
    ///
    /// Must be called before sending requests to Trezor.
    async fn initialize_device(&self) -> TrezorResult<proto_management::Features> {
        // Don't set the session_id since currently there is no need to restore the previous session.
        // https://docs.trezor.io/trezor-firmware/common/communication/sessions.html#session-lifecycle
        let req = proto_management::Initialize { session_id: None };

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ok()
    }

    pub(crate) async fn cancel_last_op(&self) {
        let req = proto_management::Cancel {};
        let result_handler = Box::new(|_m: proto_common::Failure| Ok(()));
        // Ignore result.
        self.call(req, result_handler).await.ok();
    }
}
