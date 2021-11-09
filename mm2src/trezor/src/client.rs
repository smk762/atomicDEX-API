//! This file is inspired by https://github.com/tezedge/tezedge-client/blob/master/trezor_api/src/client.rs

use crate::coins::TrezorCoin;
use crate::error::OperationFailure;
use crate::proto::messages::MessageType;
use crate::proto::messages_bitcoin as proto_bitcoin;
use crate::proto::messages_common as proto_common;
use crate::proto::messages_management as proto_management;
use crate::proto::{ProtoMessage, TrezorMessage};
use crate::response::TrezorResponse;
use crate::transport::Transport;
use crate::{TrezorError, TrezorResult};
use common::mm_error::prelude::*;
use futures::lock::Mutex as AsyncMutex;
use hw_common::primitives::{DerivationPath, EcdsaCurve};
use std::ops::Deref;
use std::sync::Arc;

fn serialize_derivation_path(path: &DerivationPath) -> Vec<u32> { path.iter().map(|index| index.0).collect() }
fn ecdsa_curve_to_string(curve: EcdsaCurve) -> String {
    match curve {
        EcdsaCurve::Secp256k1 => "secp256k1".to_owned(),
    }
}

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

// Bitcoin(UTXO) operations.
impl TrezorClient {
    pub async fn get_utxo_address(
        &self,
        path: &DerivationPath,
        coin: TrezorCoin,
    ) -> TrezorResult<TrezorResponse<String>> {
        let mut req = proto_bitcoin::GetAddress::default();
        req.set_address_n(serialize_derivation_path(path));
        req.set_coin_name(coin.to_string());

        let result_handler = Box::new(|m: proto_bitcoin::Address| Ok(m.get_address().to_string()));
        self.call(req, result_handler).await
    }

    pub async fn get_public_key(
        &self,
        path: &DerivationPath,
        coin: TrezorCoin,
        ecdsa_curve: EcdsaCurve,
    ) -> TrezorResult<TrezorResponse<String>> {
        let mut req = proto_bitcoin::GetPublicKey::default();
        req.set_address_n(serialize_derivation_path(path));
        req.set_coin_name(coin.to_string());
        req.set_ecdsa_curve_name(ecdsa_curve_to_string(ecdsa_curve));

        let result_handler = Box::new(|m: proto_bitcoin::PublicKey| Ok(m.get_xpub().to_string()));
        self.call(req, result_handler).await
    }
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
            MessageType::MessageType_Failure => {
                let fail_msg: proto_common::Failure = resp.into_message()?;
                MmError::err(TrezorError::Failure(OperationFailure::from(fail_msg)))
            },
            MessageType::MessageType_ButtonRequest => {
                let req_msg = resp.into_message()?;
                // trace!("Received ButtonRequest: {:?}", req_msg);
                Ok(TrezorResponse::new_button_request(
                    req_msg,
                    self.clone(),
                    result_handler,
                ))
            },
            MessageType::MessageType_PinMatrixRequest => {
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
        let proto_msg = ProtoMessage::new(S::message_type(), message.write_to_bytes()?);
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
        let req = proto_management::Initialize::new();

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ok()
    }
}
