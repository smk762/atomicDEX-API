//! This file is inspired by https://github.com/tezedge/tezedge-client/blob/master/trezor_api/src/client.rs

use crate::proto::messages::MessageType;
use crate::proto::messages_bitcoin as proto_bitcoin;
use crate::proto::messages_management as proto_management;
use crate::proto::{ProtoMessage, TrezorMessage};
use crate::response::TrezorResponse;
use crate::transport::Transport;
use crate::{TrezorError, TrezorResult};
use common::mm_error::prelude::*;
use hw_common::primitives::KeyDerivationPath;

/// Function to be passed to the [`TrezorClient::call`] method
/// to process the Trezor response message into a general-purpose type.
pub(crate) type ResultHandler<'a, T, R> = Box<dyn Fn(&'a mut TrezorClient, R) -> TrezorResult<T>>;

pub struct TrezorClient {
    transport: Box<dyn Transport + 'static>,
    /// Device features. This is initialized on [`TrezorClient::initialize_device`].
    #[allow(dead_code)]
    features: Option<proto_management::Features>,
}

// Bitcoin(UTXO) operations.
impl TrezorClient {
    pub async fn get_utxo_address(
        &mut self,
        path: &KeyDerivationPath,
        coin_name: String,
    ) -> TrezorResult<TrezorResponse<'_, String, proto_bitcoin::Address>> {
        let mut req = proto_bitcoin::GetAddress::default();
        req.set_address_n(path.as_ref().to_vec());
        req.set_coin_name(coin_name);

        let result_handler = Box::new(|_, m: proto_bitcoin::Address| Ok(m.get_address().to_string()));
        self.call(req, result_handler).await
    }

    pub async fn get_public_key(
        &mut self,
        path: &KeyDerivationPath,
        coin_name: String,
    ) -> TrezorResult<TrezorResponse<'_, String, proto_bitcoin::PublicKey>> {
        let mut req = proto_bitcoin::GetPublicKey::default();
        req.set_address_n(path.as_ref().to_vec());
        req.set_coin_name(coin_name);

        let result_handler = Box::new(|_, m: proto_bitcoin::PublicKey| Ok(m.get_xpub().to_string()));
        self.call(req, result_handler).await
    }
}

impl TrezorClient {
    /// Create a `TrezorClient` from the given `transport` and initialize the device
    /// by sending the [Initialize](https://docs.trezor.io/trezor-firmware/common/communication/sessions.html#examples) Protobuf message.
    pub async fn init<T: Transport + 'static>(transport: T) -> TrezorResult<TrezorClient> {
        let mut client = TrezorClient {
            transport: Box::new(transport),
            features: None,
        };
        client.initialize_device().await?;
        Ok(client)
    }

    /// Sends a message and returns a TrezorResponse with either the
    /// expected response message, a failure or an interaction request.
    pub async fn call<'a, T, S: TrezorMessage, R: TrezorMessage>(
        &'a mut self,
        message: S,
        result_handler: ResultHandler<'a, T, R>,
    ) -> TrezorResult<TrezorResponse<'a, T, R>> {
        // trace!("Sending {:?} msg: {:?}", S::message_type(), message);
        let resp = self.call_raw(message).await?;
        if resp.message_type() == R::message_type() {
            let resp_msg = resp.into_message()?;
            // trace!("Received {:?} msg: {:?}", R::message_type(), resp_msg);
            Ok(TrezorResponse::Ok(result_handler(self, resp_msg)?))
        } else {
            match resp.message_type() {
                MessageType::MessageType_Failure => {
                    let fail_msg = resp.into_message()?;
                    // debug!("Received failure: {:?}", fail_msg);
                    Ok(TrezorResponse::Failure(fail_msg))
                },
                MessageType::MessageType_ButtonRequest => {
                    let req_msg = resp.into_message()?;
                    // trace!("Received ButtonRequest: {:?}", req_msg);
                    Ok(TrezorResponse::new_button_request(req_msg, self, result_handler))
                },
                MessageType::MessageType_PinMatrixRequest => {
                    let req_msg = resp.into_message()?;
                    // trace!("Received PinMatrixRequest: {:?}", req_msg);
                    Ok(TrezorResponse::new_pin_matrix_request(req_msg, self, result_handler))
                },
                mtype => {
                    // debug!(
                    // 	"Received unexpected msg type: {:?}; raw msg: {}",
                    // 	mtype,
                    // 	hex::encode(resp.into_payload())
                    // );
                    MmError::err(TrezorError::UnexpectedMessageType(mtype))
                },
            }
        }
    }

    /// Sends a message and returns the raw ProtoMessage struct that was
    /// responded by the device.
    async fn call_raw<S: TrezorMessage>(&mut self, message: S) -> TrezorResult<ProtoMessage> {
        let proto_msg = ProtoMessage::new(S::message_type(), message.write_to_bytes()?);
        self.transport.write_message(proto_msg).await?;
        self.transport.read_message().await
    }

    /// Initialize the device.
    ///
    /// # Warning
    ///
    /// Must be called before sending requests to Trezor.
    async fn initialize_device(&mut self) -> TrezorResult<()> {
        // Don't set the session_id since currently there is no need to restore the previous session.
        // https://docs.trezor.io/trezor-firmware/common/communication/sessions.html#session-lifecycle
        let req = proto_management::Initialize::new();

        let result_handler = Box::new(|_, m: proto_management::Features| Ok(m));
        let features = self.call(req, result_handler).await?.ok()?;
        self.features = Some(features);
        Ok(())
    }
}
