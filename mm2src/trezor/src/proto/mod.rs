//! This file is inspired by https://github.com/tezedge/tezedge-client/blob/master/trezor_api/src/messages.rs
//! In this module we implement the `message_type` getter for all protobuf message types.

#[allow(clippy::all)] pub mod messages;
#[allow(clippy::all)] pub mod messages_bitcoin;
#[allow(clippy::all)] pub mod messages_common;
#[allow(clippy::all)] pub mod messages_management;

use messages::MessageType::{self, *};
use messages_bitcoin::*;
use messages_common::*;
use messages_management::*;

/// This macro provides the TrezorMessage trait for a protobuf message.
macro_rules! trezor_message_impl {
    ($struct:ident, $mtype:expr) => {
        impl TrezorMessage for $struct {
            fn message_type() -> MessageType { $mtype }
        }
    };
}

/// A protobuf message accompanied by the message type.
/// This type is used to pass messages over the transport
/// and used to contain messages received from the transport.
pub struct ProtoMessage {
    message_type: MessageType,
    payload: Vec<u8>,
}

impl ProtoMessage {
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> ProtoMessage { ProtoMessage { message_type, payload } }

    pub fn message_type(&self) -> MessageType { self.message_type }

    pub fn payload(&self) -> &[u8] { &self.payload }

    pub fn into_payload(self) -> Vec<u8> { self.payload }

    /// Take the payload from the ProtoMessage and parse it to a protobuf message.
    pub fn into_message<M: protobuf::Message>(self) -> Result<M, protobuf::error::ProtobufError> {
        protobuf::Message::parse_from_bytes(&self.into_payload())
    }
}

/// This trait extends the protobuf Message trait to also have a static getter for the message
/// type code.
pub trait TrezorMessage: protobuf::Message {
    fn message_type() -> MessageType;
}

// Management
trezor_message_impl!(Initialize, MessageType_Initialize);
trezor_message_impl!(Ping, MessageType_Ping);
trezor_message_impl!(ChangePin, MessageType_ChangePin);
trezor_message_impl!(WipeDevice, MessageType_WipeDevice);
trezor_message_impl!(GetEntropy, MessageType_GetEntropy);
trezor_message_impl!(Entropy, MessageType_Entropy);
trezor_message_impl!(LoadDevice, MessageType_LoadDevice);
trezor_message_impl!(ResetDevice, MessageType_ResetDevice);
trezor_message_impl!(Features, MessageType_Features);
trezor_message_impl!(Cancel, MessageType_Cancel);
trezor_message_impl!(EndSession, MessageType_EndSession);
trezor_message_impl!(ApplySettings, MessageType_ApplySettings);
trezor_message_impl!(ApplyFlags, MessageType_ApplyFlags);
trezor_message_impl!(BackupDevice, MessageType_BackupDevice);
trezor_message_impl!(EntropyRequest, MessageType_EntropyRequest);
trezor_message_impl!(EntropyAck, MessageType_EntropyAck);
trezor_message_impl!(RecoveryDevice, MessageType_RecoveryDevice);
trezor_message_impl!(WordRequest, MessageType_WordRequest);
trezor_message_impl!(WordAck, MessageType_WordAck);
trezor_message_impl!(GetFeatures, MessageType_GetFeatures);
trezor_message_impl!(SetU2FCounter, MessageType_SetU2FCounter);
// Common
trezor_message_impl!(Success, MessageType_Success);
trezor_message_impl!(Failure, MessageType_Failure);
trezor_message_impl!(PinMatrixRequest, MessageType_PinMatrixRequest);
trezor_message_impl!(PinMatrixAck, MessageType_PinMatrixAck);
trezor_message_impl!(ButtonRequest, MessageType_ButtonRequest);
trezor_message_impl!(ButtonAck, MessageType_ButtonAck);
// Bitcoin
trezor_message_impl!(GetAddress, MessageType_GetAddress);
trezor_message_impl!(Address, MessageType_Address);
trezor_message_impl!(GetPublicKey, MessageType_GetPublicKey);
trezor_message_impl!(PublicKey, MessageType_PublicKey);
