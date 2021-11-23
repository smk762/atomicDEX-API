#[macro_use] extern crate serde_derive;

pub mod client;
pub mod constants;
pub mod error;
mod proto;
pub mod response;
pub mod response_channel;
pub mod transport;
pub mod trezor_rpc_task;
pub mod user_interaction;
pub mod utxo;

pub use client::TrezorClient;
pub use constants::TrezorCoin;
pub use error::{OperationFailure, TrezorError, TrezorResult};
pub use hw_common::primitives::{DerivationPath, EcdsaCurve};
pub use response::{ButtonRequest, PinMatrixRequest, TrezorResponse};
pub use response_channel::{TrezorEvent, TrezorResponseReceiver};
pub use user_interaction::{TrezorPinMatrix3x3Response, TrezorUserInteraction};

pub(crate) fn serialize_derivation_path(path: &DerivationPath) -> Vec<u32> {
    path.iter().map(|index| index.0).collect()
}

pub(crate) fn ecdsa_curve_to_string(curve: EcdsaCurve) -> String {
    match curve {
        EcdsaCurve::Secp256k1 => "secp256k1".to_owned(),
    }
}
