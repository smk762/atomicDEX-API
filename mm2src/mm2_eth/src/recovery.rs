use mm2_err_handle::prelude::*;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::{Message as SecpMessage, Secp256k1};
use web3::types::{H256, H520};

pub use ethkey::{Error, Signature};

/// Inspired by `ethkey::recover` with the only one difference:
/// this methods returns the full `H520` pubkey instead of unprefixed `H512`.
pub fn recover_pubkey(message_hash: H256, mut signature: Signature) -> MmResult<H520, Error> {
    if !(0..3).contains(&signature[64]) {
        if signature[64] < 27 {
            return MmError::err(Error::InvalidSignature);
        }
        // https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L459
        signature[64] -= 27;
    }

    let recovery_id = RecoveryId::from_i32(signature[64] as i32)?;
    let sig = RecoverableSignature::from_compact(&signature[0..64], recovery_id)?;
    let secp_message = SecpMessage::from_slice(message_hash.as_ref())?;
    let pubkey = Secp256k1::new().recover(&secp_message, &sig)?;
    let serialized = pubkey.serialize_uncompressed();

    Ok(H520::from_slice(&serialized))
}
