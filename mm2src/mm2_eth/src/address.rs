use ethkey::{public_to_address, Address, Public};
use web3::types::H520;

pub fn address_from_pubkey_uncompressed(bytes: H520) -> Address {
    // Skip the first byte of the uncompressed public key.
    let public = Public::from_slice(&bytes[1..]);
    public_to_address(&public)
}
