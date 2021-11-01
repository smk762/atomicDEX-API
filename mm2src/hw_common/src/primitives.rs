pub const HARDENED_PATH: u32 = 2147483648;

pub use bip32::DerivationPath;

#[derive(Clone, Copy)]
pub enum EcdsaCurve {
    Secp256k1,
}
