#[macro_use] extern crate serde_derive;

mod crypto_ctx;
mod hw_client;
mod hw_ctx;

pub use crypto_ctx::{CryptoCtx, CryptoInitError, CryptoInitResult};
pub use hw_client::{HwClient, HwError, HwResult, HwWalletType};
pub use hw_common::primitives::{DerivationPath, EcdsaCurve};
pub use hw_ctx::HardwareWalletCtx;
pub use trezor;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
