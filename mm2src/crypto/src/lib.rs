#[macro_use] extern crate serde_derive;

mod crypto_ctx;
mod hw_client;
pub mod hw_task;

pub use crypto_ctx::{CryptoCtx, CryptoInitError, CryptoInitResult, CryptoResponse};
pub use hw_client::{HwClient, HwDelayedResponse, HwError, HwResponse, HwResult, HwUserInteraction, HwWalletType};
pub use trezor;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
