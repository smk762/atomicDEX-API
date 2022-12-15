#[cfg(target_arch = "wasm32")] mod eip_1193_provider;
#[cfg(target_arch = "wasm32")] mod metamask;
#[cfg(target_arch = "wasm32")] mod metamask_error;

#[cfg(target_arch = "wasm32")]
pub use eip_1193_provider::Eip1193Provider;
#[cfg(target_arch = "wasm32")]
pub use metamask::{detect_metamask_provider, EthAccount, MetamaskSession, ObjectType, PropertyType};
#[cfg(target_arch = "wasm32")]
pub use metamask_error::{from_metamask_error, MetamaskError, MetamaskResult, MetamaskRpcError, WithMetamaskRpcError};
