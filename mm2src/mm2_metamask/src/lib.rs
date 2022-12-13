#[cfg(target_arch = "wasm32")] mod eip_1193_provider;
#[cfg(target_arch = "wasm32")] mod eth_provider;
#[cfg(target_arch = "wasm32")] mod metamask;
#[cfg(target_arch = "wasm32")] mod metamask_error;
#[cfg(target_arch = "wasm32")] mod metamask_provider;
#[cfg(target_arch = "wasm32")] mod metamask_session;

#[cfg(target_arch = "wasm32")]
pub use metamask_error::{from_metamask_error, MetamaskError, MetamaskResult, MetamaskRpcError, WithMetamaskRpcError};
#[cfg(target_arch = "wasm32")]
pub use metamask_provider::{EthAccount, MetamaskProvider, ObjectType, PropertyType};
