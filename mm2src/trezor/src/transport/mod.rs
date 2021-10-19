use crate::proto::ProtoMessage;
use crate::TrezorResult;
use async_trait::async_trait;
use rand::RngCore;

mod protocol;
#[cfg(target_arch = "wasm32")] pub mod webusb;

/// The transport interface that is implemented by the different ways to communicate with a Trezor
/// device.
#[async_trait]
pub trait Transport {
    async fn session_begin(&mut self) -> TrezorResult<()>;
    async fn session_end(&mut self) -> TrezorResult<()>;

    async fn write_message(&mut self, message: ProtoMessage) -> TrezorResult<()>;
    async fn read_message(&mut self) -> TrezorResult<ProtoMessage>;
}

/// The Trezor session identifier.
/// https://docs.trezor.io/trezor-firmware/common/communication/sessions.html#session-lifecycle
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Generate a new random `SessionId`.
    pub fn new() -> SessionId {
        let mut rng = rand::thread_rng();

        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        SessionId(bytes)
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
