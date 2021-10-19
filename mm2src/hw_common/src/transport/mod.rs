#[cfg(target_arch = "wasm32")] pub mod webusb_driver;
#[cfg(target_arch = "wasm32")]
pub use webusb_driver::WebUsbError;
