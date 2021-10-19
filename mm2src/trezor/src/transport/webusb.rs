use crate::proto::ProtoMessage;
use crate::transport::protocol::{Link, Protocol, ProtocolV1};
use crate::transport::Transport;
use crate::{TrezorError, TrezorResult};
use async_trait::async_trait;
use common::executor::Timer;
use common::log::warn;
use common::mm_error::prelude::*;
use hw_common::transport::webusb_driver::{DeviceFilter, WebUsbDevice, WebUsbWrapper};

pub use hw_common::transport::webusb_driver::WebUsbDeviceInfo;

const T1HID_VENDOR: u16 = 0x534c;
const CONFIGURATION_ID: u8 = 1;
const DEBUG_ENDPOINT_ID: u8 = 2;

const TREZOR_DEVICES: [DeviceFilter; 3] = [
    // TREZOR v1
    // won't get opened, but we can show error at least
    DeviceFilter::with_product_id(0x534c, 0x0001),
    // TREZOR webusb Bootloader
    DeviceFilter::with_product_id(0x1209, 0x53c0),
    // TREZOR webusb Firmware
    DeviceFilter::with_product_id(0x1209, 0x53c1),
];

pub struct WebUsbTransport {
    protocol: ProtocolV1<WebUsbLink>,
}

#[async_trait]
impl Transport for WebUsbTransport {
    async fn session_begin(&mut self) -> TrezorResult<()> { self.protocol.session_begin().await }

    async fn session_end(&mut self) -> TrezorResult<()> { self.protocol.session_end().await }

    async fn write_message(&mut self, message: ProtoMessage) -> TrezorResult<()> { self.protocol.write(message).await }

    async fn read_message(&mut self) -> TrezorResult<ProtoMessage> { self.protocol.read().await }
}

struct WebUsbLink {
    device: WebUsbDevice,
    interface_number: u8,
    endpoint_number: u8,
    debug: bool,
}

#[async_trait]
impl Link for WebUsbLink {
    async fn write_chunk(&mut self, chunk: Vec<u8>) -> TrezorResult<()> {
        if !self.device.is_open().await? {
            self.reconnect().await?;
        }
        Ok(self.device.write_chunk(self.endpoint_number, chunk).await?)
    }

    async fn read_chunk(&mut self, chunk_len: u32) -> TrezorResult<Vec<u8>> {
        if !self.device.is_open().await? {
            self.reconnect().await?;
        }
        Ok(self.device.read_chunk(self.endpoint_number, chunk_len).await?)
    }
}

impl WebUsbLink {
    #[allow(dead_code)]
    pub fn is_debug(&self) -> bool { self.debug }

    async fn reconnect(&self) -> TrezorResult<()> {
        let attempts = 5usize;
        let first = false;
        for i in 0..attempts {
            match self.establish_connection(first).await {
                Ok(()) => return Ok(()),
                Err(e) if i != attempts - 1 => {
                    warn!(
                        "Unsuccessful attempt to connect: '{}'. Attempts left: {}",
                        e,
                        attempts - i - 1
                    );
                    Timer::sleep_ms(500).await;
                },
                Err(_) => (),
            }
        }
        return MmError::err(TrezorError::DeviceDisconnected);
    }

    /// Configure the WebUSB device.
    async fn establish_connection(&self, first: bool) -> TrezorResult<()> {
        self.device.open().await?;
        if first {
            self.device.select_configuration(CONFIGURATION_ID).await?;
            if let Err(e) = self.device.reset_device().await {
                // Reset fails on ChromeOS and Windows.
                warn!("{}", e);
            }
        }
        self.device.claim_interface(self.interface_number).await?;
        Ok(())
    }
}

pub struct WebUsbAvailableDevice(WebUsbLink);

impl WebUsbAvailableDevice {
    pub async fn connect(self) -> TrezorResult<WebUsbTransport> {
        let first = true;
        self.0.establish_connection(first).await?;
        Ok(WebUsbTransport {
            protocol: ProtocolV1 { link: self.0 },
        })
    }

    fn from_webusb_device(device: WebUsbDevice) -> Result<WebUsbAvailableDevice, String> {
        let (interface_number, endpoint_number) = match device.device_info.interface {
            Some(ref interface) => (interface.interface_number, interface.endpoint_number),
            None => return Err(format!("Unknown interface: {:?}", device.device_info)),
        };
        Ok(WebUsbAvailableDevice(WebUsbLink {
            device,
            interface_number,
            endpoint_number,
            debug: endpoint_number == DEBUG_ENDPOINT_ID,
        }))
    }
}

pub struct FoundDevices {
    pub available: Vec<WebUsbAvailableDevice>,
    pub not_supported: Vec<WebUsbDeviceInfo>,
}

/// The implementation is inspired by (WebUsbPlugin::_listDevices)[https://github.com/trezor/trezor-link/blob/master/src/lowlevel/webusb.js#L74].
///
/// # Usage
///
/// This function **must** be called via a user gesture like a touch or mouse click.
pub async fn find_devices() -> TrezorResult<FoundDevices> {
    let wrapper = WebUsbWrapper::new()?;
    wrapper.request_device(TREZOR_DEVICES.to_vec()).await?;
    let devices_iter = wrapper.get_devices().await?.into_iter().filter(is_trezor);
    let mut available = Vec::new();
    let mut not_supported = Vec::new();
    for device in devices_iter {
        if is_hid(&device) {
            not_supported.push(device.device_info);
            continue;
        }
        match WebUsbAvailableDevice::from_webusb_device(device) {
            Ok(device) => available.push(device),
            Err(e) => {
                warn!("Skip the device: {}", e);
                continue;
            },
        }
    }
    Ok(FoundDevices {
        available,
        not_supported,
    })
}

fn is_trezor(device: &WebUsbDevice) -> bool {
    let (vendor_id, product_id) = (device.device_info.vendor_id, device.device_info.product_id);
    TREZOR_DEVICES
        .iter()
        .any(|expected| vendor_id == expected.vendor_id && product_id == expected.product_id.unwrap_or(product_id))
}

fn is_hid(device: &WebUsbDevice) -> bool { device.device_info.vendor_id == T1HID_VENDOR }
