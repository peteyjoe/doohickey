//! Composite USB: FIDO HID interface 0, CDC ACM control/data interfaces 1/2.
pub mod cbor;
pub mod ctaphid;
pub mod framing;
mod hid;
pub mod management;
pub mod serial;
mod session;
pub use session::SessionState;

use embassy_futures::join::join3;
use embassy_rp::{
    Peri, bind_interrupts,
    peripherals::USB,
    usb::{Driver, InterruptHandler},
};
use embassy_usb::{
    Builder, Config, Handler,
    class::{cdc_acm, hid as usb_hid},
    control::{OutResponse, Recipient, Request, RequestType},
};

// Development placeholders, centralized for replacement with assigned IDs.
pub const VENDOR_ID: u16 = 0xc0de;
pub const PRODUCT_ID: u16 = 0xd001;

bind_interrupts!(struct Irqs { USBCTRL_IRQ => InterruptHandler<USB>; });

struct Events<'a>(&'a SessionState);
impl Handler for Events<'_> {
    fn reset(&mut self) {
        self.0.invalidate();
    }
    fn enabled(&mut self, enabled: bool) {
        if !enabled {
            self.0.invalidate();
        }
    }
    fn configured(&mut self, configured: bool) {
        self.0.configure(configured);
    }
    fn control_out(&mut self, request: Request, _data: &[u8]) -> Option<OutResponse> {
        // Observe CDC line-coding/DTR/RTS changes without consuming the request.
        // Count events, so even a rapid close/reopen invalidates the old frame
        // and future Noise session while a bulk write is awaiting the host.
        if request.request_type == RequestType::Class
            && request.recipient == Recipient::Interface
            && request.index == 1
            && matches!(request.request, 0x20 | 0x22)
        {
            self.0.serial_changed();
        }
        None
    }
}

/// All descriptors and class state live in this pinned async future. No heap,
/// static mut, flash writes, OTP provisioning, or host pairing occurs here.
pub async fn run(peripheral: Peri<'static, USB>) -> ! {
    let info = management::Information {
        ctap_ready: false,
        flash_size: crate::storage::FLASH_SIZE,
        insecure_test_otp: cfg!(feature = "insecure-test-otp"),
        initialization: crate::init::Report::NOT_CHECKED,
    };
    run_with_handlers(peripheral, cbor::DiscoveryBackend::default(), info).await
}

/// Application integration point. A CBOR backend can forward to a single
/// authenticator owner; serial authentication remains an independent handler.
pub async fn run_with_handlers(
    peripheral: Peri<'static, USB>,
    backend: impl ctaphid::Backend,
    serial_handler: impl management::Handler,
) -> ! {
    let driver = Driver::new(peripheral, Irqs);
    let mut config = Config::new(VENDOR_ID, PRODUCT_ID);
    config.manufacturer = Some("DOOHICKEY");
    config.product = Some("DOOHICKEY");
    config.device_class = 0xef;
    config.device_sub_class = 0x02;
    config.device_protocol = 0x01;
    config.composite_with_iads = true;
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut msos_descriptor = [0; 0];
    let mut control_buffer = [0; 64];
    let sessions = SessionState::new();
    let mut events = Events(&sessions);
    let mut hid_state = usb_hid::State::new();
    let mut cdc_state = cdc_acm::State::new();
    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control_buffer,
    );
    builder.handler(&mut events);
    let hid = usb_hid::HidReaderWriter::<_, 64, 64>::new(
        &mut builder,
        &mut hid_state,
        usb_hid::Config {
            report_descriptor: ctaphid::REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: 64,
            hid_subclass: usb_hid::HidSubclass::No,
            hid_boot_protocol: usb_hid::HidBootProtocol::None,
        },
    );
    let cdc = cdc_acm::CdcAcmClass::new(&mut builder, &mut cdc_state, 64);
    let mut device = builder.build();
    let version = [
        env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
        env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
        env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0),
    ];
    let engine = ctaphid::Engine::new(backend, version);
    defmt::info!("USB composite starting: FIDO HID + CDC ACM");
    join3(
        device.run(),
        hid::run(hid, &sessions, engine),
        serial::run(cdc, &sessions, serial_handler),
    )
    .await;
    unreachable!()
}
