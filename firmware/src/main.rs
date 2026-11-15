#![no_std]
#![no_main]

pub mod application;
pub mod button;
pub mod ctap;
pub mod init;
pub mod otp;
pub mod serial_service;
pub mod storage;
pub mod usb;
pub use doohickey_crypto as crypto;

#[used]
static UPDATE_DESCRIPTOR: [u8; 64] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/update_descriptor.bin"));

use core::cell::Cell;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::gpio::{Level, Output};
use panic_probe as _;

#[unsafe(link_section = ".bi_entries")]
#[used]
pub static PICOTOOL_ENTRIES: [embassy_rp::binary_info::EntryAddr; 4] = [
    embassy_rp::binary_info::rp_program_name!(c"DOOHICKEY"),
    embassy_rp::binary_info::rp_program_description!(c"FIDO HID and CDC ACM composite USB"),
    embassy_rp::binary_info::rp_cargo_version!(),
    embassy_rp::binary_info::rp_program_build_attribute!(),
];

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(_spawner: Spawner) {
    core::hint::black_box(&UPDATE_DESCRIPTOR);
    let peripherals = embassy_rp::init(Default::default());
    let button = button::Button::new(peripherals.BOOTSEL);
    let led = Output::new(peripherals.PIN_25, Level::Low);

    let storage = storage::Storage::new(peripherals.FLASH, peripherals.DMA_CH0);
    let mut coordinator = init::Coordinator::new(init::DeviceBackend::new(storage));
    let report = coordinator.inspect().await;
    defmt::info!(
        "Startup: {} ({})",
        report.state.as_str(),
        report.reason.as_str()
    );

    // Diagnostics stay reachable in every startup state; the application owner
    // enables credential operations only after initialization and entropy pass.
    let status = Cell::new(report);
    let exchange = ctap::exchange::Exchange::new();
    let serial_exchange = ctap::exchange::Exchange::new();
    let information = usb::management::LiveInformation {
        flash_size: storage::FLASH_SIZE,
        insecure_test_otp: otp::IS_FLASH_BACKED,
        initialization: &status,
        ctap_ready: &exchange.ready,
    };
    join(
        usb::run_with_handlers(
            peripherals.USB,
            usb::cbor::AuthenticatorBackend(&exchange),
            usb::management::SerialAdapter {
                information,
                exchange: &serial_exchange,
            },
        ),
        application::run(
            &mut coordinator,
            button,
            led,
            peripherals.TRNG,
            &status,
            &exchange,
            &serial_exchange,
        ),
    )
    .await;
    unreachable!()
}
