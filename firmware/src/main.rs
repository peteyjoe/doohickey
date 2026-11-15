#![no_std]
#![no_main]

pub mod ctap;
pub mod init;
pub mod otp;
pub mod storage;
pub mod usb;
pub use doohickey_crypto as crypto;

use core::cell::Cell;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::gpio::{Input, Pull};
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
    let peripherals = embassy_rp::init(Default::default());
    let button = Input::new(peripherals.PIN_23, Pull::Up);

    let storage = storage::Storage::new(peripherals.FLASH, peripherals.DMA_CH0);
    let mut coordinator = init::Coordinator::new(init::DeviceBackend::new(storage));
    let report = coordinator.inspect().await;
    defmt::info!(
        "Startup: {} ({})",
        report.state.as_str(),
        report.reason.as_str()
    );

    // Diagnostics stay reachable in every reported startup state. A future
    // authenticator backend must start only after application state validates.
    let status = Cell::new(report);
    let information = usb::management::LiveInformation {
        flash_size: storage::FLASH_SIZE,
        insecure_test_otp: otp::IS_FLASH_BACKED,
        initialization: &status,
    };
    join(
        usb::run_with_handlers(
            peripherals.USB,
            usb::ctaphid::UnavailableBackend,
            information,
        ),
        init::run_setup(&mut coordinator, button, peripherals.TRNG, &status),
    )
    .await;
    unreachable!()
}
