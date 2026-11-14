#![no_std]
#![no_main]

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_rp::gpio::{Level, Output};
use embassy_time::Timer;
use panic_probe as _;

#[unsafe(link_section = ".bi_entries")]
#[used]
pub static PICOTOOL_ENTRIES: [embassy_rp::binary_info::EntryAddr; 4] = [
    embassy_rp::binary_info::rp_program_name!(c"blinky test wooooo"),
    embassy_rp::binary_info::rp_program_description!(
        c"blinks an LED, what else do you need to know"
    ),
    embassy_rp::binary_info::rp_cargo_version!(),
    embassy_rp::binary_info::rp_program_build_attribute!(),
];

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(_spawner: Spawner) {
    let peripherals = embassy_rp::init(Default::default());
    let mut led = Output::new(peripherals.PIN_25, Level::Low);

    defmt::info!("Blinky started on GPIO 25");
    loop {
        led.set_high();
        defmt::info!("LED on");
        Timer::after_millis(200).await;

        led.set_low();
        defmt::info!("LED off");
        Timer::after_millis(200).await;
    }
}
