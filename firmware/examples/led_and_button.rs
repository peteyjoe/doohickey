#![no_std]
#![no_main]

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_time::Timer;
use panic_probe as _;

#[unsafe(link_section = ".bi_entries")]
#[used]
pub static PICOTOOL_ENTRIES: [embassy_rp::binary_info::EntryAddr; 4] = [
    embassy_rp::binary_info::rp_program_name!(c"blinky test wooooo"),
    embassy_rp::binary_info::rp_program_description!(c"GPIO 25 LED blink and GPIO 23 button test"),
    embassy_rp::binary_info::rp_cargo_version!(),
    embassy_rp::binary_info::rp_program_build_attribute!(),
];

#[embassy_executor::task]
async fn blink_led(mut led: Output<'static>) {
    defmt::info!("Blinky started on GPIO 25");
    loop {
        led.set_high();
        defmt::info!("LED on");
        Timer::after_millis(1000).await;

        led.set_low();
        defmt::info!("LED off");
        Timer::after_millis(1000).await;
    }
}

#[embassy_executor::task]
async fn read_button(mut button: Input<'static>) {
    // Active-low button: GPIO 23 is connected to GND when pressed.
    loop {
        button.wait_for_low().await;
        Timer::after_millis(20).await;
        if !button.is_low() {
            continue;
        }

        defmt::info!("Button on GPIO 23 pressed");

        // Debounce the release before accepting another press, so holding the
        // button produces a single message and release bounce cannot retrigger.
        loop {
            button.wait_for_high().await;
            Timer::after_millis(20).await;
            if button.is_high() {
                break;
            }
        }
    }
}

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(spawner: Spawner) {
    let peripherals = embassy_rp::init(Default::default());
    let led = Output::new(peripherals.PIN_25, Level::Low);
    let button = Input::new(peripherals.PIN_23, Pull::Up);

    spawner.spawn(blink_led(led).unwrap());
    spawner.spawn(read_button(button).unwrap());
}
