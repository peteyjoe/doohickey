#![no_std]
#![no_main]

use defmt_rtt as _; // panic-probe needs a defmt logger linked in, even though nothing reads it now
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config};
use panic_probe as _;

#[unsafe(link_section = ".bi_entries")]
#[used]
pub static PICOTOOL_ENTRIES: [embassy_rp::binary_info::EntryAddr; 4] = [
    embassy_rp::binary_info::rp_program_name!(c"cdc echo"),
    embassy_rp::binary_info::rp_program_description!(c"USB CDC-ACM echo"),
    embassy_rp::binary_info::rp_cargo_version!(),
    embassy_rp::binary_info::rp_program_build_attribute!(),
];

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    let driver = Driver::new(p.USB, Irqs);

    // 1. Device identity. 0x1209:0x0001 is pid.codes' public test ID
    let mut config = Config::new(0x1209, 0x0001);
    config.manufacturer = Some("SunHacks");
    config.product = Some("FIDO2 backup (dev)");
    config.serial_number = Some("0001");
    config.max_power = 100; // mA
    config.max_packet_size_0 = 64;

    // 2. Scratch buffers the builder writes descriptors into.
    //    `[0; 256]` = array of 256 bytes, all zero. They live on main's
    //    stack, which is fine because main never returns.
    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 64];

    // 3. CDC class state
    let mut state = State::new();

    // 4. The builder collects interfaces/endpoints. `&mut` means "borrow
    //    mutably": the builder temporarily has exclusive access to these
    //    buffers and must not outlive them.
    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [], // MS OS descriptors: not needed for CDC
        &mut control_buf,
    );

    // 5. Add a CDC-ACM interface (64 = max packet size for the endpoints).
    let mut class = CdcAcmClass::new(&mut builder, &mut state, 64);

    // 6. Finish the descriptors and get the USB device object.
    let mut usb = builder.build();

    // 7. Two futures. Nothing runs yet, until join is called
    //    `usb.run()` handles enumeration, control requests and bus resets.
    let usb_fut = usb.run();

    let echo_fut = async {
        loop {
            // Waits until the host opens the port (DTR asserted)
            class.wait_connection().await;
            // `let _ =` ignores the result
            let _ = echo(&mut class).await;
        }
    };

    // run both futures at once inside this single task. `join` polls each future
    // never returns
    join(usb_fut, echo_fut).await;
}

/// "the host went away" error
struct Disconnected;

/// `From` lets the `?` operator convert embassy's error into ours automatically.
impl From<EndpointError> for Disconnected {
    fn from(e: EndpointError) -> Self {
        match e {
            // Packet bigger than our buffer. Unlikely to happen
            EndpointError::BufferOverflow => panic!("buffer overflow"),
            // Endpoint disabled = cable pulled or port closed.
            EndpointError::Disabled => Disconnected,
        }
    }
}

// `'d` is a lifetime: it ties the class to the driver/buffers it borrows from.
async fn echo<'d>(class: &mut CdcAcmClass<'d, Driver<'d, USB>>) -> Result<(), Disconnected> {
    let mut buf = [0u8; 64];
    loop {
        // `?` = "if this returned Err, return that Err from this function now
        // otherwise unwrap the Ok value".
        let n = class.read_packet(&mut buf).await?;
        let data = &buf[..n]; // slice: a view of the first n bytes, no copy
        class.write_packet(data).await?;
        class.write_packet(data).await?;
    }
}