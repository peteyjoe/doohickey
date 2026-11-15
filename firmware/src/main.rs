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

mod framing; // pulls in src/cobs.rs
mod protocol;

use framing::{FrameReader, Push};

const MAX_PAYLOAD: usize = 512;
// +1 for the delimiter we now append ourselves
const MAX_ENCODED: usize = cobs::max_encoding_length(MAX_PAYLOAD) + 1;

#[unsafe(link_section = ".bi_entries")]
#[used]
pub static PICOTOOL_ENTRIES: [embassy_rp::binary_info::EntryAddr; 4] = [
    embassy_rp::binary_info::rp_program_name!(c"cdc cobs"),
    embassy_rp::binary_info::rp_program_description!(c"USB CDC-ACM cobs test"),
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

async fn echo<'d>(class: &mut CdcAcmClass<'d, Driver<'d, USB>>) -> Result<(), Disconnected> {
    let mut packet = [0u8; 64];
    let mut reader = FrameReader::<MAX_ENCODED>::new();
    let mut decoded = [0u8; MAX_PAYLOAD];
    let mut tx = [0u8; MAX_ENCODED];
    let mut resp = [0u8; MAX_PAYLOAD];

    loop {
        let n = class.read_packet(&mut packet).await?;

        // A message can be split across packets, or several can share one,
        // so feed bytes one at a time and let the reader find the boundaries.
        for &b in &packet[..n] {
            match reader.push(b) {
                Push::Pending => {}
                Push::Overflow => send_frame(class, b"ERR overflow", &mut tx).await?,
                Push::Frame(frame) => match cobs::decode(frame, &mut decoded) {
                    Ok(report) => {
                        let len = report.frame_size();
                        let n = protocol::handle(&decoded[..len], &mut resp);
                        send_frame(class, &resp[..n], &mut tx).await?
                    }
                    Err(_) => send_frame(class, b"ERR bad frame", &mut tx).await?,
                },
            }
        }
    }
}

/// COBS-encode `payload` into the scratch buffer `tx` and send it.
async fn send_frame<'d>(
    class: &mut CdcAcmClass<'d, Driver<'d, USB>>,
    payload: &[u8],
    tx: &mut [u8],
) -> Result<(), Disconnected> {
    let Ok(n) = cobs::try_encode(payload, tx) else {
        return Ok(()); // payload too big for tx
    };
    tx[n] = 0; // append the delimiter ourselves
    let n = n + 1;
    // USB bulk packets max out at 64 bytes, so send in chunks.
    for chunk in tx[..n].chunks(64) {
        class.write_packet(chunk).await?;
    }
    // If the data ended exactly on a 64-byte boundary, send an empty packet
    // so the host knows the transfer is over.
    if n % 64 == 0 {
        class.write_packet(&[]).await?;
    }
    Ok(())
}
