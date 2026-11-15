//! CDC framing and asynchronous handler dispatch. Credential authorization and
//! pairing live in the single application owner, never in the USB task.
use super::{
    SessionState,
    framing::{Decoder, MAX_FRAME_SIZE},
    management::Handler,
    session::Interface,
};
use embassy_futures::select::{Either3, select3};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embassy_usb::{
    class::cdc_acm::{CdcAcmClass, Sender},
    driver::Driver,
};
use zeroize::{Zeroize, Zeroizing};

async fn send<'d, D: Driver<'d>>(
    sender: &mut Sender<'d, D>,
    data: &[u8],
    sessions: &SessionState,
    epoch: u32,
) -> Result<(), ()> {
    if data.is_empty() || data.len() > MAX_FRAME_SIZE {
        return Err(());
    }
    let mut framed = Zeroizing::new([0; MAX_FRAME_SIZE + 2]);
    framed[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    framed[2..data.len() + 2].copy_from_slice(data);
    for packet in framed[..data.len() + 2].chunks(64) {
        if sessions.serial_epoch() != epoch || !sessions.configured() || !sender.dtr() {
            return Err(());
        }
        with_timeout(
            Duration::from_secs(2),
            sessions.guard_write(Interface::Serial, epoch, sender.write_packet(packet)),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    }
    if (data.len() + 2).is_multiple_of(64) {
        with_timeout(
            Duration::from_secs(2),
            sessions.guard_write(Interface::Serial, epoch, sender.write_packet(&[])),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    }
    Ok(())
}

pub async fn run<'d, D: Driver<'d>>(
    class: CdcAcmClass<'d, D>,
    sessions: &SessionState,
    mut handler: impl Handler,
) -> ! {
    let (mut sender, mut receiver, control) = class.split_with_control();
    let mut decoder = Decoder::new();
    let mut packet = [0; 64];
    let mut response = Zeroizing::new([0; MAX_FRAME_SIZE]);
    let mut epoch = sessions.serial_epoch();
    let mut dtr = false;
    let mut quarantined = false;
    loop {
        let current_epoch = sessions.serial_epoch();
        let current_dtr = control.dtr();
        if epoch != current_epoch || dtr != current_dtr || !sessions.configured() {
            decoder.reset();
            response.zeroize();
            packet.zeroize();
            handler.disconnected();
            quarantined = false;
            epoch = current_epoch;
            dtr = current_dtr;
        }
        // Reading stays live while closed, so bytes from an old session cannot
        // become the beginning of the next session's authenticated handshake.
        let result = select3(
            control.control_changed(),
            receiver.read_packet(&mut packet),
            Timer::after_millis(10),
        )
        .await;
        let now = Instant::now().as_millis();
        if sessions.serial_epoch() != epoch || control.dtr() != dtr {
            continue;
        }
        if !dtr || !sessions.configured() {
            packet.zeroize();
            continue;
        }
        if !quarantined && decoder.check_timeout(now).is_err() {
            quarantined = true;
            handler.disconnected();
            let _ = send(&mut sender, b"ERR FRAME_TIMEOUT", sessions, epoch).await;
        }
        match result {
            Either3::Second(Ok(n)) if !quarantined => {
                for byte in packet[..n].iter().copied() {
                    if sessions.serial_epoch() != epoch || control.dtr() != dtr {
                        break;
                    }
                    match decoder.push(byte, now) {
                        Ok(Some(frame)) => {
                            let length = handler
                                .handle_async(sessions, frame, &mut response[..])
                                .await;
                            let body = match length {
                                Ok(n) if n > 0 && n <= MAX_FRAME_SIZE => &response[..n],
                                _ => {
                                    response.zeroize();
                                    b"ERR AUTH_UNAVAILABLE"
                                }
                            };
                            if send(&mut sender, body, sessions, epoch).await.is_err() {
                                quarantined = true;
                                handler.disconnected();
                                decoder.reset();
                                break;
                            }
                            response.zeroize();
                        }
                        Ok(None) => {}
                        Err(_) => {
                            quarantined = true;
                            handler.disconnected();
                            let _ = send(&mut sender, b"ERR INVALID_FRAME", sessions, epoch).await;
                            break;
                        }
                    }
                }
            }
            Either3::Second(Err(_)) => {
                decoder.reset();
                handler.disconnected();
                response.zeroize();
                receiver.wait_connection().await;
            }
            _ => {}
        }
        packet.zeroize();
    }
}
