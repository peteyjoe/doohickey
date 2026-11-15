//! Embassy HID I/O adapter. Receive and backend polling stay live concurrently.
use super::{
    SessionState,
    ctaphid::{Backend, Engine, Reply},
    session::Interface,
};
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embassy_usb::{
    class::hid::{HidReaderWriter, HidWriter},
    driver::Driver,
};

async fn send<'d, D: Driver<'d>>(
    writer: &mut HidWriter<'d, D, 64>,
    reply: Reply<'_>,
    sessions: &SessionState,
    epoch: u32,
) -> Result<(), ()> {
    for report in reply.reports().map_err(|_| ())? {
        if epoch != sessions.epoch() || !sessions.configured() {
            return Err(());
        }
        with_timeout(
            Duration::from_secs(2),
            sessions.guard_write(Interface::Hid, epoch, writer.write(&report)),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    }
    Ok(())
}

pub async fn run<'d, D: Driver<'d>, B: Backend>(
    class: HidReaderWriter<'d, D, 64, 64>,
    sessions: &SessionState,
    mut engine: Engine<B>,
) -> ! {
    let (mut reader, mut writer) = class.split();
    let mut epoch = sessions.epoch();
    let mut report = [0; 64];
    loop {
        if epoch != sessions.epoch() {
            engine.disconnected();
            epoch = sessions.epoch();
        }
        if let Some(reply) = engine.tick(Instant::now().as_millis())
            && sessions.configured()
            && send(&mut writer, reply, sessions, epoch).await.is_err()
        {
            engine.disconnected();
        }
        match select(reader.read(&mut report), Timer::after_millis(10)).await {
            Either::First(Ok(n)) => {
                if epoch != sessions.epoch() || !sessions.configured() {
                    continue;
                }
                if let Some(reply) = engine.receive(&report[..n], Instant::now().as_millis())
                    && send(&mut writer, reply, sessions, epoch).await.is_err()
                {
                    engine.disconnected();
                }
            }
            Either::First(Err(_)) => {
                engine.disconnected();
                Timer::after_millis(10).await;
            }
            Either::Second(_) => {}
        }
    }
}
