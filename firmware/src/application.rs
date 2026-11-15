//! Core-0 single owner of initialization, credentials, entropy and physical UP.
//! USB stays live in the joined future; storage operations are never cancelled.
use crate::{
    ctap::{self, Request, Status, authenticator::Presence, codec::Scratch, exchange::Exchange},
    init::{self, Coordinator, DeviceBackend, Reason, Report, State},
    storage::credentials::Repository,
};
use core::cell::Cell;
use doohickey_crypto::rng::HardwareEntropy;
use embassy_rp::{
    Peri,
    gpio::{Input, Output},
    peripherals::TRNG,
};
use embassy_time::{Instant, Timer};
use zeroize::Zeroizing;

struct ButtonPresence<'a, 'd> {
    button: &'a Input<'d>,
    led: &'a mut Output<'d>,
    exchange: &'a Exchange,
    timeout: u32,
}
impl Presence for ButtonPresence<'_, '_> {
    async fn confirm(&mut self) -> ctap::Result<()> {
        self.exchange.set_presence(true);
        defmt::info!("CTAP: press and release GPIO 23 to confirm");
        let mut gate = ctap::presence::Gate::new(Instant::now().as_millis(), self.timeout);
        let result = loop {
            if self.cancelled() {
                break Err(Status::KeepaliveCancel);
            }
            let now = Instant::now().as_millis();
            if (now / 150).is_multiple_of(2) {
                self.led.set_high();
            } else {
                self.led.set_low();
            }
            match gate.observe(self.button.is_low(), now) {
                Ok(true) => break Ok(()),
                Err(error) => break Err(error),
                Ok(false) => {}
            }
            Timer::after_millis(10).await;
        };
        self.led.set_low();
        self.exchange.set_presence(false);
        result
    }
    fn cancelled(&self) -> bool {
        self.exchange.cancelled()
    }
}

pub async fn run(
    coordinator: &mut Coordinator<DeviceBackend<'_>>,
    button: Input<'static>,
    mut led: Output<'static>,
    trng: Peri<'static, TRNG>,
    report: &Cell<Report>,
    exchange: &Exchange,
) -> ! {
    let mut entropy = HardwareEntropy::new(trng);
    let mut rng = None;
    let mut retry_entropy_at = 0;
    let mut setup_gate = init::presence::PresenceGate::new(Instant::now().as_millis());
    if report.get().permits_setup() {
        defmt::info!("Setup: release GPIO 23, hold for 3 seconds, then release to confirm");
    }
    let mut input = Zeroizing::new([0; ctap::exchange::CAPACITY]);
    let mut output = Zeroizing::new([0; ctap::exchange::CAPACITY - 1]);
    loop {
        let now = Instant::now().as_millis();
        if report.get().permits_setup() {
            if setup_gate.expired(now) {
                setup_gate = init::presence::PresenceGate::new(now);
            }
            if let Some(confirmation) = setup_gate.observe(button.is_low(), now) {
                report.set(Report {
                    state: State::Initializing,
                    reason: Reason::None,
                });
                match entropy.seed_rng().await {
                    Ok(mut setup_rng) => {
                        let _ = coordinator.initialize(confirmation, &mut setup_rng).await;
                        report.set(coordinator.report());
                        defmt::info!(
                            "Setup: {} ({})",
                            report.get().state.as_str(),
                            report.get().reason.as_str()
                        );
                    }
                    Err(_) => {
                        let mut status = coordinator.report();
                        status.reason = Reason::EntropyUnavailable;
                        report.set(status);
                    }
                }
                setup_gate = init::presence::PresenceGate::new(Instant::now().as_millis());
            }
        }
        if report.get().state == State::Ready && rng.is_none() && now >= retry_entropy_at {
            match entropy.seed_rng().await {
                Ok(seeded) => {
                    rng = Some(seeded);
                    exchange.ready.set(true);
                    defmt::info!("CTAP ES256 allow-list profile ready");
                }
                Err(_) => {
                    retry_entropy_at = Instant::now().as_millis().saturating_add(5000);
                    defmt::warn!("CTAP unavailable: hardware entropy failed");
                }
            }
        }
        if let Some(len) = exchange.take(&mut input) {
            let mut scratch = Scratch::new();
            let result = match ctap::codec::decode(&input[..len], &mut scratch) {
                Err(error) => Err(error),
                Ok(_) if exchange.cancelled() => Err(Status::KeepaliveCancel),
                Ok(Request::GetInfo) => {
                    if exchange.ready.get() {
                        ctap::info::encode_for_authenticator(&mut output[..])
                    } else {
                        ctap::info::encode(&mut output[..])
                    }
                }
                Ok(request) => match (coordinator.application_parts(), rng.as_mut()) {
                    (Some((backend, initialized)), Some(rng)) => {
                        let mut repository =
                            Repository::new(backend.storage(), initialized.credential_key(), rng);
                        let mut presence = ButtonPresence {
                            button: &button,
                            led: &mut led,
                            exchange,
                            timeout: initialized.settings().user_presence_timeout_ms,
                        };
                        ctap::authenticator::execute(
                            &mut repository,
                            request,
                            &mut presence,
                            &mut output[..],
                        )
                        .await
                    }
                    _ => Err(Status::OperationDenied),
                },
            };
            exchange.complete(result, &output[..]);
            // Input contains account identifiers/encrypted PIN fields. Never log.
            use zeroize::Zeroize;
            input.zeroize();
            output.zeroize();
        }
        Timer::after_millis(10).await;
    }
}
