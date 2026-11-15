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
    fn now_ms(&self) -> u64 {
        Instant::now().as_millis()
    }
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

async fn confirm_reset(
    button: &Input<'_>,
    led: &mut Output<'_>,
    exchange: &Exchange,
) -> ctap::Result<init::presence::Confirmation> {
    exchange.set_presence(true);
    defmt::warn!("Reset deletes all credentials and PIN: release GPIO 23, hold 3 seconds, release");
    let mut gate = init::presence::PresenceGate::new(Instant::now().as_millis());
    let result = loop {
        let now = Instant::now().as_millis();
        if exchange.cancelled() {
            break Err(Status::KeepaliveCancel);
        }
        if gate.expired(now) {
            break Err(Status::UserActionTimeout);
        }
        if (now / 100).is_multiple_of(2) {
            led.set_high();
        } else {
            led.set_low();
        }
        if let Some(confirmation) = gate.observe(button.is_low(), now) {
            break Ok(confirmation);
        }
        Timer::after_millis(10).await;
    };
    led.set_low();
    exchange.set_presence(false);
    result
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
    let mut session = ctap::pin_session::Session::default();
    let mut epoch = exchange.epoch.get();
    let mut retry_entropy_at = 0;
    let mut retry_transition_at = 0;
    let mut setup_gate = init::presence::PresenceGate::new(Instant::now().as_millis());
    if report.get().permits_setup() {
        defmt::info!("Setup: release GPIO 23, hold for 3 seconds, then release to confirm");
    }
    if report.get().state == State::RecoveryRequired {
        defmt::warn!(
            "Recovery: a fresh 3-second GPIO 23 hold/release requests destructive reset; OTP is retained"
        );
    }
    let mut input = Zeroizing::new([0; ctap::exchange::CAPACITY]);
    let mut output = Zeroizing::new([0; ctap::exchange::CAPACITY - 1]);
    loop {
        let now = Instant::now().as_millis();
        if epoch != exchange.epoch.get() {
            session.invalidate();
            epoch = exchange.epoch.get();
        }
        session.expire(now);
        // A committed pending transaction already contains authenticated local
        // authorization. Never expose CTAP between its individual writes.
        if matches!(
            report.get().reason,
            Reason::ResetInterrupted | Reason::UpgradeInterrupted | Reason::FirmwareVersionMismatch
        ) && now >= retry_transition_at
        {
            exchange.ready.set(false);
            session = ctap::pin_session::Session::default();
            rng = None;
            match entropy.seed_rng().await {
                Ok(mut seeded) => {
                    let _ = coordinator.upgrade(&mut seeded).await;
                    report.set(coordinator.report());
                }
                Err(_) => defmt::warn!("Lifecycle waiting for hardware entropy"),
            }
            retry_transition_at = Instant::now().as_millis().saturating_add(5000);
        }
        // Local recovery is deliberately destructive, uses the same fresh
        // long-hold gate, and never repairs/replaces an OTP trust root.
        if report.get().state == State::RecoveryRequired {
            if setup_gate.expired(now) {
                setup_gate = init::presence::PresenceGate::new(now);
            }
            if let Some(confirmation) = setup_gate.observe(button.is_low(), now) {
                exchange.ready.set(false);
                session = ctap::pin_session::Session::default();
                rng = None;
                if let Ok(mut seeded) = entropy.seed_rng().await {
                    let _ = coordinator.reset(confirmation, &mut seeded).await;
                    report.set(coordinator.report());
                }
                setup_gate = init::presence::PresenceGate::new(Instant::now().as_millis());
            }
        }
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
                Ok(mut seeded) => {
                    let valid =
                        if let Some((backend, initialized)) = coordinator.application_parts() {
                            let mut repository = Repository::new(
                                backend.storage(),
                                initialized.credential_key(),
                                &mut seeded,
                            );
                            match session.load(&mut repository).await {
                                Ok(_) => true,
                                Err(_) => {
                                    report.set(Report {
                                        state: State::RecoveryRequired,
                                        reason: Reason::AuthenticationFailed,
                                    });
                                    false
                                }
                            }
                        } else {
                            false
                        };
                    rng = Some(seeded);
                    exchange.ready.set(valid);
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
                Ok(Request::Reset) => {
                    if Instant::now().as_millis() > 10_000 {
                        Err(Status::NotAllowed)
                    } else {
                        session.invalidate();
                        match confirm_reset(&button, &mut led, exchange).await {
                            Err(error) => Err(error),
                            Ok(confirmation) => {
                                exchange.ready.set(false);
                                rng = None;
                                let result = match entropy.seed_rng().await {
                                    Ok(mut seeded) if !exchange.cancelled() => coordinator
                                        .reset(confirmation, &mut seeded)
                                        .await
                                        .map(|_| 0)
                                        .map_err(|_| Status::OperationDenied),
                                    Ok(_) => Err(Status::KeepaliveCancel),
                                    Err(_) => Err(Status::Other),
                                };
                                report.set(coordinator.report());
                                if result.is_ok() {
                                    session = ctap::pin_session::Session::default();
                                }
                                result
                            }
                        }
                    }
                }
                Ok(Request::GetInfo) if !exchange.ready.get() => {
                    ctap::info::encode(&mut output[..])
                }
                Ok(_) if !exchange.ready.get() => Err(Status::OperationDenied),
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
                        ctap::authenticator::execute_with_session(
                            &mut repository,
                            request,
                            &mut presence,
                            &mut output[..],
                            &mut session,
                            Instant::now().as_millis(),
                        )
                        .await
                    }
                    _ => Err(Status::OperationDenied),
                },
            };
            if epoch != exchange.epoch.get() {
                session.invalidate();
                epoch = exchange.epoch.get();
            }
            if result.is_err() {
                session.clear_assertions();
                session.clear_management();
            }
            exchange.complete(result, &output[..]);
            // Input contains account identifiers/encrypted PIN fields. Never log.
            use zeroize::Zeroize;
            input.zeroize();
            output.zeroize();
        }
        Timer::after_millis(10).await;
    }
}
