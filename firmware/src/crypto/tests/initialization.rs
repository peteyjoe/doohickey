//! Actual coordinator/codec/crypto, memory-backed persistence and injected power
//! failures. No hardware OTP/flash access; test secrets are deterministic fixtures.
#![allow(dead_code)]
#[path = "../../init/mod.rs"]
mod init;
use doohickey_crypto::secrets::{MasterKey, SecretBox};
use init::presence::{Confirmation, PresenceGate};
use init::records::{COMPLETION_KEY, JOURNAL_KEY, STATE_KEY, Settings};
use init::{Backend, Coordinator, Error, Partition, Reason, RootStatus, State};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = core::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => panic!("mock I/O must complete immediately"),
    }
}
fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}
fn confirmation() -> Confirmation {
    let mut gate = PresenceGate::new(0);
    for (pressed, now) in [
        (false, 0),
        (false, 30),
        (true, 40),
        (true, 3040),
        (false, 3050),
    ] {
        assert!(gate.observe(pressed, now).is_none());
    }
    gate.observe(false, 3080).unwrap()
}
struct Mock {
    records: BTreeMap<u32, Vec<u8>>,
    version: Option<&'static str>,
    running: &'static str,
    root: Option<[u8; 32]>,
    sealed: bool,
    broken_root: bool,
    allow_root: bool,
    root_writes: usize,
    writes: usize,
    fail_at: Option<usize>,
    fail_after: bool,
    read_error: Option<Error>,
    fail_reads_at: Option<usize>,
    now: u64,
    flash_size: u32,
}
impl Default for Mock {
    fn default() -> Self {
        Self {
            records: BTreeMap::new(),
            version: None,
            running: "0.1.0",
            root: None,
            sealed: false,
            broken_root: false,
            allow_root: true,
            root_writes: 0,
            writes: 0,
            fail_at: None,
            fail_after: false,
            read_error: None,
            fail_reads_at: None,
            now: 3080,
            flash_size: 4 * 1024 * 1024,
        }
    }
}
impl Mock {
    fn before(&mut self) -> Result<(), Error> {
        if self.fail_at == Some(self.writes) && !self.fail_after {
            return Err(Error::StorageUnavailable);
        }
        Ok(())
    }
    fn after(&mut self) -> Result<(), Error> {
        let fail = self.fail_at == Some(self.writes) && self.fail_after;
        self.writes += 1;
        if fail {
            Err(Error::StorageUnavailable)
        } else {
            Ok(())
        }
    }
}
impl Backend for Mock {
    fn geometry(&self) -> init::lifecycle::Geometry {
        init::lifecycle::Geometry {
            storage_start: 0x300000,
            flash_size: self.flash_size,
        }
    }
    fn firmware_version(&self) -> &str {
        self.running
    }
    async fn clear_application(&mut self) -> Result<(), Error> {
        self.before()?;
        self.records.retain(|k, _| {
            (0xffff_fe00..=0xffff_fe04).contains(k) || (0xffff_ff00..=0xffff_ff02).contains(k)
        });
        self.after()
    }
    async fn remove(&mut self, key: u32) -> Result<(), Error> {
        self.before()?;
        self.records.remove(&key);
        self.after()
    }
    async fn update_metadata_version(&mut self) -> Result<(), Error> {
        if self.version == Some(self.running) {
            return Ok(());
        }
        self.before()?;
        self.version = Some(self.running);
        self.after()
    }
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn can_program_root(&self) -> bool {
        self.allow_root
    }
    async fn partition(&mut self) -> Result<Partition, Error> {
        if self.fail_reads_at == Some(self.writes) {
            return Err(Error::StorageUnavailable);
        }
        if let Some(error) = self.read_error {
            return Err(error);
        }
        match self.version {
            None if self.records.is_empty() => Ok(Partition::Erased),
            None => Err(Error::MissingMetadata),
            Some(version) => Ok(match init::lifecycle::upgrade(version, self.running) {
                init::lifecycle::Upgrade::Current => Partition::Compatible,
                init::lifecycle::Upgrade::Migrate => Partition::Migrate,
                init::lifecycle::Upgrade::DowngradeBlocked => Partition::DowngradeBlocked,
                init::lifecycle::Upgrade::Unsupported => Partition::DifferentVersion,
            }),
        }
    }
    async fn initialize_metadata(&mut self) -> Result<(), Error> {
        if self.version.is_some() {
            return Ok(());
        }
        self.before()?;
        self.version = Some(self.running);
        self.after()
    }
    async fn only_setup_data(&mut self) -> Result<bool, Error> {
        Ok(self
            .records
            .keys()
            .all(|k| (0xffff_fe00..=0xffff_fe04).contains(k)))
    }
    async fn read(&mut self, key: u32, output: &mut [u8]) -> Result<Option<usize>, Error> {
        if self.fail_reads_at == Some(self.writes) {
            return Err(Error::StorageUnavailable);
        }
        if let Some(error) = self.read_error {
            return Err(error);
        }
        let Some(value) = self.records.get(&key) else {
            return Ok(None);
        };
        if value.len() > output.len() {
            return Err(Error::InvalidInitialization);
        }
        output[..value.len()].copy_from_slice(value);
        Ok(Some(value.len()))
    }
    async fn store(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        assert!((0xffff_fe00..=0xffff_fe04).contains(&key));
        self.before()?;
        self.records.insert(key, value.to_vec());
        self.after()
    }
    async fn root_status(&mut self) -> Result<RootStatus, Error> {
        if self.broken_root {
            return Err(Error::IncompleteProvisioning);
        }
        Ok(match self.root {
            None => RootStatus::Blank,
            Some(_) if self.sealed => RootStatus::Sealed,
            _ => RootStatus::Unsealed,
        })
    }
    async fn load_root(&mut self) -> Result<MasterKey, Error> {
        if self.fail_reads_at == Some(self.writes) {
            return Err(Error::OtpUnavailable);
        }
        if !self.sealed {
            return Err(Error::OtpUnavailable);
        }
        Ok(MasterKey::from_bytes(Zeroizing::new(
            self.root.ok_or(Error::InvalidMasterKey)?,
        )))
    }
    async fn provision_root(&mut self, key: &MasterKey) -> Result<(), Error> {
        assert!(self.root.is_none(), "root overwrite attempt");
        if !self.allow_root {
            return Err(Error::ProvisioningDisabled);
        }
        self.before()?;
        self.root = Some(*key.provisioning_bytes());
        self.root_writes += 1;
        self.after()
    }
    async fn seal_root(&mut self) -> Result<(), Error> {
        if !self.allow_root {
            return Err(Error::ProvisioningDisabled);
        }
        assert!(self.root.is_some());
        self.before()?;
        self.sealed = true;
        self.after()
    }
}
fn initialized() -> Coordinator<Mock> {
    let mut c = Coordinator::new(Mock::default());
    assert_eq!(
        ready(c.initialize(confirmation(), &mut rng(1)))
            .unwrap()
            .state,
        State::Ready
    );
    c
}

#[test]
fn startup_never_initializes_without_confirmation_and_completed_setup_has_no_rewrites() {
    let mut c = Coordinator::new(Mock::default());
    assert_eq!(c.report().state, State::NotChecked);
    assert_eq!(ready(c.inspect()).state, State::SetupRequired);
    assert!(c.initialized().is_none());
    let b = c.into_backend();
    assert_eq!(b.writes, 0);
    assert!(b.root.is_none());
    let mut c = Coordinator::new(b);
    ready(c.initialize(confirmation(), &mut rng(1))).unwrap();
    assert_eq!(c.initialized().unwrap().settings(), Settings::default());
    let b = c.into_backend();
    assert_eq!(b.root_writes, 1);
    assert_eq!(b.writes, 6);
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).state, State::Ready);
    assert_eq!(
        ready(c.initialize(confirmation(), &mut rng(2))),
        Err(Error::SetupNotAllowed)
    );
    assert_eq!(c.into_backend().writes, 6);
}

#[test]
fn reboot_and_compatible_firmware_update_preserve_keys_settings_and_encrypted_marker() {
    let c = initialized();
    let original = *c
        .initialized()
        .unwrap()
        .credential_key()
        .provisioning_bytes();
    let cipher = SecretBox::from_master_key(c.initialized().unwrap().credential_key());
    let mut marker = [0; 128];
    let n = cipher
        .seal(
            &mut rng(5),
            b"persistence probe",
            b"same stored credential",
            &mut marker,
        )
        .unwrap();
    let mut b = c.into_backend();
    let root = b.root;
    let writes = b.writes;
    b.running = "0.2.0";
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).state, State::MigrationRequired);
    ready(c.upgrade(&mut rng(6))).unwrap();
    assert_eq!(
        c.initialized()
            .unwrap()
            .credential_key()
            .provisioning_bytes(),
        &original
    );
    assert_eq!(c.initialized().unwrap().settings(), Settings::default());
    let mut output = [0; 64];
    let len = SecretBox::from_master_key(c.initialized().unwrap().credential_key())
        .open(b"persistence probe", &marker[..n], &mut output)
        .unwrap();
    assert_eq!(&output[..len], b"same stored credential");
    let b = c.into_backend();
    assert_eq!(b.root, root);
    assert_eq!(b.version, Some("0.2.0"));
    assert!(b.writes > writes);
}

#[test]
fn every_durable_write_boundary_recovers_without_root_replacement() {
    // Metadata, journal, root record, seal, state, authenticated final commit. Simulate
    // loss before the operation and an acknowledgement lost after it persisted.
    for fail_after in [false, true] {
        for fail_at in 0..6 {
            let b = Mock {
                fail_at: Some(fail_at),
                fail_after,
                ..Mock::default()
            };
            let mut c = Coordinator::new(b);
            assert!(ready(c.initialize(confirmation(), &mut rng(2))).is_err());
            let mut b = c.into_backend();
            let persisted_root = b.root;
            let journal = b.records.get(&JOURNAL_KEY).cloned();
            let prepared_state = b.records.get(&STATE_KEY).cloned();
            b.fail_at = None;
            let mut c = Coordinator::new(b);
            let state = ready(c.inspect()).state;
            if state != State::Ready {
                assert!(
                    c.report().permits_setup(),
                    "{fail_at}/{fail_after}: {:?}",
                    c.report()
                );
                ready(c.initialize(confirmation(), &mut rng(3))).unwrap();
            }
            assert_eq!(c.report().state, State::Ready);
            let b = c.into_backend();
            assert_eq!(b.root_writes, 1);
            if let Some(root) = persisted_root {
                assert_eq!(b.root, Some(root));
            }
            if let Some(journal) = journal {
                assert_eq!(b.records.get(&JOURNAL_KEY), Some(&journal));
            }
            if let Some(state) = prepared_state {
                assert_eq!(b.records.get(&STATE_KEY), Some(&state));
            }
        }
    }
}

#[test]
fn sealed_root_and_erased_storage_requires_confirmation_and_reuses_the_root() {
    let mut b = initialized().into_backend();
    let root = b.root;
    b.records.clear();
    b.version = None;
    b.allow_root = false; // a normal read-only OTP build may initialize flash with its existing root
    let count = b.root_writes;
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).reason, Reason::StorageErased);
    ready(c.initialize(confirmation(), &mut rng(10))).unwrap();
    let b = c.into_backend();
    assert_eq!(b.root, root);
    assert_eq!(b.root_writes, count);
}

#[test]
fn completion_witness_blocks_lost_state_but_missing_completion_reuses_prepared_key() {
    let mut b = initialized().into_backend();
    b.records.remove(&STATE_KEY);
    let writes = b.writes;
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).state, State::RecoveryRequired);
    assert!(ready(c.initialize(confirmation(), &mut rng(20))).is_err());
    assert_eq!(c.into_backend().writes, writes);

    let c = initialized();
    let key = *c
        .initialized()
        .unwrap()
        .credential_key()
        .provisioning_bytes();
    let mut b = c.into_backend();
    let prepared = b.records[&STATE_KEY].clone();
    let writes = b.writes;
    b.records.remove(&COMPLETION_KEY);
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).state, State::InitializationRequired);
    assert!(c.initialized().is_none());
    ready(c.initialize(confirmation(), &mut rng(20))).unwrap();
    assert_eq!(
        c.initialized()
            .unwrap()
            .credential_key()
            .provisioning_bytes(),
        &key
    );
    let b = c.into_backend();
    assert_eq!(b.writes, writes + 1);
    assert_eq!(b.records[&STATE_KEY], prepared);
    assert_eq!(b.root_writes, 1);
}

#[test]
fn valid_commit_from_another_generation_under_the_same_root_is_rejected() {
    let mut a = initialized().into_backend();
    let b = Mock {
        root: a.root,
        sealed: true,
        ..Mock::default()
    };
    let mut c = Coordinator::new(b);
    ready(c.initialize(confirmation(), &mut rng(90))).unwrap();
    let b = c.into_backend();
    a.records
        .insert(COMPLETION_KEY, b.records[&COMPLETION_KEY].clone());
    let mut c = Coordinator::new(a);
    assert_eq!(ready(c.inspect()).reason, Reason::InvalidInitialization);
    assert!(c.initialized().is_none());
}

#[test]
fn partial_or_unsealed_root_without_our_journal_never_gets_overwritten() {
    for broken_root in [false, true] {
        let b = Mock {
            root: Some([42; 32]),
            broken_root,
            ..Mock::default()
        };
        let mut c = Coordinator::new(b);
        assert_eq!(ready(c.inspect()).state, State::RecoveryRequired);
        assert!(ready(c.initialize(confirmation(), &mut rng(5))).is_err());
        assert_eq!(c.into_backend().writes, 0);
    }
}

#[test]
fn unknown_data_missing_root_invalid_metadata_and_read_failures_never_offer_setup() {
    for root in [None, Some([42; 32])] {
        let mut b = Mock {
            version: Some("0.1.0"),
            root,
            sealed: root.is_some(),
            ..Mock::default()
        };
        b.records.insert(123, b"existing application data".to_vec());
        let mut c = Coordinator::new(b);
        assert_eq!(ready(c.inspect()).state, State::RecoveryRequired);
        assert!(ready(c.initialize(confirmation(), &mut rng(5))).is_err());
        assert_eq!(c.into_backend().writes, 0);
    }
    for error in [
        Error::MissingMetadata,
        Error::InvalidMetadata,
        Error::StorageUnavailable,
        Error::OtpUnavailable,
    ] {
        let mut c = Coordinator::new(Mock {
            read_error: Some(error),
            ..Mock::default()
        });
        assert_eq!(ready(c.inspect()).state, State::RecoveryRequired);
        assert!(ready(c.initialize(confirmation(), &mut rng(5))).is_err());
        assert_eq!(c.into_backend().writes, 0);
    }
}

#[test]
fn missing_root_or_journal_on_completed_state_never_regenerates_secrets() {
    for missing_root in [false, true] {
        let mut b = initialized().into_backend();
        let writes = b.writes;
        if missing_root {
            b.root = None;
            b.sealed = false;
        } else {
            b.records.remove(&JOURNAL_KEY);
        }
        let mut c = Coordinator::new(b);
        assert_eq!(ready(c.inspect()).state, State::RecoveryRequired);
        assert!(ready(c.initialize(confirmation(), &mut rng(5))).is_err());
        assert!(c.initialized().is_none());
        assert_eq!(c.into_backend().writes, writes);
    }
}

#[test]
fn every_tampered_byte_or_truncated_record_fails_closed() {
    for key in [JOURNAL_KEY, STATE_KEY, COMPLETION_KEY] {
        let baseline = initialized().into_backend().records[&key].clone();
        for i in 0..baseline.len() {
            let mut b = initialized().into_backend();
            let writes = b.writes;
            b.records.get_mut(&key).unwrap()[i] ^= 1;
            let mut c = Coordinator::new(b);
            assert_eq!(
                ready(c.inspect()).state,
                State::RecoveryRequired,
                "key {key} byte {i}"
            );
            assert!(c.initialized().is_none());
            assert!(ready(c.initialize(confirmation(), &mut rng(5))).is_err());
            assert_eq!(c.into_backend().writes, writes);
        }
        for len in 0..baseline.len() {
            let mut b = initialized().into_backend();
            b.records.get_mut(&key).unwrap().truncate(len);
            let mut c = Coordinator::new(b);
            assert_eq!(ready(c.inspect()).state, State::RecoveryRequired);
        }
    }
}

#[test]
fn wrong_root_or_swapped_setup_records_cannot_authenticate() {
    let mut a = initialized().into_backend();
    let mut c = Coordinator::new(Mock::default());
    ready(c.initialize(confirmation(), &mut rng(9))).unwrap();
    let b = c.into_backend();
    a.records.insert(STATE_KEY, b.records[&STATE_KEY].clone());
    let mut c = Coordinator::new(a);
    assert_eq!(ready(c.inspect()).reason, Reason::AuthenticationFailed);
    let mut b = initialized().into_backend();
    b.root = Some([77; 32]);
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).reason, Reason::AuthenticationFailed);
}

#[test]
fn authenticated_but_invalid_settings_or_completion_are_rejected() {
    const CONTEXT: &[u8] = b"DOOHICKEY initialization state v1/fffffe01";
    for offset in [0, 8, 24, 56, 92] {
        let mut b = initialized().into_backend();
        let root = MasterKey::from_bytes(Zeroizing::new(b.root.unwrap()));
        let cipher = SecretBox::from_master_key(&root);
        let mut plaintext = [0; 100];
        let n = cipher
            .open(CONTEXT, &b.records[&STATE_KEY], &mut plaintext)
            .unwrap();
        if offset == 56 {
            plaintext[56..60].fill(0);
        } else {
            plaintext[offset] ^= 1;
        }
        let mut envelope = [0; 141];
        let len = cipher
            .seal(&mut rng(10), CONTEXT, &plaintext[..n], &mut envelope)
            .unwrap();
        b.records.insert(STATE_KEY, envelope[..len].to_vec());
        let mut c = Coordinator::new(b);
        assert_eq!(ready(c.inspect()).reason, Reason::InvalidInitialization);
    }
}

#[test]
fn newer_unknown_metadata_is_preserved_and_no_migration_is_invented() {
    let mut b = initialized().into_backend();
    b.version = Some("999.0.0");
    let writes = b.writes;
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).reason, Reason::DowngradeBlocked);
    assert!(ready(c.initialize(confirmation(), &mut rng(5))).is_err());
    let b = c.into_backend();
    assert_eq!(b.writes, writes);
    assert_eq!(b.version, Some("999.0.0"));
    assert!(!init::storage_version_supported("0.1.1", "0.1.0"));
}

#[test]
fn disabled_provisioning_and_stale_confirmation_do_not_mutate_storage() {
    let mut c = Coordinator::new(Mock {
        allow_root: false,
        ..Mock::default()
    });
    assert_eq!(ready(c.inspect()).reason, Reason::ProvisioningDisabled);
    assert!(ready(c.initialize(confirmation(), &mut rng(5))).is_err());
    assert_eq!(c.into_backend().writes, 0);
    for now in [0, 13_081] {
        let mut c = Coordinator::new(Mock {
            now,
            ..Mock::default()
        });
        assert_eq!(
            ready(c.initialize(confirmation(), &mut rng(5))),
            Err(Error::ConfirmationExpired)
        );
        assert_eq!(c.into_backend().writes, 0);
    }
}

struct FailedEntropy;
impl RngCore for FailedEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible entropy used")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible entropy used")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible entropy used")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        Err(rand_core::Error::from(
            std::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
        ))
    }
}
impl CryptoRng for FailedEntropy {}

struct LimitedEntropy {
    inner: ChaCha20Rng,
    calls_left: usize,
}
impl RngCore for LimitedEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible entropy used")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible entropy used")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible entropy used")
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), rand_core::Error> {
        if self.calls_left == 0 {
            return FailedEntropy.try_fill_bytes(output);
        }
        self.calls_left -= 1;
        self.inner.try_fill_bytes(output)
    }
}
impl CryptoRng for LimitedEntropy {}

#[test]
fn entropy_failure_at_each_generation_and_nonce_step_is_resumable_without_key_replacement() {
    for calls_left in 0..5 {
        let mut c = Coordinator::new(Mock::default());
        let mut limited = LimitedEntropy {
            inner: rng(60),
            calls_left,
        };
        assert_eq!(
            ready(c.initialize(confirmation(), &mut limited)),
            Err(Error::EntropyUnavailable)
        );
        let b = c.into_backend();
        let persisted_root = b.root;
        let persisted_state = b.records.get(&STATE_KEY).cloned();
        let mut c = Coordinator::new(b);
        ready(c.initialize(confirmation(), &mut rng(61))).unwrap();
        let b = c.into_backend();
        assert_eq!(b.root_writes, 1);
        if let Some(root) = persisted_root {
            assert_eq!(b.root, Some(root));
        }
        if let Some(state) = persisted_state {
            assert_eq!(b.records.get(&STATE_KEY), Some(&state));
        }
    }
}

#[test]
fn failed_readback_never_leaves_unverified_ready_state_and_reboot_can_resume() {
    for write in [1, 2, 4, 5, 6] {
        let b = Mock {
            fail_reads_at: Some(write),
            ..Mock::default()
        };
        let mut c = Coordinator::new(b);
        assert!(ready(c.initialize(confirmation(), &mut rng(70))).is_err());
        assert_ne!(c.report().state, State::Ready);
        assert!(c.initialized().is_none());
        let mut b = c.into_backend();
        let persisted_root = b.root;
        b.fail_reads_at = None;
        let mut c = Coordinator::new(b);
        if ready(c.inspect()).state != State::Ready {
            ready(c.initialize(confirmation(), &mut rng(71))).unwrap();
        }
        assert_eq!(c.report().state, State::Ready);
        let b = c.into_backend();
        assert_eq!(b.root_writes, 1);
        if let Some(root) = persisted_root {
            assert_eq!(b.root, Some(root));
        }
    }
}
#[test]
fn entropy_failure_does_not_create_a_root_or_ready_record_and_aead_clears_output() {
    let mut c = Coordinator::new(Mock::default());
    assert_eq!(
        ready(c.initialize(confirmation(), &mut FailedEntropy)),
        Err(Error::EntropyUnavailable)
    );
    let b = c.into_backend();
    assert!(b.root.is_none());
    assert!(!b.records.contains_key(&STATE_KEY));
    let root = MasterKey::from_bytes(Zeroizing::new([42; 32]));
    let mut output = [0xa5; 80];
    assert_eq!(
        SecretBox::from_master_key(&root).seal(
            &mut FailedEntropy,
            b"context",
            b"secret",
            &mut output
        ),
        Err(doohickey_crypto::Error::EntropyUnavailable)
    );
    assert_eq!(&output[..47], &[0; 47]);
}

#[test]
fn presence_requires_fresh_continuous_hold_release_and_is_single_use() {
    let mut g = PresenceGate::new(0);
    assert!(g.observe(true, 0).is_none());
    assert!(g.observe(true, 4000).is_none());
    assert!(g.observe(false, 4010).is_none());
    assert!(g.observe(false, 4040).is_none());
    assert!(g.observe(true, 4050).is_none());
    assert!(g.observe(false, 5000).is_none()); // too short
    assert!(g.observe(true, 5010).is_none());
    assert!(g.observe(true, 8010).is_none());
    assert!(g.observe(false, 8020).is_none());
    assert!(g.observe(true, 8030).is_none()); // release bounce
    assert!(g.observe(false, 8040).is_none());
    assert!(g.observe(false, 8070).is_some());
    assert!(g.observe(false, 8100).is_none());
    assert!(g.observe(true, 8200).is_none());
    let mut g = PresenceGate::new(0);
    assert!(g.observe(false, 30_001).is_none());
    assert!(g.expired(30_001));
    let mut g = PresenceGate::new(100);
    assert!(g.observe(false, 90).is_none());
    assert!(g.observe(false, 120).is_none());
}

#[test]
fn reset_rotates_only_credential_key_and_preserves_trust_records() {
    let c = initialized();
    let old_key = *c
        .initialized()
        .unwrap()
        .credential_key()
        .provisioning_bytes();
    let mut b = c.into_backend();
    b.records.insert(0x01000001, b"credential".to_vec());
    b.records.insert(0x02000000, b"PIN".to_vec());
    b.records.insert(0xffff_ff01, b"boot trust key".to_vec());
    let root = b.root;
    let mut c = Coordinator::new(b);
    ready(c.inspect());
    ready(c.reset(confirmation(), &mut rng(81))).unwrap();
    assert_ne!(
        c.initialized()
            .unwrap()
            .credential_key()
            .provisioning_bytes(),
        &old_key
    );
    let b = c.into_backend();
    assert_eq!(b.root, root);
    assert_eq!(b.root_writes, 1);
    assert_eq!(b.records.get(&0xffff_ff01).unwrap(), b"boot trust key");
    assert!(!b.records.contains_key(&0x01000001));
    assert!(!b.records.contains_key(&0x02000000));
    assert!(!b.records.contains_key(&init::lifecycle::TRANSACTION_KEY));
}

#[test]
fn reset_and_upgrade_resume_each_interrupted_write_forward() {
    for reset in [false, true] {
        for fail_after in [false, true] {
            for cut in 0..9 {
                let c = initialized();
                let old_key = *c
                    .initialized()
                    .unwrap()
                    .credential_key()
                    .provisioning_bytes();
                let mut b = c.into_backend();
                b.records.insert(0x01000001, b"credential marker".to_vec());
                let root = b.root;
                b.running = "0.2.0";
                b.fail_at = Some(b.writes + cut);
                b.fail_after = fail_after;
                let mut c = Coordinator::new(b);
                ready(c.inspect());
                if reset {
                    let _ = ready(c.reset(confirmation(), &mut rng(82)));
                } else {
                    let _ = ready(c.upgrade(&mut rng(82)));
                }
                let mut b = c.into_backend();
                b.fail_at = None;
                let pending = b.records.contains_key(&init::lifecycle::TRANSACTION_KEY);
                let mut c = Coordinator::new(b);
                let report = ready(c.inspect());
                if pending {
                    assert!(
                        matches!(
                            report.reason,
                            Reason::ResetInterrupted | Reason::UpgradeInterrupted
                        ),
                        "{reset}/{fail_after}/{cut}: {report:?}"
                    );
                    assert!(c.application_parts().is_none());
                    ready(c.resume_transition(&mut rng(83))).unwrap();
                } else if report.state != State::Ready {
                    if reset {
                        ready(c.reset(confirmation(), &mut rng(83))).unwrap();
                    } else {
                        ready(c.upgrade(&mut rng(83))).unwrap();
                    }
                }
                assert_eq!(c.report().state, State::Ready);
                let key = c
                    .initialized()
                    .unwrap()
                    .credential_key()
                    .provisioning_bytes();
                if reset {
                    assert_ne!(key, &old_key);
                } else {
                    assert_eq!(key, &old_key);
                }
                let b = c.into_backend();
                assert_eq!(b.root, root);
                assert_eq!(b.root_writes, 1);
                assert_eq!(b.records.contains_key(&0x01000001), !reset);
            }
        }
    }
}

#[test]
fn version_geometry_and_confirmation_checks_fail_closed() {
    use init::lifecycle::{Upgrade, upgrade};
    assert_eq!(upgrade("0.1.0", "0.2.0"), Upgrade::Migrate);
    assert_eq!(upgrade("0.2.0", "0.1.0"), Upgrade::DowngradeBlocked);
    for value in ["0.1.1", "01.0.0", "0.2.0-alpha", "garbage"] {
        assert_eq!(upgrade(value, "0.2.0"), Upgrade::Unsupported);
    }
    let c = initialized();
    // The backend clock is deliberately earlier than the confirmation.
    let mut b = c.into_backend();
    let writes = b.writes;
    b.now = 1;
    let mut c = Coordinator::new(b);
    assert_eq!(
        ready(c.reset(confirmation(), &mut rng(84))),
        Err(Error::ConfirmationExpired)
    );
    assert_eq!(c.into_backend().writes, writes);
    let mut b = initialized().into_backend();
    b.running = "0.2.0";
    let mut c = Coordinator::new(b);
    ready(c.upgrade(&mut rng(85))).unwrap();
    let mut b = c.into_backend();
    let writes = b.writes;
    b.flash_size = 16 * 1024 * 1024;
    let mut c = Coordinator::new(b);
    assert_eq!(ready(c.inspect()).reason, Reason::GeometryMismatch);
    assert!(ready(c.reset(confirmation(), &mut rng(86))).is_err());
    assert_eq!(c.into_backend().writes, writes);
}
