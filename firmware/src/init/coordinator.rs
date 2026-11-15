use super::{
    Reason, Report, State,
    lifecycle::{self, Geometry, Upgrade},
    presence::Confirmation,
    records::{self, Initialized, Journal, RootMode},
};
use doohickey_crypto::ctap::sha256;
use doohickey_crypto::secrets::{MasterKey, SecretBox};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    StorageUnavailable,
    MissingMetadata,
    InvalidMetadata,
    OtpUnavailable,
    InvalidMasterKey,
    IncompleteProvisioning,
    ProvisioningDisabled,
    InvalidInitialization,
    AuthenticationFailed,
    EntropyUnavailable,
    ConfirmationExpired,
    SetupNotAllowed,
    VerificationFailed,
    DowngradeBlocked,
    UnsupportedVersion,
    GeometryMismatch,
}
impl Error {
    pub fn reason(self) -> Reason {
        match self {
            Self::StorageUnavailable => Reason::StorageUnavailable,
            Self::MissingMetadata => Reason::MissingMetadata,
            Self::InvalidMetadata => Reason::InvalidMetadata,
            Self::OtpUnavailable => Reason::OtpUnavailable,
            Self::InvalidMasterKey => Reason::InvalidMasterKey,
            Self::IncompleteProvisioning => Reason::IncompleteProvisioning,
            Self::ProvisioningDisabled => Reason::ProvisioningDisabled,
            Self::AuthenticationFailed => Reason::AuthenticationFailed,
            Self::EntropyUnavailable => Reason::EntropyUnavailable,
            Self::DowngradeBlocked => Reason::DowngradeBlocked,
            Self::UnsupportedVersion => Reason::UnsupportedVersion,
            Self::GeometryMismatch => Reason::GeometryMismatch,
            _ => Reason::InvalidInitialization,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Partition {
    Erased,
    Compatible,
    DifferentVersion,
    Migrate,
    DowngradeBlocked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootStatus {
    Blank,
    Unsealed,
    Sealed,
}

/// Versions whose persistent formats this firmware deliberately supports.
/// Keep 0.1.0 when adding a compatible successor; do not accept arbitrary newer
/// versions just because their semver patch/minor component looks similar.
pub fn storage_version_supported(stored: &str, running: &str) -> bool {
    matches!(
        lifecycle::upgrade(stored, running),
        Upgrade::Current | Upgrade::Migrate
    )
}

/// One owner, asynchronous I/O; operations must be awaited to completion.
/// Implementations expose only initialization records and the master-key policy,
/// not boot-key/security flags or a generic OTP write operation.
#[allow(async_fn_in_trait)] // Single-core owner; backend futures need not be Send.
pub trait Backend {
    fn firmware_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn geometry(&self) -> Geometry {
        Geometry {
            storage_start: 3 * 1024 * 1024,
            flash_size: 4 * 1024 * 1024,
        }
    }
    async fn restore_record(&mut self, _key: u32, _value: &[u8]) -> Result<(), Error> {
        Err(Error::StorageUnavailable)
    }
    async fn clear_application(&mut self) -> Result<(), Error> {
        Err(Error::StorageUnavailable)
    }
    async fn remove(&mut self, _key: u32) -> Result<(), Error> {
        Err(Error::StorageUnavailable)
    }
    async fn update_metadata_version(&mut self) -> Result<(), Error> {
        Err(Error::StorageUnavailable)
    }
    fn now_ms(&self) -> u64;
    fn can_program_root(&self) -> bool;
    async fn partition(&mut self) -> Result<Partition, Error>;
    async fn initialize_metadata(&mut self) -> Result<(), Error>;
    async fn only_setup_data(&mut self) -> Result<bool, Error>;
    async fn read(&mut self, key: u32, output: &mut [u8]) -> Result<Option<usize>, Error>;
    async fn store(&mut self, key: u32, value: &[u8]) -> Result<(), Error>;
    /// Unsealed means a COMPLETE valid record with a lock policy that can be
    /// safely sealed. Partial/corrupt records must return an error instead.
    async fn root_status(&mut self) -> Result<RootStatus, Error>;
    async fn load_root(&mut self) -> Result<MasterKey, Error>;
    async fn provision_root(&mut self, key: &MasterKey) -> Result<(), Error>;
    async fn seal_root(&mut self) -> Result<(), Error>;
}

pub struct Coordinator<B: Backend> {
    backend: B,
    report: Report,
    initialized: Option<Initialized>,
}
impl<B: Backend> Coordinator<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            report: Report::NOT_CHECKED,
            initialized: None,
        }
    }
    pub fn report(&self) -> Report {
        self.report
    }
    pub fn initialized(&self) -> Option<&Initialized> {
        self.initialized.as_ref()
    }
    /// Borrow validated application state and its single backend together.
    /// No root/key access is granted while setup/recovery/migration is pending.
    pub fn application_parts(&mut self) -> Option<(&mut B, &Initialized)> {
        if self.report.state != State::Ready {
            return None;
        }
        Some((&mut self.backend, self.initialized.as_ref()?))
    }
    pub fn into_backend(self) -> B {
        self.backend
    }

    pub async fn inspect(&mut self) -> Report {
        self.initialized = None;
        self.report = Report::NOT_CHECKED;
        self.report = match self.check().await {
            Ok(report) => report,
            Err(error) => Report {
                state: State::RecoveryRequired,
                reason: error.reason(),
            },
        };
        self.report
    }
    async fn journal(&mut self) -> Result<Option<Journal>, Error> {
        let mut bytes = [0; records::JOURNAL_SIZE];
        self.backend
            .read(records::JOURNAL_KEY, &mut bytes)
            .await?
            .map(|n| Journal::decode(&bytes[..n]))
            .transpose()
    }
    async fn state_record(
        &mut self,
        journal: &Journal,
    ) -> Result<Option<(Initialized, [u8; 32])>, Error> {
        let mut envelope = Zeroizing::new([0; records::ENVELOPE_SIZE]);
        let Some(n) = self
            .backend
            .read(records::STATE_KEY, &mut envelope[..])
            .await?
        else {
            return Ok(None);
        };
        let root = self.backend.load_root().await?;
        let cipher = SecretBox::from_master_key(&root);
        let mut plaintext = Zeroizing::new([0; records::STATE_SIZE]);
        let len = cipher
            .open(records::CONTEXT, &envelope[..n], &mut plaintext[..])
            .map_err(|_| Error::AuthenticationFailed)?;
        let initialized = records::decode_state(&plaintext[..len], journal)?;
        if bool::from(
            initialized
                .credential_key()
                .provisioning_bytes()
                .ct_eq(root.provisioning_bytes()),
        ) {
            return Err(Error::InvalidInitialization);
        }
        Ok(Some((initialized, sha256(&envelope[..n]))))
    }
    async fn completion(
        &mut self,
        journal: &Journal,
        state_digest: Option<&[u8; 32]>,
    ) -> Result<bool, Error> {
        let mut envelope = Zeroizing::new([0; records::COMPLETION_ENVELOPE_SIZE]);
        let Some(n) = self
            .backend
            .read(records::COMPLETION_KEY, &mut envelope[..])
            .await?
        else {
            return Ok(false);
        };
        // A surviving commit is evidence of a completed key generation. Never
        // create replacement state/key if that committed state has disappeared.
        let digest = state_digest.ok_or(Error::InvalidInitialization)?;
        let root = self.backend.load_root().await?;
        let mut plaintext = Zeroizing::new([0; records::COMPLETION_SIZE]);
        let len = SecretBox::from_master_key(&root)
            .open(
                records::COMPLETION_CONTEXT,
                &envelope[..n],
                &mut plaintext[..],
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        if len != records::COMPLETION_SIZE
            || !bool::from(plaintext[..].ct_eq(&records::completion(journal, digest)))
        {
            return Err(Error::InvalidInitialization);
        }
        Ok(true)
    }
    async fn check(&mut self) -> Result<Report, Error> {
        let partition = self.backend.partition().await?;
        if partition == Partition::DowngradeBlocked {
            return Err(Error::DowngradeBlocked);
        }
        if partition == Partition::DifferentVersion {
            return Ok(Report {
                state: State::MigrationRequired,
                reason: Reason::UnsupportedVersion,
            });
        }
        let root = self.backend.root_status().await?;
        if partition != Partition::Erased && root == RootStatus::Sealed {
            let transaction = self.transaction().await?;
            self.check_lifecycle(partition, transaction.is_some())
                .await?;
            if let Some(transaction) = transaction {
                return Ok(Report {
                    state: if transaction[49] != 2 {
                        State::ResetRequired
                    } else {
                        State::MigrationRequired
                    },
                    reason: if transaction[49] != 2 {
                        Reason::ResetInterrupted
                    } else {
                        Reason::UpgradeInterrupted
                    },
                });
            }
        }
        let journal = if partition == Partition::Erased {
            None
        } else {
            self.journal().await?
        };
        if let Some(journal) = &journal {
            if root == RootStatus::Sealed {
                if let Some((initialized, digest)) = self.state_record(journal).await? {
                    if self.completion(journal, Some(&digest)).await? {
                        if partition == Partition::Migrate {
                            return Ok(Report {
                                state: State::MigrationRequired,
                                reason: Reason::FirmwareVersionMismatch,
                            });
                        }
                        self.initialized = Some(initialized);
                        return Ok(Report {
                            state: State::Ready,
                            reason: Reason::None,
                        });
                    }
                } else {
                    self.completion(journal, None).await?;
                }
            } else {
                let mut bytes = Zeroizing::new([0; records::ENVELOPE_SIZE]);
                for key in [records::STATE_KEY, records::COMPLETION_KEY] {
                    if self.backend.read(key, &mut bytes[..]).await?.is_some() {
                        return Ok(Report {
                            state: State::RecoveryRequired,
                            reason: Reason::MasterKeyMissing,
                        });
                    }
                }
                if journal.mode == RootMode::Existing {
                    return Ok(Report {
                        state: State::RecoveryRequired,
                        reason: Reason::MasterKeyMissing,
                    });
                }
            }
        } else if partition != Partition::Erased {
            let mut bytes = Zeroizing::new([0; records::ENVELOPE_SIZE]);
            for key in [records::STATE_KEY, records::COMPLETION_KEY] {
                if self.backend.read(key, &mut bytes[..]).await?.is_some() {
                    return Err(Error::InvalidInitialization);
                }
            }
            if root == RootStatus::Unsealed {
                return Ok(Report {
                    state: State::RecoveryRequired,
                    reason: Reason::MasterKeyUnsealed,
                });
            }
        } else if root == RootStatus::Unsealed {
            return Ok(Report {
                state: State::RecoveryRequired,
                reason: Reason::MasterKeyUnsealed,
            });
        }
        if partition != Partition::Erased && !self.backend.only_setup_data().await? {
            return Ok(Report {
                state: State::RecoveryRequired,
                reason: if root == RootStatus::Blank {
                    Reason::MasterKeyMissing
                } else {
                    Reason::ApplicationDataPresent
                },
            });
        }
        let reason = if root != RootStatus::Sealed && !self.backend.can_program_root() {
            Reason::ProvisioningDisabled
        } else if partition == Partition::Erased && root == RootStatus::Sealed {
            Reason::StorageErased
        } else if partition == Partition::Erased {
            Reason::None
        } else {
            Reason::SetupInterrupted
        };
        Ok(Report {
            state: if root == RootStatus::Blank {
                State::SetupRequired
            } else {
                State::InitializationRequired
            },
            reason,
        })
    }

    /// Local confirmation is consumed once; re-inspect authoritative state and
    /// recheck expiry before the first write. No automatic generation on boot.
    /// Failure never formats storage or replaces a root/valid state record.
    pub async fn initialize(
        &mut self,
        confirmation: Confirmation,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Report, Error> {
        let report = self.inspect().await;
        if !report.permits_setup() {
            return Err(Error::SetupNotAllowed);
        }
        if !confirmation.valid(self.backend.now_ms()) {
            return Err(Error::ConfirmationExpired);
        }
        self.report = Report {
            state: State::Initializing,
            reason: Reason::None,
        };
        let result = self.finish(rng).await;
        // Recover the actual persisted outcome even if an I/O acknowledgement
        // was lost after commit. Never keep an unverified in-memory Ready state.
        let report = self.inspect().await;
        result?;
        if report.state != State::Ready {
            return Err(Error::VerificationFailed);
        }
        Ok(report)
    }
    async fn finish(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        self.backend.initialize_metadata().await?;
        let root_status = self.backend.root_status().await?;
        let journal = match self.journal().await? {
            Some(journal) => journal,
            None => {
                let mut id = [0; 16];
                rng.try_fill_bytes(&mut id)
                    .map_err(|_| Error::EntropyUnavailable)?;
                if id.iter().all(|b| *b == 0) {
                    return Err(Error::EntropyUnavailable);
                }
                let journal = Journal {
                    mode: if root_status == RootStatus::Blank {
                        RootMode::New
                    } else {
                        RootMode::Existing
                    },
                    id,
                };
                let encoded = journal.encode();
                self.backend.store(records::JOURNAL_KEY, &encoded).await?;
                let readback = self.journal().await?.ok_or(Error::VerificationFailed)?;
                if readback.id != journal.id || readback.mode != journal.mode {
                    return Err(Error::VerificationFailed);
                }
                journal
            }
        };
        match root_status {
            RootStatus::Blank => {
                if journal.mode != RootMode::New {
                    return Err(Error::SetupNotAllowed);
                }
                let key = random_secret(rng)?;
                self.backend
                    .provision_root(&MasterKey::from_bytes(key))
                    .await?;
                self.backend.seal_root().await?;
            }
            RootStatus::Unsealed => self.backend.seal_root().await?,
            RootStatus::Sealed => {}
        }
        // Reload through the sealed reader after provisioning/resume. Root is
        // transient and zeroized; only the mutable credential key is retained.
        let root = self.backend.load_root().await?;
        let digest = match self.state_record(&journal).await? {
            Some((_initialized, digest)) => digest,
            None => {
                let key = random_secret(rng)?;
                if bool::from(key[..].ct_eq(root.provisioning_bytes())) {
                    return Err(Error::EntropyUnavailable);
                }
                let plaintext = records::encode_state(&journal, &key);
                let mut envelope = Zeroizing::new([0; records::ENVELOPE_SIZE]);
                let n = SecretBox::from_master_key(&root)
                    .seal(rng, records::CONTEXT, &plaintext[..], &mut envelope[..])
                    .map_err(crypto_error)?;
                self.backend
                    .store(records::STATE_KEY, &envelope[..n])
                    .await?;
                let (initialized, digest) = self
                    .state_record(&journal)
                    .await?
                    .ok_or(Error::VerificationFailed)?;
                if !bool::from(
                    initialized
                        .credential_key()
                        .provisioning_bytes()
                        .ct_eq(&key[..]),
                ) {
                    return Err(Error::VerificationFailed);
                }
                digest
            }
        };
        let mut envelope = Zeroizing::new([0; records::COMPLETION_ENVELOPE_SIZE]);
        let plaintext = records::completion(&journal, &digest);
        let n = SecretBox::from_master_key(&root)
            .seal(
                rng,
                records::COMPLETION_CONTEXT,
                &plaintext,
                &mut envelope[..],
            )
            .map_err(crypto_error)?;
        if self.backend.firmware_version() != "0.1.0" {
            self.write_lifecycle(rng).await?;
            self.backend.update_metadata_version().await?;
        }
        self.backend
            .store(records::COMPLETION_KEY, &envelope[..n])
            .await?;
        if !self.completion(&journal, Some(&digest)).await? {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }

    async fn read_authenticated<const N: usize>(
        &mut self,
        key: u32,
        context: &[u8],
    ) -> Result<Option<Zeroizing<[u8; N]>>, Error> {
        let mut envelope = Zeroizing::new([0; 1100]);
        let Some(n) = self.backend.read(key, &mut envelope[..]).await? else {
            return Ok(None);
        };
        let root = self.backend.load_root().await?;
        let mut plaintext = Zeroizing::new([0; N]);
        let len = SecretBox::from_master_key(&root)
            .open(context, &envelope[..n], &mut plaintext[..])
            .map_err(|_| Error::AuthenticationFailed)?;
        if len != N {
            return Err(Error::InvalidInitialization);
        }
        Ok(Some(plaintext))
    }
    async fn write_authenticated(
        &mut self,
        key: u32,
        context: &[u8],
        plaintext: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), Error> {
        let root = self.backend.load_root().await?;
        let mut envelope = Zeroizing::new([0; 1100]);
        let n = SecretBox::from_master_key(&root)
            .seal(rng, context, plaintext, &mut envelope[..])
            .map_err(crypto_error)?;
        self.backend.store(key, &envelope[..n]).await?;
        let mut check = Zeroizing::new([0; 1100]);
        if self.backend.read(key, &mut check[..]).await? != Some(n)
            || !bool::from(check[..n].ct_eq(&envelope[..n]))
        {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
    async fn check_lifecycle(&mut self, partition: Partition, pending: bool) -> Result<(), Error> {
        let Some(header) = self
            .read_authenticated::<{ lifecycle::HEADER_SIZE }>(
                lifecycle::RECORD_KEY,
                lifecycle::CONTEXT,
            )
            .await?
        else {
            return if pending
                || partition == Partition::Migrate
                || self.backend.firmware_version() == "0.1.0"
            {
                Ok(())
            } else {
                // A prepared first initialization has no lifecycle record yet.
                let mut commit = [0; records::COMPLETION_ENVELOPE_SIZE];
                if self
                    .backend
                    .read(records::COMPLETION_KEY, &mut commit)
                    .await?
                    .is_none()
                {
                    Ok(())
                } else {
                    Err(Error::InvalidInitialization)
                }
            };
        };
        match lifecycle::decode_header(
            &header[..],
            self.backend.firmware_version(),
            self.backend.geometry(),
        )? {
            Upgrade::Current => Ok(()),
            Upgrade::Migrate if partition == Partition::Migrate => Ok(()),
            Upgrade::DowngradeBlocked => Err(Error::DowngradeBlocked),
            _ => Err(Error::UnsupportedVersion),
        }
    }
    async fn write_lifecycle(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        let header = lifecycle::header(self.backend.firmware_version(), self.backend.geometry())?;
        self.write_authenticated(lifecycle::RECORD_KEY, lifecycle::CONTEXT, &header, rng)
            .await
    }
    async fn transaction(
        &mut self,
    ) -> Result<Option<Zeroizing<[u8; lifecycle::TRANSACTION_SIZE]>>, Error> {
        let Some(bytes) = self
            .read_authenticated::<{ lifecycle::TRANSACTION_SIZE }>(
                lifecycle::TRANSACTION_KEY,
                lifecycle::TRANSACTION_CONTEXT,
            )
            .await?
        else {
            return Ok(None);
        };
        match lifecycle::decode_header(
            &bytes[..49],
            self.backend.firmware_version(),
            self.backend.geometry(),
        )? {
            Upgrade::Current => {}
            Upgrade::DowngradeBlocked => return Err(Error::DowngradeBlocked),
            _ => return Err(Error::UnsupportedVersion),
        }
        if !matches!(bytes[49], 1..=3) {
            return Err(Error::InvalidInitialization);
        }
        let journal = Journal::decode(&bytes[50..107])?;
        records::decode_state(&bytes[107..], &journal)?;
        Ok(Some(bytes))
    }
    /// Destructive factory reset. Only a fresh trusted GPIO confirmation may
    /// enter here. OTP master/boot keys have no write path in this lifecycle.
    pub async fn reset(
        &mut self,
        confirmation: Confirmation,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Report, Error> {
        let partition = self.backend.partition().await?;
        if !matches!(partition, Partition::Compatible | Partition::Migrate) {
            return Err(Error::SetupNotAllowed);
        }
        if self.backend.root_status().await? != RootStatus::Sealed {
            return Err(Error::InvalidMasterKey);
        }
        // Preserve a valid version/geometry fence even when application state is corrupt.
        if let Some(header) = self
            .read_authenticated::<{ lifecycle::HEADER_SIZE }>(
                lifecycle::RECORD_KEY,
                lifecycle::CONTEXT,
            )
            .await?
        {
            match lifecycle::decode_header(
                &header[..],
                self.backend.firmware_version(),
                self.backend.geometry(),
            )? {
                Upgrade::Current | Upgrade::Migrate => {}
                Upgrade::DowngradeBlocked => return Err(Error::DowngradeBlocked),
                _ => return Err(Error::UnsupportedVersion),
            }
        }
        if !confirmation.valid(self.backend.now_ms()) {
            return Err(Error::ConfirmationExpired);
        }
        if let Some(transaction) = self.transaction().await? {
            if transaction[49] != 1 {
                return Err(Error::SetupNotAllowed);
            }
            return self.resume_transition(rng).await;
        }
        let root = self.backend.load_root().await?;
        let key = random_secret(rng)?;
        if bool::from(key[..].ct_eq(root.provisioning_bytes()))
            || self.initialized.as_ref().is_some_and(|old| {
                bool::from(key[..].ct_eq(old.credential_key().provisioning_bytes()))
            })
        {
            return Err(Error::EntropyUnavailable);
        }
        let mut id = [0; 16];
        rng.try_fill_bytes(&mut id)
            .map_err(|_| Error::EntropyUnavailable)?;
        if id.iter().all(|b| *b == 0) {
            return Err(Error::EntropyUnavailable);
        }
        let journal = Journal {
            mode: RootMode::Existing,
            id,
        };
        let state = records::encode_state(&journal, &key);
        self.begin_transition(1, &journal, &state[..], rng).await?;
        self.resume_transition(rng).await
    }
    /// Compatible migration is a transaction too: preserve the credential key,
    /// adopt the v2 startup guard, then commit the release/geometry watermark.
    pub async fn upgrade(&mut self, rng: &mut impl CryptoRngCore) -> Result<Report, Error> {
        let report = self.inspect().await;
        if matches!(
            report.reason,
            Reason::ResetInterrupted | Reason::UpgradeInterrupted
        ) {
            return self.resume_transition(rng).await;
        }
        if report.state != State::MigrationRequired
            || report.reason != Reason::FirmwareVersionMismatch
        {
            return Err(Error::SetupNotAllowed);
        }
        let journal = self.journal().await?.ok_or(Error::InvalidInitialization)?;
        let (state, _) = self
            .state_record(&journal)
            .await?
            .ok_or(Error::InvalidInitialization)?;
        let mut plaintext =
            records::encode_state(&journal, state.credential_key().provisioning_bytes());
        plaintext[56..60].copy_from_slice(&state.settings().user_presence_timeout_ms.to_le_bytes());
        self.begin_transition(2, &journal, &plaintext[..], rng)
            .await?;
        self.resume_transition(rng).await
    }
    async fn begin_transition(
        &mut self,
        mode: u8,
        journal: &Journal,
        state: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), Error> {
        let mut bytes = Zeroizing::new([0; lifecycle::TRANSACTION_SIZE]);
        bytes[..49].copy_from_slice(&lifecycle::header(
            self.backend.firmware_version(),
            self.backend.geometry(),
        )?);
        bytes[49] = mode;
        bytes[50..107].copy_from_slice(&journal.encode());
        bytes[107..].copy_from_slice(state);
        self.initialized = None;
        self.report = Report {
            state: if mode == 1 {
                State::ResetRequired
            } else {
                State::MigrationRequired
            },
            reason: if mode == 1 {
                Reason::ResetInterrupted
            } else {
                Reason::UpgradeInterrupted
            },
        };
        self.write_authenticated(
            lifecycle::TRANSACTION_KEY,
            lifecycle::TRANSACTION_CONTEXT,
            &bytes[..],
            rng,
        )
        .await
    }
    /// A root-authenticated pending transaction proves earlier authorization.
    /// Resume only forward; never fall back to an older credential/PIN state.
    pub async fn resume_transition(
        &mut self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Report, Error> {
        self.initialized = None;
        let result = self.finish_transition(rng).await;
        let report = self.inspect().await;
        result?;
        if report.state != State::Ready {
            return Err(Error::VerificationFailed);
        }
        Ok(report)
    }
    pub async fn restore_backup(
        &mut self,
        bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Report, Error> {
        super::snapshot::validate(bytes).map_err(|_| Error::InvalidInitialization)?;
        if self.inspect().await.state != State::Ready {
            return Err(Error::SetupNotAllowed);
        }
        let mut id = [0; 16];
        rng.try_fill_bytes(&mut id)
            .map_err(|_| Error::EntropyUnavailable)?;
        if id == [0; 16] {
            return Err(Error::EntropyUnavailable);
        }
        let journal = Journal {
            mode: RootMode::Existing,
            id,
        };
        let key: &[u8; 32] = bytes[8..40].try_into().unwrap();
        if !records::valid_secret(key) {
            return Err(Error::InvalidInitialization);
        }
        // Header authenticates full snapshot length and digest before any deletion.
        for (i, chunk) in bytes.chunks(900).enumerate() {
            self.write_authenticated(
                0xffff_fd01 + i as u32,
                b"DOOHICKEY restore chunk v1",
                chunk,
                rng,
            )
            .await?;
        }
        let mut header = [0; 36];
        header[..4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        header[4..].copy_from_slice(&sha256(bytes));
        self.write_authenticated(0xffff_fd00, b"DOOHICKEY restore header v1", &header, rng)
            .await?;
        let state = records::encode_state(&journal, key);
        self.begin_transition(3, &journal, &state[..], rng).await?;
        self.resume_transition(rng).await
    }
    async fn restore_staged(&mut self) -> Result<(), Error> {
        let header = self
            .read_authenticated::<36>(0xffff_fd00, b"DOOHICKEY restore header v1")
            .await?
            .ok_or(Error::InvalidInitialization)?;
        let n = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        if !(40..=32768).contains(&n) {
            return Err(Error::InvalidInitialization);
        }
        let mut bytes = Zeroizing::new([0; 32768]);
        let root = self.backend.load_root().await?;
        let cipher = SecretBox::from_master_key(&root);
        for (i, chunk) in bytes[..n].chunks_mut(900).enumerate() {
            let mut envelope = Zeroizing::new([0; 1024]);
            let len = self
                .backend
                .read(0xffff_fd01 + i as u32, &mut envelope[..])
                .await?
                .ok_or(Error::InvalidInitialization)?;
            if cipher
                .open(b"DOOHICKEY restore chunk v1", &envelope[..len], chunk)
                .map_err(|_| Error::AuthenticationFailed)?
                != chunk.len()
            {
                return Err(Error::InvalidInitialization);
            }
        }
        if !bool::from(sha256(&bytes[..n]).ct_eq(&header[4..])) {
            return Err(Error::AuthenticationFailed);
        }
        super::snapshot::validate(&bytes[..n]).map_err(|_| Error::InvalidInitialization)?;
        self.backend.clear_application().await?;
        let mut p = 40;
        while p < n {
            let key = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            let len = u16::from_le_bytes(bytes[p + 4..p + 6].try_into().unwrap()) as usize;
            self.backend
                .restore_record(key, &bytes[p + 6..p + 6 + len])
                .await?;
            p += 6 + len;
        }
        Ok(())
    }
    async fn finish_transition(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        let partition = self.backend.partition().await?;
        if !matches!(partition, Partition::Compatible | Partition::Migrate) {
            return Err(Error::UnsupportedVersion);
        }
        let bytes = self.transaction().await?.ok_or(Error::SetupNotAllowed)?;
        self.check_lifecycle(partition, true).await?;
        let journal = Journal::decode(&bytes[50..107])?;
        if bytes[49] == 3 {
            self.restore_staged().await?;
        } else if bytes[49] == 1 {
            self.backend.clear_application().await?;
        }
        self.backend
            .store(records::JOURNAL_KEY, &journal.encode())
            .await?;
        self.write_authenticated(records::STATE_KEY, records::CONTEXT, &bytes[107..], rng)
            .await?;
        let (_, digest) = self
            .state_record(&journal)
            .await?
            .ok_or(Error::VerificationFailed)?;
        self.write_authenticated(
            records::COMPLETION_KEY,
            records::COMPLETION_CONTEXT,
            &records::completion(&journal, &digest),
            rng,
        )
        .await?;
        self.write_lifecycle(rng).await?;
        self.backend.update_metadata_version().await?;
        self.backend.remove(lifecycle::TRANSACTION_KEY).await?;
        Ok(())
    }
}
fn crypto_error(error: doohickey_crypto::Error) -> Error {
    if error == doohickey_crypto::Error::EntropyUnavailable {
        Error::EntropyUnavailable
    } else {
        Error::AuthenticationFailed
    }
}
fn random_secret(rng: &mut impl CryptoRngCore) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut key[..])
        .map_err(|_| Error::EntropyUnavailable)?;
    if !records::valid_secret(&key) {
        return Err(Error::EntropyUnavailable);
    }
    Ok(key)
}
