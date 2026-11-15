use super::{
    Reason, Report, State,
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
            _ => Reason::InvalidInitialization,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Partition {
    Erased,
    Compatible,
    DifferentVersion,
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
    stored == running || stored == "0.1.0"
}

/// One owner, asynchronous I/O; operations must be awaited to completion.
/// Implementations expose only initialization records and the master-key policy,
/// not boot-key/security flags or a generic OTP write operation.
#[allow(async_fn_in_trait)] // Single-core owner; backend futures need not be Send.
pub trait Backend {
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
        if partition == Partition::DifferentVersion {
            return Ok(Report {
                state: State::MigrationRequired,
                reason: Reason::FirmwareVersionMismatch,
            });
        }
        let root = self.backend.root_status().await?;
        let journal = if partition == Partition::Erased {
            None
        } else {
            self.journal().await?
        };
        if let Some(journal) = &journal {
            if root == RootStatus::Sealed {
                if let Some((initialized, digest)) = self.state_record(journal).await? {
                    if self.completion(journal, Some(&digest)).await? {
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
        self.backend
            .store(records::COMPLETION_KEY, &envelope[..n])
            .await?;
        if !self.completion(&journal, Some(&digest)).await? {
            return Err(Error::VerificationFailed);
        }
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
