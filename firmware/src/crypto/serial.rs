//! Authenticated serial record layer: Noise_NNpsk0_25519_ChaChaPoly_SHA256.
//! The 32-byte pairing key must be provisioned over an authenticated channel,
//! not sent over the same untrusted serial connection or derived from a PIN.
//! User-presence/backup authorization remains an application responsibility.

use crate::Error;
use noise_protocol::{CipherState, DH, HandshakeState, U8Array};
use noise_rust_crypto::{ChaCha20Poly1305, Sha256, sensitive::Sensitive};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
pub const HANDSHAKE_SIZE: usize = 48;
pub const MAX_PLAINTEXT: usize = 1024;
pub const TAG_SIZE: usize = 16;
pub const MAX_FRAME: usize = MAX_PLAINTEXT + TAG_SIZE;
const PROLOGUE: &[u8] = b"DOOHICKEY serial backup v1";
const TRANSPORT_AAD: &[u8] = b""; // Standard Noise transport encoding.

/// Pair-specific secret, distinct from device root and CTAP keys.
pub struct PairingKey(Zeroizing<[u8; 32]>);

impl PairingKey {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut key = Zeroizing::new([0; 32]);
        rng.fill_bytes(&mut key[..]);
        Self(key)
    }
    pub fn from_bytes(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
    /// Explicit export for secure out-of-band pairing or encrypted persistence.
    pub fn provisioning_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// noise-protocol's DH::genkey has no RNG parameter. Our private adapter always
// supplies a fresh key from the caller's CSPRNG at construction, and fails
// closed if the library ever unexpectedly attempts implicit generation.
enum ExplicitEphemeral25519 {}

impl DH for ExplicitEphemeral25519 {
    type Key = Sensitive<[u8; 32]>;
    type Pubkey = [u8; 32];
    type Output = Sensitive<[u8; 32]>;
    fn name() -> &'static str {
        "25519"
    }
    fn genkey() -> Self::Key {
        panic!("Noise ephemeral must come from the supplied CSPRNG")
    }
    fn pubkey(key: &Self::Key) -> Self::Pubkey {
        *PublicKey::from(&StaticSecret::from(**key)).as_bytes()
    }
    fn dh(key: &Self::Key, peer: &Self::Pubkey) -> Result<Self::Output, ()> {
        let shared = StaticSecret::from(**key).diffie_hellman(&PublicKey::from(*peer));
        if bool::from(shared.as_bytes().ct_eq(&[0; 32])) {
            return Err(());
        }
        Ok(Sensitive::from_slice(shared.as_bytes()))
    }
}

type NoiseHandshake = HandshakeState<ExplicitEphemeral25519, ChaCha20Poly1305, Sha256>;

/// Not Clone. One handshake, with fresh random ephemerals, for each connection.
pub struct SerialHandshake {
    state: Option<NoiseHandshake>,
}

impl SerialHandshake {
    /// Initiator is the host; responder is the authenticator. Never send backup
    /// data in handshake messages: only transport messages after `finish`.
    pub fn new(initiator: bool, pairing: &PairingKey, rng: &mut impl CryptoRngCore) -> Self {
        let mut ephemeral = Zeroizing::new([0; 32]);
        rng.fill_bytes(&mut ephemeral[..]);
        let mut state = NoiseHandshake::new(
            noise_protocol::patterns::noise_nn_psk0(),
            initiator,
            PROLOGUE,
            None,
            Some(Sensitive::from(ephemeral)),
            None,
            None,
        );
        state.push_psk(&pairing.0[..]);
        Self { state: Some(state) }
    }

    pub fn write_message(&mut self, output: &mut [u8; HANDSHAKE_SIZE]) -> Result<(), Error> {
        let state = self.state.as_mut().ok_or(Error::InvalidState)?;
        if state.completed() || !state.is_write_turn() {
            return Err(Error::InvalidState);
        }
        if state.write_message(&[], output).is_err() {
            output.zeroize();
            self.state = None;
            return Err(Error::Authentication);
        }
        Ok(())
    }

    /// Authentication or malformed-frame errors permanently invalidate this
    /// handshake. Start over with a fresh instance; do not reuse its ephemeral.
    pub fn read_message(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.len() != HANDSHAKE_SIZE {
            self.state = None;
            return Err(Error::InvalidLength);
        }
        let state = self.state.as_mut().ok_or(Error::InvalidState)?;
        if state.completed() || state.is_write_turn() {
            return Err(Error::InvalidState);
        }
        if state.read_message(input, &mut []).is_err() {
            self.state = None;
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<SerialSession, Error> {
        let state = self.state.take().ok_or(Error::InvalidState)?;
        if !state.completed() {
            return Err(Error::InvalidState);
        }
        let (initiator_tx, responder_tx) = state.get_ciphers();
        let mut binding = [0; 32];
        binding.copy_from_slice(state.get_hash());
        let (tx, rx) = if state.get_is_initiator() {
            (initiator_tx, responder_tx)
        } else {
            (responder_tx, initiator_tx)
        };
        Ok(SerialSession {
            tx,
            rx,
            closed: false,
            binding,
        })
    }
}

/// Ordered transport with independent directional keys and implicit counters.
/// Never serialize/restore/clone sessions or reset counters. Any inbound
/// authentication error closes the session. Reconnect with a new handshake.
pub struct SerialSession {
    tx: CipherState<ChaCha20Poly1305>,
    rx: CipherState<ChaCha20Poly1305>,
    closed: bool,
    binding: [u8; 32],
}

impl SerialSession {
    /// Public transcript hash for binding application authorization to a session.
    pub fn channel_binding(&self) -> &[u8; 32] {
        &self.binding
    }

    pub fn seal(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if self.closed {
            return Err(Error::InvalidState);
        }
        if self.tx.get_next_n() == u64::MAX {
            self.closed = true;
            return Err(Error::Exhausted);
        }
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::InvalidLength);
        }
        let len = plaintext.len() + TAG_SIZE;
        if output.len() < len {
            return Err(Error::BufferTooSmall);
        }
        self.tx
            .encrypt_ad(TRANSPORT_AAD, plaintext, &mut output[..len]);
        Ok(len)
    }

    pub fn open(&mut self, ciphertext: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if self.closed {
            return Err(Error::InvalidState);
        }
        if self.rx.get_next_n() == u64::MAX {
            self.closed = true;
            return Err(Error::Exhausted);
        }
        if !(TAG_SIZE..=MAX_FRAME).contains(&ciphertext.len()) {
            self.closed = true;
            return Err(Error::InvalidLength);
        }
        let len = ciphertext.len() - TAG_SIZE;
        if output.len() < len {
            return Err(Error::BufferTooSmall);
        }
        if self
            .rx
            .decrypt_ad(TRANSPORT_AAD, ciphertext, &mut output[..len])
            .is_err()
        {
            output[..len].zeroize();
            self.closed = true;
            return Err(Error::Authentication);
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_all_zero_x25519_shared_secret() {
        let secret = Sensitive::from_slice(&[1; 32]);
        assert!(ExplicitEphemeral25519::dh(&secret, &[0; 32]).is_err());
    }

    #[test]
    fn nonce_exhaustion_closes_instead_of_wrapping_or_panicking() {
        for receive in [false, true] {
            let mut session = SerialSession {
                tx: CipherState::new(&[1; 32], if receive { 0 } else { u64::MAX }),
                rx: CipherState::new(&[2; 32], if receive { u64::MAX } else { 0 }),
                closed: false,
                binding: [0; 32],
            };
            let mut out = [0; TAG_SIZE];
            let result = if receive {
                session.open(&[0; TAG_SIZE], &mut out)
            } else {
                session.seal(&[], &mut out)
            };
            assert_eq!(result, Err(Error::Exhausted));
            assert_eq!(session.seal(&[], &mut out), Err(Error::InvalidState));
        }
    }
}
