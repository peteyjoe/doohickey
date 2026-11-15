//! RP2350 hardware entropy, conditioned into a ChaCha20 CSPRNG. No clock,
//! device ID, ROSC-only fallback, OS random source, or fixed production seed.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};

/// Not Clone: cloning a generator would repeat its future keys/nonces.
/// Recreate from hardware entropy at boot and periodically in long-lived use.
pub struct DeviceRng(ChaCha20Rng);

impl RngCore for DeviceRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.0.fill_bytes(out);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(out)
    }
}
impl CryptoRng for DeviceRng {}

#[cfg(target_os = "none")]
mod hardware {
    use super::*;
    use crate::Error;
    use embassy_rp::{
        Peri, bind_interrupts,
        peripherals::TRNG,
        trng::{Config, Trng},
    };
    use embassy_time::{Duration, with_timeout};
    use rand_core::SeedableRng;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    bind_interrupts!(struct Irqs {
        TRNG_IRQ => embassy_rp::trng::InterruptHandler<TRNG>;
    });

    pub struct HardwareEntropy<'d>(Trng<'d, TRNG>);

    impl<'d> HardwareEntropy<'d> {
        pub fn new(peripheral: Peri<'d, TRNG>) -> Self {
            let mut config = Config::default();
            // Leave all hardware health checks and the balancer enabled.
            config.sample_count = 100;
            Self(Trng::new(peripheral, Irqs, config))
        }

        /// A stuck/failing peripheral yields an error, never a fallback seed.
        /// The driver owns health-test retries; the timeout bounds waiting.
        pub async fn seed_rng(&mut self) -> Result<DeviceRng, Error> {
            let mut entropy = Zeroizing::new([0u8; 64]);
            with_timeout(Duration::from_secs(2), self.0.fill_bytes(&mut entropy[..]))
                .await
                .map_err(|_| Error::EntropyUnavailable)?;
            // Additional catastrophic-failure guard, not an entropy estimate.
            if entropy.iter().all(|b| *b == entropy[0]) {
                return Err(Error::EntropyUnavailable);
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&Sha256::digest(&entropy[..]));
            Ok(DeviceRng(ChaCha20Rng::from_seed(*seed)))
        }
    }
}

#[cfg(target_os = "none")]
pub use hardware::HardwareEntropy;
