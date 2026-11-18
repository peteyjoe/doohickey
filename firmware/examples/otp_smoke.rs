//! Explicit test only: stores an emulated root in plaintext flash, never OTP.
//! Run twice (including after a firmware update) to check persistence.
#![no_std]
#![no_main]

#[path = "../src/otp.rs"]
pub mod otp;
#[path = "../src/storage.rs"]
pub mod storage;

use defmt_rtt as _;
use doohickey_crypto::{
    rng::HardwareEntropy,
    secrets::{MasterKey, SecretBox},
};
use embassy_executor::Spawner;
use embassy_time::Timer;
use panic_probe as _;

// Application test record, distinct from the emulator's reserved OTP keys.
const PROBE_KEY: u32 = 0x7fff_ff00;

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(_spawner: Spawner) {
    defmt::warn!("INSECURE TEST OTP: flash emulation, never real OTP provisioning");
    let p = embassy_rp::init(Default::default());
    let mut entropy = HardwareEntropy::new(p.TRNG);
    let mut rng = entropy.seed_rng().await.expect("TRNG failed");
    let mut storage = storage::Storage::new(p.FLASH, p.DMA_CH0);
    storage
        .initialize_metadata()
        .await
        .expect("storage metadata failed");
    let mut envelope = [0; 64];
    let had_probe = storage
        .read(PROBE_KEY, &mut envelope)
        .await
        .unwrap()
        .is_some();
    let cipher = {
        let mut otp = otp::Otp::new(&mut storage);
        let master = match otp.read_master_key().await {
            Ok(master) => {
                defmt::info!("Loaded existing emulated master key");
                master
            }
            Err(otp::Error::Unprovisioned) => {
                assert!(
                    !had_probe,
                    "existing encrypted probe but missing test root; refusing replacement"
                );
                let master = MasterKey::generate(&mut rng);
                otp.provision_master_key(&master)
                    .await
                    .expect("test provisioning failed");
                otp.seal_master_key().await.expect("test sealing failed");
                defmt::info!("Provisioned and sealed new TEST master key in flash");
                otp.read_master_key().await.expect("test readback failed")
            }
            Err(error) => panic!("test OTP failed: {error:?}"),
        };
        match otp.read_secure_boot_key_hash().await {
            Ok(_) => {}
            Err(otp::Error::Unprovisioned) => {
                // Only an emulator fixture, NOT a deployable secure-boot key.
                let hash = otp::BootKeyHash::from_bytes(doohickey_crypto::ctap::sha256(
                    b"TEST boot key fixture",
                ))
                .unwrap();
                otp.provision_secure_boot_key_hash(&hash)
                    .await
                    .expect("test boot hash failed");
            }
            Err(error) => panic!("test boot hash failed: {error:?}"),
        }
        SecretBox::from_master_key(&master)
    };
    let context = b"OTP emulator persistence test/v1";
    if !had_probe {
        let n = cipher
            .seal(&mut rng, context, b"otp smoke", &mut envelope)
            .unwrap();
        storage.store(PROBE_KEY, &envelope[..n]).await.unwrap();
    }
    let n = storage
        .read(PROBE_KEY, &mut envelope)
        .await
        .unwrap()
        .unwrap();
    let mut plaintext = [0; 9];
    cipher
        .open(context, &envelope[..n], &mut plaintext)
        .expect("persistent key mismatch");
    assert_eq!(&plaintext, b"otp smoke");
    if had_probe {
        defmt::info!(
            "OTP emulator persistence verified using the previously stored encrypted marker"
        );
    } else {
        defmt::info!("OTP emulator initialized; reboot/update and run again to verify persistence");
    }
    loop {
        Timer::after_secs(60).await;
    }
}
