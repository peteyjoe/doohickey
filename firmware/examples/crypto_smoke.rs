//! Optional hardware test. No OTP programming or persistent writes. All test
//! keys are ephemeral and discarded. Never use its test messages as credentials.
#![no_std]
#![no_main]

use defmt_rtt as _;
use doohickey_crypto::{Error, ctap::*, rng::HardwareEntropy, secrets::*, serial::*};
use embassy_executor::Spawner;
use embassy_time::Timer;
use panic_probe as _;

#[embassy_executor::main(
    executor = "embassy_rp::executor::Executor",
    entry = "cortex_m_rt::entry"
)]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    let mut entropy = HardwareEntropy::new(p.TRNG);
    defmt::info!("Starting crypto smoke test with RP2350 TRNG");
    let result = async {
        let mut rng = entropy.seed_rng().await?;
        let signing = Es256Key::generate(&mut rng);
        let mut signature = [0; 72];
        signing.sign(b"DOOHICKEY smoke test", &mut signature)?;

        let alice = PinUvKeyAgreement::generate(&mut rng);
        let bob = PinUvKeyAgreement::generate(&mut rng);
        let a = alice.agree(&bob.public_key(), PinUvProtocol::Two)?;
        let b = bob.agree(&alice.public_key(), PinUvProtocol::Two)?;
        let mut encrypted = [0; 48];
        let n = a.encrypt(&mut rng, &[0x55; 32], &mut encrypted)?;
        let mut tag = [0; 32];
        a.authenticate(&encrypted[..n], &mut tag)?;
        b.verify_authentication(&encrypted[..n], &tag)?;
        let mut plain = [0; 32];
        b.decrypt(&encrypted[..n], &mut plain)?;
        if plain != [0x55; 32] {
            return Err(Error::Authentication);
        }

        // Ephemeral root is only for this self-test, never persistent storage.
        let root = MasterKey::generate(&mut rng);
        let cipher = SecretBox::from_master_key(&root);
        let mut envelope = [0; 64];
        let n = cipher.seal(&mut rng, b"smoke/v1", b"smoke", &mut envelope)?;
        let mut recovered = [0; 5];
        cipher.open(b"smoke/v1", &envelope[..n], &mut recovered)?;
        if &recovered != b"smoke" {
            return Err(Error::Authentication);
        }

        let pairing = PairingKey::generate(&mut rng);
        let mut host = SerialHandshake::new(true, &pairing, &mut rng);
        let mut device = SerialHandshake::new(false, &pairing, &mut rng);
        let mut hello = [0; HANDSHAKE_SIZE];
        host.write_message(&mut hello)?;
        device.read_message(&hello)?;
        device.write_message(&mut hello)?;
        host.read_message(&hello)?;
        let mut host = host.finish()?;
        let mut device = device.finish()?;
        let mut frame = [0; 64];
        let n = host.seal(b"smoke", &mut frame)?;
        device.open(&frame[..n], &mut recovered)?;
        if &recovered != b"smoke" {
            return Err(Error::Authentication);
        }
        Ok::<(), Error>(())
    }
    .await;

    match result {
        Ok(()) => defmt::info!("Crypto smoke test passed; no secrets were persisted"),
        Err(error) => defmt::error!(
            "Crypto smoke test failed: {:?}",
            defmt::Debug2Format(&error)
        ),
    }
    loop {
        Timer::after_secs(60).await;
    }
}
