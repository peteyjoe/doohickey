use doohickey_crypto::{Error, ctap::*, secrets::*, serial::*};
use hex_literal::hex;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroizing;

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

#[test]
fn es256_rfc6979_vector_and_der_verification() {
    let key = Es256Key::from_bytes(&hex!(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    ))
    .unwrap();
    let mut out = [0; 72];
    let len = key.sign(b"sample", &mut out).unwrap();
    let signature = Signature::from_der(&out[..len]).unwrap();
    assert_eq!(
        signature.to_bytes().as_slice(),
        &hex!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        )
    );
    let verifier = VerifyingKey::from_sec1_bytes(&key.public_key()).unwrap();
    verifier.verify(b"sample", &signature).unwrap();
    assert!(verifier.verify(b"changed", &signature).is_err());
    assert!(matches!(
        Es256Key::from_bytes(&[0; 32]),
        Err(Error::InvalidKey)
    ));
}

#[test]
fn pin_protocols_agree_authenticate_and_encrypt() {
    for protocol in [PinUvProtocol::One, PinUvProtocol::Two] {
        let alice = PinUvKeyAgreement::generate(&mut rng(1));
        let bob = PinUvKeyAgreement::generate(&mut rng(2));
        let a = alice.agree(&bob.public_key(), protocol).unwrap();
        let b = bob.agree(&alice.public_key(), protocol).unwrap();
        let mut ciphertext = [0; 48];
        let length = a.encrypt(&mut rng(3), &[7; 32], &mut ciphertext).unwrap();
        assert_eq!(
            length,
            if protocol == PinUvProtocol::One {
                32
            } else {
                48
            }
        );
        let mut auth = [0; 32];
        let tag_len = a.authenticate(&ciphertext[..length], &mut auth).unwrap();
        b.verify_authentication(&ciphertext[..length], &auth[..tag_len])
            .unwrap();
        let mut plain = [0; 32];
        assert_eq!(b.decrypt(&ciphertext[..length], &mut plain), Ok(32));
        assert_eq!(plain, [7; 32]);
        auth[0] ^= 1;
        assert_eq!(
            b.verify_authentication(&ciphertext[..length], &auth[..tag_len]),
            Err(Error::Authentication)
        );
        assert_eq!(
            b.verify_authentication(&ciphertext[..length], &auth[..tag_len - 1]),
            Err(Error::Authentication)
        );
        assert!(matches!(
            alice.agree(&[0; 65], protocol),
            Err(Error::InvalidKey)
        ));
        assert_eq!(
            a.encrypt(&mut rng(4), &[0; 17], &mut ciphertext),
            Err(Error::InvalidLength)
        );
        for len in 0..16 {
            assert_eq!(
                b.decrypt(&ciphertext[..len], &mut plain),
                Err(Error::InvalidLength)
            );
        }
    }
}

#[test]
fn sealed_secrets_are_randomized_and_bind_context_and_key() {
    let root = MasterKey::from_bytes(Zeroizing::new([1; 32]));
    let cipher = SecretBox::from_master_key(&root);
    let mut random = rng(4);
    let mut first = [0; 64];
    let mut second = [0; 64];
    let n = cipher
        .seal(&mut random, b"credential/1", b"secret", &mut first)
        .unwrap();
    cipher
        .seal(&mut random, b"credential/1", b"secret", &mut second)
        .unwrap();
    assert_ne!(first, second);
    let mut plain = [0; 6];
    assert_eq!(cipher.open(b"credential/1", &first[..n], &mut plain), Ok(6));
    assert_eq!(&plain, b"secret");
    assert_eq!(
        cipher.open(b"credential/2", &first[..n], &mut plain),
        Err(Error::Authentication)
    );
    assert_eq!(plain, [0; 6]);
    let wrong = SecretBox::from_master_key(&MasterKey::from_bytes(Zeroizing::new([2; 32])));
    assert_eq!(
        wrong.open(b"credential/1", &first[..n], &mut plain),
        Err(Error::Authentication)
    );
    for i in 0..n {
        let mut changed = first;
        changed[i] ^= 1;
        assert!(
            cipher
                .open(b"credential/1", &changed[..n], &mut plain)
                .is_err()
        );
    }
}

#[test]
fn sealed_secret_boundaries_and_empty_plaintext() {
    let cipher = SecretBox::from_master_key(&MasterKey::generate(&mut rng(1)));
    let mut out = [0; ENVELOPE_OVERHEAD];
    assert_eq!(
        cipher.seal(&mut rng(1), b"empty", b"", &mut out),
        Ok(ENVELOPE_OVERHEAD)
    );
    assert_eq!(cipher.open(b"empty", &out, &mut []), Ok(0));
    assert_eq!(
        cipher.seal(&mut rng(1), b"", b"x", &mut out),
        Err(Error::BufferTooSmall)
    );
    for len in 0..ENVELOPE_OVERHEAD {
        assert_eq!(
            cipher.open(b"", &out[..len], &mut []),
            Err(Error::InvalidLength)
        );
    }
}

fn sessions() -> (SerialSession, SerialSession) {
    sessions_with_seed(1)
}

fn sessions_with_seed(seed: u8) -> (SerialSession, SerialSession) {
    let key = PairingKey::from_bytes(Zeroizing::new([9; 32]));
    let mut host = SerialHandshake::new(true, &key, &mut rng(seed));
    let mut device = SerialHandshake::new(false, &key, &mut rng(seed + 1));
    let mut message = [0; HANDSHAKE_SIZE];
    host.write_message(&mut message).unwrap();
    device.read_message(&message).unwrap();
    device.write_message(&mut message).unwrap();
    host.read_message(&message).unwrap();
    (host.finish().unwrap(), device.finish().unwrap())
}

#[test]
fn serial_maximum_record_and_small_buffer_retry() {
    let (mut host, mut device) = sessions();
    let mut frame = [0; MAX_FRAME];
    let n = host.seal(&[7; MAX_PLAINTEXT], &mut frame).unwrap();
    assert_eq!(n, MAX_FRAME);
    assert_eq!(
        device.open(&frame[..n], &mut [0; MAX_PLAINTEXT - 1]),
        Err(Error::BufferTooSmall)
    );
    let mut plain = [0; MAX_PLAINTEXT];
    assert_eq!(device.open(&frame[..n], &mut plain), Ok(MAX_PLAINTEXT));
    assert_eq!(plain, [7; MAX_PLAINTEXT]);
}

#[test]
fn new_handshake_rejects_old_session_records() {
    let (mut host, _) = sessions();
    let (_, mut new_device) = sessions_with_seed(10);
    let mut frame = [0; MAX_FRAME];
    let n = host.seal(b"old session", &mut frame).unwrap();
    assert_eq!(
        new_device.open(&frame[..n], &mut [0; MAX_PLAINTEXT]),
        Err(Error::Authentication)
    );
}

#[test]
fn serial_bidirectional_transport_and_replay_rejection() {
    let (mut host, mut device) = sessions();
    assert_eq!(host.channel_binding(), device.channel_binding());
    let mut frame = [0; MAX_FRAME];
    let mut plain = [0; MAX_PLAINTEXT];
    let n = host.seal(b"backup request", &mut frame).unwrap();
    let len = device.open(&frame[..n], &mut plain).unwrap();
    assert_eq!(&plain[..len], b"backup request");
    let mut response = [0; MAX_FRAME];
    let n2 = device.seal(b"backup response", &mut response).unwrap();
    let len = host.open(&response[..n2], &mut plain).unwrap();
    assert_eq!(&plain[..len], b"backup response");
    assert_eq!(
        device.open(&frame[..n], &mut plain),
        Err(Error::Authentication)
    );
    assert_eq!(device.seal(b"closed", &mut frame), Err(Error::InvalidState));
}

#[test]
fn serial_tampering_reflection_and_reordering_close_session() {
    for mode in 0..3 {
        let (mut host, mut device) = sessions();
        let mut frame = [0; MAX_FRAME];
        let mut plain = [0x55; MAX_PLAINTEXT];
        let n = host.seal(b"first", &mut frame).unwrap();
        match mode {
            0 => {
                frame[n - 1] ^= 1;
                assert_eq!(
                    device.open(&frame[..n], &mut plain),
                    Err(Error::Authentication)
                );
            }
            1 => {
                assert_eq!(
                    host.open(&frame[..n], &mut plain),
                    Err(Error::Authentication)
                );
            }
            _ => {
                let n = host.seal(b"second", &mut frame).unwrap();
                assert_eq!(
                    device.open(&frame[..n], &mut plain),
                    Err(Error::Authentication)
                );
            }
        }
        assert_eq!(&plain[..5], &[0; 5]);
    }
}

#[test]
fn serial_requires_pairing_and_complete_handshake() {
    let host_key = PairingKey::from_bytes(Zeroizing::new([1; 32]));
    let device_key = PairingKey::from_bytes(Zeroizing::new([2; 32]));
    let mut host = SerialHandshake::new(true, &host_key, &mut rng(1));
    let mut device = SerialHandshake::new(false, &device_key, &mut rng(2));
    let mut message = [0; HANDSHAKE_SIZE];
    assert!(matches!(
        SerialHandshake::new(true, &host_key, &mut rng(1)).finish(),
        Err(Error::InvalidState)
    ));
    assert_eq!(device.write_message(&mut message), Err(Error::InvalidState));
    host.write_message(&mut message).unwrap();
    assert_eq!(device.read_message(&message), Err(Error::Authentication));
    assert!(matches!(device.finish(), Err(Error::InvalidState)));
}

#[test]
fn serial_malformed_frames_do_not_panic_or_reuse_session() {
    let key = PairingKey::generate(&mut rng(1));
    for n in 0..HANDSHAKE_SIZE {
        let mut handshake = SerialHandshake::new(false, &key, &mut rng(2));
        assert_eq!(
            handshake.read_message(&[0; HANDSHAKE_SIZE][..n]),
            Err(Error::InvalidLength)
        );
    }
    let (mut host, mut device) = sessions();
    assert_eq!(
        host.seal(&[0; MAX_PLAINTEXT + 1], &mut [0; MAX_FRAME]),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        device.open(&[0; TAG_SIZE - 1], &mut [0; MAX_PLAINTEXT]),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        device.open(&[0; TAG_SIZE], &mut [0; MAX_PLAINTEXT]),
        Err(Error::InvalidState)
    );
}

#[test]
fn noise_interoperates_with_independent_snow_host() {
    let raw_key = [0x42; 32];
    let key = PairingKey::from_bytes(Zeroizing::new(raw_key));
    let mut device = SerialHandshake::new(false, &key, &mut rng(3));
    let mut host = snow::Builder::new(PROTOCOL.parse().unwrap())
        .prologue(b"DOOHICKEY serial backup v1")
        .unwrap()
        .psk(0, &raw_key)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut message = [0; HANDSHAKE_SIZE];
    assert_eq!(
        host.write_message(&[], &mut message).unwrap(),
        HANDSHAKE_SIZE
    );
    device.read_message(&message).unwrap();
    device.write_message(&mut message).unwrap();
    assert_eq!(host.read_message(&message, &mut []).unwrap(), 0);
    let mut host = host.into_transport_mode().unwrap();
    let mut device = device.finish().unwrap();
    let mut frame = [0; MAX_FRAME];
    let mut plain = [0; MAX_PLAINTEXT];
    let n = host.write_message(b"from snow", &mut frame).unwrap();
    let len = device.open(&frame[..n], &mut plain).unwrap();
    assert_eq!(&plain[..len], b"from snow");
    let n = device.seal(b"to snow", &mut frame).unwrap();
    let len = host.read_message(&frame[..n], &mut plain).unwrap();
    assert_eq!(&plain[..len], b"to snow");
}
