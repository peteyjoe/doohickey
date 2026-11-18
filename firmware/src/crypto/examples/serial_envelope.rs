//! Host-only interoperability fixture; deterministic synthetic key, no device I/O.
use doohickey_crypto::secrets::{MasterKey, SecretBox};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroizing;
fn main() {
    let key = MasterKey::from_bytes(Zeroizing::new([7; 32]));
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let mut out = [0; 128];
    let n = SecretBox::from_master_key(&key)
        .seal(
            &mut rng,
            b"serial device v1",
            b"browser interoperability",
            &mut out,
        )
        .unwrap();
    for b in &out[..n] {
        print!("{b:02x}");
    }
    println!();
}
