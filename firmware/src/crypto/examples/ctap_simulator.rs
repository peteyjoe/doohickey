//! Host-only interoperability fixture. Deterministic secrets and synthetic UP;
//! never a firmware build or evidence of physical user presence.
#![allow(dead_code, unused_imports)]
#[path = "../../ctap/authenticator.rs"]
mod authenticator;
#[path = "../../ctap/mod.rs"]
mod ctap;
#[path = "../../ctap/pin_session.rs"]
mod pin_session;
#[path = "../tests/support/credential_storage.rs"]
mod storage;
use ctap::{Request, Result, Status, cbor, credentials, info, pin_uv};
use rand_core::SeedableRng;
use std::io::{self, BufRead, Write};
use zeroize::Zeroizing;
struct Presence;
impl authenticator::Presence for Presence {
    async fn confirm(&mut self) -> Result<()> {
        Ok(())
    }
    fn cancelled(&self) -> bool {
        false
    }
}
fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = core::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(v) => v,
        _ => panic!("fixture I/O must finish"),
    }
}
fn main() {
    let key = doohickey_crypto::secrets::MasterKey::from_bytes(Zeroizing::new([7; 32]));
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
    let mut store = storage::Storage::default();
    let mut session = pin_session::Session::default();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if line == "REBOOT" {
            session = pin_session::Session::default();
            println!("00");
            continue;
        }
        let message: Vec<u8> = line
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
            .collect();
        let mut scratch = ctap::codec::Scratch::new();
        let mut out = [0; 1023];
        let result = match ctap::codec::decode(&message, &mut scratch) {
            Ok(request) => ready(authenticator::execute_with_session(
                &mut storage::credentials::Repository::new(&mut store, &key, &mut rng),
                request,
                &mut Presence,
                &mut out,
                &mut session,
                0,
            )),
            Err(error) => Err(error),
        };
        match result {
            Ok(n) => {
                print!("00");
                for byte in &out[..n] {
                    print!("{byte:02x}");
                }
            }
            Err(error) => print!("{:02x}", error as u8),
        }
        println!();
        io::stdout().flush().unwrap();
    }
}
