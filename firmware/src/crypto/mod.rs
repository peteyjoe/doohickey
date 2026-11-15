//! Heap-free cryptographic building blocks. See README.md for protocol scope,
//! key provisioning, serial framing, and security assumptions.
#![no_std]

pub mod ctap;
pub mod rng;
pub mod secrets;
pub mod serial;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidKey,
    InvalidLength,
    BufferTooSmall,
    Authentication,
    InvalidState,
    Exhausted,
    EntropyUnavailable,
    KeyUnavailable,
}
