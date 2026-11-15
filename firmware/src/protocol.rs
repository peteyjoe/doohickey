//! Message layer on top of COBS frames.
//! Request:  [req_id u16 LE][cmd u8][payload...]
//! Response: [req_id u16 LE][status u8][body...]
//!   status 0 = OK    -> body is the command's result
//!   status 1 = ERROR -> body is [error_code u16 LE][optional details...]
#![allow(dead_code)] // the error list below is the full registry; most aren't used yet

pub const PROTO_VERSION: u8 = 1;

pub mod cmd {
    pub const HELLO: u8 = 0x01;
    pub const STATUS: u8 = 0x02;
    pub const ECHO: u8 = 0x03;
}

pub mod status {
    pub const OK: u8 = 0;
    pub const ERROR: u8 = 1;
}

/// Every way a command can fail. The numbers are part of the wire protocol
/// (see the integration doc), so never renumber one; retire it instead.
/// `#[repr(u16)]` makes each variant a plain 16-bit number.
#[derive(Clone, Copy, Debug)]
#[repr(u16)]
pub enum Error {
    UnknownCmd = 0x0001,
    BadRequest = 0x0002,
    // 0x0003 retired (was NOT_UNLOCKED)
    BadPin = 0x0004,
    LockedOut = 0x0005,
    BadSequence = 0x0010,
    NoTransfer = 0x0011,
    Busy = 0x0012,
    TooLarge = 0x0013,
    BadBlob = 0x0014,
    HashMismatch = 0x0015,
    UserDenied = 0x0016,
}

impl Error {
    fn code(self) -> u16 {
        self as u16 // allowed because of #[repr(u16)]
    }
}

/// Handle one decoded request and write the response into `out`.
/// Returns the number of bytes written. `out` must be at least as large as
/// the largest request (both buffers are MAX_PAYLOAD in main.rs).
pub fn handle(req: &[u8], out: &mut [u8]) -> usize {
    // Too short to even hold a header, so we don't know the request id: use 0.
    if req.len() < 3 {
        return error_reply(0, Error::BadRequest, out);
    }

    let id = u16::from_le_bytes([req[0], req[1]]);
    let command = req[2];
    let payload = &req[3..];

    // `dispatch` returns Ok(body_len) or Err(reason). Rust makes us handle both.
    match dispatch(command, payload, &mut out[3..]) {
        Ok(n) => {
            out[0..2].copy_from_slice(&id.to_le_bytes());
            out[2] = status::OK;
            3 + n
        }
        Err(e) => error_reply(id, e, out),
    }
}

/// Write [id][status=ERROR][error_code]. No details text yet.
fn error_reply(id: u16, e: Error, out: &mut [u8]) -> usize {
    out[0..2].copy_from_slice(&id.to_le_bytes());
    out[2] = status::ERROR;
    out[3..5].copy_from_slice(&e.code().to_le_bytes());
    5
}

/// Run one command. Writes its result into `body` and returns the length,
/// or returns an Error. New commands get a new arm here.
fn dispatch(command: u8, payload: &[u8], body: &mut [u8]) -> Result<usize, Error> {
    match command {
        cmd::HELLO => {
            body[0] = 0; // firmware major
            body[1] = 1; // firmware minor
            Ok(2)
        }
        cmd::STATUS => {
            body[0] = 1; // locked (stub)
            body[1..3].copy_from_slice(&0u16.to_le_bytes()); // credential count (stub)
            Ok(3)
        }
        cmd::ECHO => {
            // `get_mut(..n)` returns None instead of panicking if `body` is too small;
            // `ok_or(..)?` turns that None into an early `return Err(TooLarge)`.
            body.get_mut(..payload.len())
                .ok_or(Error::TooLarge)?
                .copy_from_slice(payload);
            Ok(payload.len())
        }
        _ => Err(Error::UnknownCmd),
    }
}