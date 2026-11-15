//! Message layer on top of COBS frames.
//! Request:  [req_id u16 LE][cmd u8][payload...]
//! Response: [req_id u16 LE][status u8][payload...]

pub const PROTO_VERSION: u8 = 1;

pub mod cmd {
    pub const HELLO: u8 = 0x01;
    pub const STATUS: u8 = 0x02;
    pub const ECHO: u8 = 0x03;
}

pub mod status {
    pub const OK: u8 = 0;
    pub const UNKNOWN_CMD: u8 = 1;
    pub const BAD_REQUEST: u8 = 2;
}

/// Handle one decoded request and write the response into `out`.
/// Returns the number of bytes written. `out` must be at least as
/// large as the largest request (our buffers are both MAX_PAYLOAD).
pub fn handle(req: &[u8], out: &mut [u8]) -> usize {
    // Too short to even contain a header: reply with id 0
    if req.len() < 3 {
        out[0..2].copy_from_slice(&0u16.to_le_bytes());
        out[2] = status::BAD_REQUEST;
        return 3;
    }

    let id = u16::from_le_bytes([req[0], req[1]]);
    let command = req[2];
    let payload = &req[3..];

    out[0..2].copy_from_slice(&id.to_le_bytes());
    let body = &mut out[3..];

    // `match` returns a (status, body_length) pair
    let (st, n) = match command {
        cmd::HELLO => {
            body[0] = PROTO_VERSION;
            body[1] = 0; // firmware major
            body[2] = 1; // firmware minor
            (status::OK, 3)
        }
        cmd::STATUS => {
            body[0] = 1; // locked (stub)
            body[1..3].copy_from_slice(&0u16.to_le_bytes()); // credential count (stub)
            (status::OK, 3)
        }
        cmd::ECHO => {
            body[..payload.len()].copy_from_slice(payload);
            (status::OK, payload.len())
        }
        _ => (status::UNKNOWN_CMD, 0),
    };

    out[2] = st;
    3 + n
}