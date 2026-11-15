//! Minimal COBS framing. Frames on the wire are: COBS(payload) followed by 0x00.

/// Worst-case encoded size for `n` payload bytes, including the 0x00 delimiter.
pub const fn max_encoded_len(n: usize) -> usize {
    n + n / 254 + 2
}

/// What happened when we fed the reader one byte.
pub enum Push<'a> {
    Pending,          // frame not finished yet
    Frame(&'a [u8]),  // complete frame (still encoded, delimiter stripped)
    Overflow,         // frame was too big; it has been discarded
}

/// Accumulates bytes until a 0x00 delimiter. `N` is a const generic: the
/// buffer size is part of the type and fixed at compile time (no heap).
pub struct FrameReader<const N: usize> {
    buf: [u8; N],
    len: usize,
    overflow: bool,
}

impl<const N: usize> FrameReader<N> {
    pub const fn new() -> Self {
        Self { buf: [0; N], len: 0, overflow: false }
    }

    /// The returned `Push<'_>` borrows from `self`, so the compiler won't let
    /// you call `push` again while you're still holding the returned frame.
    pub fn push(&mut self, b: u8) -> Push<'_> {
        if b == 0 {
            let n = self.len;
            self.len = 0;
            if self.overflow {
                self.overflow = false;
                return Push::Overflow;
            }
            if n == 0 {
                return Push::Pending; // empty frame (back-to-back delimiters): ignore
            }
            return Push::Frame(&self.buf[..n]);
        }
        if self.len < N {
            self.buf[self.len] = b;
            self.len += 1;
        } else {
            self.overflow = true; // drop bytes until the next delimiter
        }
        Push::Pending
    }
}