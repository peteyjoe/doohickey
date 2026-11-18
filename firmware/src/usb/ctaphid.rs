//! Bounded CTAPHID transport, independent of USB hardware for host testing.
//! Backends are polled without dropping in-progress operations on cancellation.

use crate::ctap::{Command, Status};
use zeroize::Zeroize;

pub const REPORT_SIZE: usize = 64;
pub const MAX_MESSAGE_SIZE: usize = 1024;
pub const BROADCAST: u32 = u32::MAX;
pub const PING: u8 = 0x01;
pub const INIT: u8 = 0x06;
pub const CBOR: u8 = 0x10;
pub const CANCEL: u8 = 0x11;
pub const KEEPALIVE: u8 = 0x3b;
pub const ERROR: u8 = 0x3f;
pub const RECEIVE_TIMEOUT_MS: u64 = 3000;
const KEEPALIVE_MS: u64 = 100;

// FIDO usage page 0xF1D0, usage 1, one 64-byte IN and OUT report, no report IDs.
pub const REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportError {
    InvalidCommand = 0x01,
    InvalidLength = 0x03,
    InvalidSequence = 0x04,
    MessageTimeout = 0x05,
    ChannelBusy = 0x06,
    InvalidChannel = 0x0b,
    Other = 0x7f,
}

impl TransportError {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::InvalidCommand => &[0x01],
            Self::InvalidLength => &[0x03],
            Self::InvalidSequence => &[0x04],
            Self::MessageTimeout => &[0x05],
            Self::ChannelBusy => &[0x06],
            Self::InvalidChannel => &[0x0b],
            Self::Other => &[0x7f],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Processing,
    UserPresence,
}

impl Progress {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Processing => &[1],
            Self::UserPresence => &[2],
        }
    }
}

pub enum Completion {
    Pending(Progress),
    Ready(Result<usize, Status>),
}

/// Queue work in start, poll for a response CBOR body, and request cooperative
/// cancellation. Never block here. A future repository-owner adapter must copy
/// request bytes before start returns and retain ownership until completion.
/// cancel/disconnected must not drop flash futures or report success early.
pub trait Backend {
    fn start(&mut self, channel: u32, request: &[u8]) -> Result<(), Status>;
    fn poll(&mut self, response: &mut [u8]) -> Completion;
    fn cancel(&mut self);
    /// Abort/resynchronize this channel and clear its continuation state.
    fn resynchronize(&mut self, channel: u32);
    /// Clear transport-bound continuation/auth state and request cancellation.
    fn disconnected(&mut self);
}

/// Until the CBOR codec and persistent command backend are connected, known
/// commands fail explicitly; no fake getInfo or credential success is returned.
pub struct UnavailableBackend;
impl Backend for UnavailableBackend {
    fn start(&mut self, _channel: u32, request: &[u8]) -> Result<(), Status> {
        let command = *request.first().ok_or(Status::InvalidLength)?;
        Command::try_from(command)?;
        Err(Status::OperationDenied)
    }
    fn poll(&mut self, _response: &mut [u8]) -> Completion {
        Completion::Ready(Err(Status::OperationDenied))
    }
    fn cancel(&mut self) {}
    fn resynchronize(&mut self, _channel: u32) {}
    fn disconnected(&mut self) {}
}

pub struct Reply<'a> {
    pub channel: u32,
    pub command: u8,
    pub payload: &'a [u8],
}
impl Reply<'_> {
    fn error(channel: u32, error: TransportError) -> Self {
        Self {
            channel,
            command: ERROR,
            payload: error.bytes(),
        }
    }
    pub fn reports(&self) -> Result<Reports<'_>, TransportError> {
        if self.payload.len() > MAX_MESSAGE_SIZE || self.command & 0x80 != 0 {
            return Err(TransportError::InvalidLength);
        }
        Ok(Reports {
            reply: self,
            offset: 0,
            packet: 0,
        })
    }
}

pub struct Reports<'a> {
    reply: &'a Reply<'a>,
    offset: usize,
    packet: u16,
}
impl Iterator for Reports<'_> {
    type Item = [u8; REPORT_SIZE];
    fn next(&mut self) -> Option<Self::Item> {
        if self.packet != 0 && self.offset == self.reply.payload.len() {
            return None;
        }
        let mut report = [0; REPORT_SIZE];
        report[..4].copy_from_slice(&self.reply.channel.to_be_bytes());
        let header = if self.packet == 0 {
            report[4] = self.reply.command | 0x80;
            report[5..7].copy_from_slice(&(self.reply.payload.len() as u16).to_be_bytes());
            7
        } else {
            report[4] = (self.packet - 1) as u8;
            5
        };
        let count = (REPORT_SIZE - header).min(self.reply.payload.len() - self.offset);
        report[header..header + count]
            .copy_from_slice(&self.reply.payload[self.offset..self.offset + count]);
        self.offset += count;
        self.packet += 1;
        Some(report)
    }
}

#[derive(Clone, Copy)]
enum State {
    Idle,
    Receiving {
        channel: u32,
        command: u8,
        len: usize,
        received: usize,
        sequence: u8,
        deadline: u64,
    },
    Processing {
        channel: u32,
        last_keepalive: u64,
        progress: Option<Progress>,
    },
    Resync {
        channel: u32,
        nonce: [u8; 8],
    },
    Draining,
}

pub struct Engine<B: Backend> {
    backend: B,
    state: State,
    rx: [u8; MAX_MESSAGE_SIZE],
    tx: [u8; MAX_MESSAGE_SIZE],
    next_channel: u32,
    first_channel: u32,
    version: [u8; 3],
}

impl<B: Backend> Engine<B> {
    pub fn new(backend: B, version: [u8; 3]) -> Self {
        Self {
            backend,
            state: State::Idle,
            rx: [0; MAX_MESSAGE_SIZE],
            tx: [0; MAX_MESSAGE_SIZE],
            next_channel: 1,
            first_channel: 1,
            version,
        }
    }

    fn valid_channel(&self, channel: u32) -> bool {
        channel >= self.first_channel && channel < self.next_channel
    }

    /// Invalidates channels and drains any operation safely before reuse. The
    /// monotonically allocated IDs are never reused during this firmware boot.
    pub fn disconnected(&mut self) {
        let pending = matches!(
            self.state,
            State::Processing { .. } | State::Resync { .. } | State::Draining
        );
        self.backend.disconnected();
        self.first_channel = self.next_channel;
        self.rx.zeroize();
        self.tx.zeroize();
        self.state = if pending {
            State::Draining
        } else {
            State::Idle
        };
    }

    fn init_reply(&mut self, channel: u32, nonce: &[u8; 8]) -> Reply<'_> {
        self.tx.zeroize();
        self.tx[..8].copy_from_slice(nonce);
        self.tx[8..12].copy_from_slice(&channel.to_be_bytes());
        self.tx[12] = 2;
        self.tx[13..16].copy_from_slice(&self.version);
        self.tx[16] = 0x04 | 0x08; // CBOR framing, no CTAP1/U2F MSG or WINK.
        Reply {
            channel,
            command: INIT,
            payload: &self.tx[..17],
        }
    }

    fn cbor_error(&mut self, channel: u32, status: Status) -> Reply<'_> {
        self.tx.zeroize();
        self.tx[0] = status as u8;
        Reply {
            channel,
            command: CBOR,
            payload: &self.tx[..1],
        }
    }

    /// Call tick regularly even when no reports arrive (timeouts/keepalives).
    pub fn tick(&mut self, now_ms: u64) -> Option<Reply<'_>> {
        match self.state {
            State::Receiving {
                channel, deadline, ..
            } if now_ms >= deadline => {
                self.rx.zeroize();
                self.state = State::Idle;
                Some(Reply::error(channel, TransportError::MessageTimeout))
            }
            State::Processing {
                channel,
                last_keepalive,
                progress,
            } => {
                self.tx.zeroize();
                match self.backend.poll(&mut self.tx[1..]) {
                    Completion::Pending(current) => {
                        self.tx.zeroize();
                        if progress != Some(current)
                            || now_ms.saturating_sub(last_keepalive) >= KEEPALIVE_MS
                        {
                            self.state = State::Processing {
                                channel,
                                last_keepalive: now_ms,
                                progress: Some(current),
                            };
                            Some(Reply {
                                channel,
                                command: KEEPALIVE,
                                payload: current.bytes(),
                            })
                        } else {
                            None
                        }
                    }
                    Completion::Ready(result) => {
                        self.state = State::Idle;
                        match result {
                            Ok(n) if n < MAX_MESSAGE_SIZE => Some(Reply {
                                channel,
                                command: CBOR,
                                payload: &self.tx[..n + 1],
                            }),
                            Ok(_) => Some(self.cbor_error(channel, Status::Other)),
                            Err(status) => Some(self.cbor_error(channel, status)),
                        }
                    }
                }
            }
            State::Resync { channel, nonce } => {
                if matches!(self.backend.poll(&mut self.tx[1..]), Completion::Ready(_)) {
                    self.state = State::Idle;
                    Some(self.init_reply(channel, &nonce))
                } else {
                    self.tx.zeroize();
                    None
                }
            }
            State::Draining => {
                if matches!(self.backend.poll(&mut self.tx[1..]), Completion::Ready(_)) {
                    self.state = State::Idle;
                }
                self.tx.zeroize();
                None
            }
            _ => None,
        }
    }

    pub fn receive(&mut self, report: &[u8], now_ms: u64) -> Option<Reply<'_>> {
        if report.len() < 4 {
            return None;
        }
        let channel = u32::from_be_bytes(report[..4].try_into().unwrap());
        if report.len() != REPORT_SIZE {
            if matches!(self.state, State::Receiving { channel: active, .. } if active == channel) {
                self.rx.zeroize();
                self.state = State::Idle;
            }
            return Some(Reply::error(channel, TransportError::InvalidLength));
        }
        let initial = report[4] & 0x80 != 0;
        let command = report[4] & 0x7f;
        let len = u16::from_be_bytes([report[5], report[6]]) as usize;
        // CANCEL has no response of its own, including idle/wrong-channel cases.
        if initial && command == CANCEL {
            if len == 0
                && matches!(self.state, State::Processing { channel: active, .. } if active == channel)
            {
                self.backend.cancel();
            }
            return None;
        }
        if matches!(self.state, State::Draining) {
            return None;
        }
        if !initial
            && !matches!(self.state, State::Receiving { channel: active, .. } if active == channel)
        {
            return None;
        }
        if channel == 0 || (channel != BROADCAST && !self.valid_channel(channel)) {
            return Some(Reply::error(channel, TransportError::InvalidChannel));
        }
        let active = match self.state {
            State::Receiving { channel, .. }
            | State::Processing { channel, .. }
            | State::Resync { channel, .. } => Some(channel),
            _ => None,
        };
        if active.is_some_and(|active| active != channel) {
            return Some(Reply::error(channel, TransportError::ChannelBusy));
        }
        if initial && command == INIT {
            if len != 8 {
                return Some(Reply::error(channel, TransportError::InvalidLength));
            }
            let nonce: [u8; 8] = report[7..15].try_into().unwrap();
            if channel != BROADCAST {
                self.backend.resynchronize(channel);
            }
            if matches!(self.state, State::Processing { .. } | State::Resync { .. }) {
                self.rx.zeroize();
                self.state = State::Resync { channel, nonce };
                return None;
            }
            self.rx.zeroize();
            self.state = State::Idle;
            let allocated = if channel == BROADCAST {
                if self.next_channel == BROADCAST {
                    return Some(Reply::error(channel, TransportError::Other));
                }
                let allocated = self.next_channel;
                self.next_channel += 1;
                allocated
            } else {
                channel
            };
            let mut reply = self.init_reply(allocated, &nonce);
            reply.channel = channel; // Broadcast response contains the allocated CID.
            return Some(reply);
        }
        if channel == BROADCAST {
            return Some(Reply::error(channel, TransportError::InvalidChannel));
        }
        if matches!(self.state, State::Processing { .. } | State::Resync { .. }) {
            return if initial {
                Some(Reply::error(channel, TransportError::ChannelBusy))
            } else {
                None
            };
        }
        if initial {
            if matches!(self.state, State::Receiving { .. }) {
                self.rx.zeroize();
                self.state = State::Idle;
                return Some(Reply::error(channel, TransportError::InvalidSequence));
            }
            if command != PING && command != CBOR {
                return Some(Reply::error(channel, TransportError::InvalidCommand));
            }
            if len > MAX_MESSAGE_SIZE || (command == CBOR && len == 0) {
                return Some(Reply::error(channel, TransportError::InvalidLength));
            }
            let count = len.min(57);
            self.rx.zeroize();
            self.rx[..count].copy_from_slice(&report[7..7 + count]);
            self.state = State::Receiving {
                channel,
                command,
                len,
                received: count,
                sequence: 0,
                deadline: now_ms.saturating_add(RECEIVE_TIMEOUT_MS),
            };
        } else {
            let State::Receiving {
                channel,
                command,
                len,
                received,
                sequence,
                ..
            } = self.state
            else {
                return None;
            };
            if report[4] != sequence {
                self.rx.zeroize();
                self.state = State::Idle;
                return Some(Reply::error(channel, TransportError::InvalidSequence));
            }
            let count = (len - received).min(59);
            self.rx[received..received + count].copy_from_slice(&report[5..5 + count]);
            self.state = State::Receiving {
                channel,
                command,
                len,
                received: received + count,
                sequence: sequence + 1,
                deadline: now_ms.saturating_add(RECEIVE_TIMEOUT_MS),
            };
        }
        if let State::Receiving {
            channel,
            command,
            len,
            received,
            ..
        } = self.state
            && received == len
        {
            self.state = State::Idle;
            if command == PING {
                return Some(Reply {
                    channel,
                    command,
                    payload: &self.rx[..len],
                });
            }
            let result = self.backend.start(channel, &self.rx[..len]);
            self.rx.zeroize();
            return match result {
                Ok(()) => {
                    self.state = State::Processing {
                        channel,
                        last_keepalive: now_ms,
                        progress: None,
                    };
                    None
                }
                Err(status) => Some(self.cbor_error(channel, status)),
            };
        }
        None
    }
}
