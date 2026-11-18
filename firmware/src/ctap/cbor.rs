//! Heap-free CTAP canonical CBOR. Validate the entire item before traversing
//! borrowed views, including unknown members. No tags/indefinite containers.
use super::{Result, Status};

pub const MAX_MESSAGE_SIZE: usize = 1024;
pub const MAX_DEPTH: usize = 4;
pub const MAX_ITEMS: usize = 256;
pub const MAX_COLLECTION: usize = 32;

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(Status::InvalidCbor)?;
        let value = self.bytes.get(self.pos..end).ok_or(Status::InvalidCbor)?;
        self.pos = end;
        Ok(value)
    }
    fn head(&mut self) -> Result<(u8, u64)> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let ai = first & 31;
        let (value, minimum) = match ai {
            0..=23 => (u64::from(ai), 0),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
                256,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
                65536,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                1 << 32,
            ),
            _ => return Err(Status::InvalidCbor),
        };
        // Floating point representations retain their original width in CTAP.
        if !(major == 7 && ai >= 25) && value < minimum {
            return Err(Status::InvalidCbor);
        }
        Ok((major, value))
    }
    fn item(&mut self, depth: usize, budget: &mut usize) -> Result<()> {
        *budget = budget.checked_sub(1).ok_or(Status::RequestTooLarge)?;
        let start = self.pos;
        let (major, argument) = self.head()?;
        match major {
            0 | 1 => {}
            2 | 3 => {
                let len = usize::try_from(argument).map_err(|_| Status::InvalidCbor)?;
                let bytes = self.take(len)?;
                if major == 3 {
                    core::str::from_utf8(bytes).map_err(|_| Status::InvalidCbor)?;
                }
            }
            4 | 5 => {
                if depth >= MAX_DEPTH {
                    return Err(Status::InvalidCbor);
                }
                let count = usize::try_from(argument).map_err(|_| Status::RequestTooLarge)?;
                if count > MAX_COLLECTION {
                    return Err(Status::RequestTooLarge);
                }
                let mut previous: Option<&[u8]> = None;
                for _ in 0..count {
                    if major == 5 {
                        let key_start = self.pos;
                        self.item(depth + 1, budget)?;
                        let key = &self.bytes[key_start..self.pos];
                        if !matches!(key[0] >> 5, 0..=3 | 7) {
                            return Err(Status::InvalidCbor);
                        }
                        if let Some(previous) = previous {
                            // CTAP compares major type first, then encoded
                            // length, then bytes; strict order rejects duplicates.
                            let order = (previous[0] >> 5)
                                .cmp(&(key[0] >> 5))
                                .then(previous.len().cmp(&key.len()))
                                .then(previous.cmp(key));
                            if !order.is_lt() {
                                return Err(Status::InvalidCbor);
                            }
                        }
                        previous = Some(key);
                    }
                    self.item(depth + 1, budget)?;
                }
            }
            6 => return Err(Status::InvalidCbor),
            7 => {
                // 0xf8 encodes only simple values >=32; 24..31 are reserved.
                if self.bytes[start] == 0xf8 && argument < 32 {
                    return Err(Status::InvalidCbor);
                }
            }
            _ => return Err(Status::InvalidCbor),
        }
        Ok(())
    }
    fn view(&mut self) -> Result<Value<'a>> {
        let start = self.pos;
        let mut budget = MAX_ITEMS;
        self.item(0, &mut budget)?;
        Ok(Value {
            bytes: &self.bytes[start..self.pos],
        })
    }
}

/// A fully validated, exactly delimited CBOR item. No Debug: values may contain
/// account identifiers or encrypted PIN material.
#[derive(Clone, Copy)]
pub struct Value<'a> {
    bytes: &'a [u8],
}
pub fn decode(bytes: &[u8]) -> Result<Value<'_>> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(Status::RequestTooLarge);
    }
    let mut reader = Reader { bytes, pos: 0 };
    let value = reader.view()?;
    if reader.pos != bytes.len() {
        return Err(Status::InvalidCbor);
    }
    Ok(value)
}
impl<'a> Value<'a> {
    pub fn encoded(self) -> &'a [u8] {
        self.bytes
    }
    fn parts(self, expected: u8) -> Result<(Reader<'a>, u64)> {
        let mut reader = Reader {
            bytes: self.bytes,
            pos: 0,
        };
        let (major, value) = reader.head()?;
        if major != expected {
            return Err(Status::CborUnexpectedType);
        }
        Ok((reader, value))
    }
    pub fn unsigned(self) -> Result<u64> {
        Ok(self.parts(0)?.1)
    }
    pub fn integer(self) -> Result<i64> {
        let mut reader = Reader {
            bytes: self.bytes,
            pos: 0,
        };
        let (major, value) = reader.head()?;
        if !matches!(major, 0 | 1) {
            return Err(Status::CborUnexpectedType);
        }
        let value = i64::try_from(value).map_err(|_| Status::InvalidParameter)?;
        match major {
            0 => Ok(value),
            1 => Ok(-1 - value),
            _ => Err(Status::CborUnexpectedType),
        }
    }
    pub fn bytes(self) -> Result<&'a [u8]> {
        let (mut reader, len) = self.parts(2)?;
        reader.take(usize::try_from(len).map_err(|_| Status::InvalidCbor)?)
    }
    pub fn text(self) -> Result<&'a str> {
        let (mut reader, len) = self.parts(3)?;
        core::str::from_utf8(reader.take(usize::try_from(len).map_err(|_| Status::InvalidCbor)?)?)
            .map_err(|_| Status::InvalidCbor)
    }
    pub fn boolean(self) -> Result<bool> {
        match self.bytes {
            [0xf4] => Ok(false),
            [0xf5] => Ok(true),
            _ => Err(Status::CborUnexpectedType),
        }
    }
    pub fn array(self) -> Result<Array<'a>> {
        let (reader, remaining) = self.parts(4)?;
        Ok(Array {
            reader,
            remaining: remaining as usize,
        })
    }
    pub fn map(self) -> Result<Map<'a>> {
        let (reader, remaining) = self.parts(5)?;
        Ok(Map {
            reader,
            remaining: remaining as usize,
        })
    }
    pub fn get_int(self, wanted: i64) -> Result<Option<Self>> {
        let mut map = self.map()?;
        while let Some((key, value)) = map.read_next()? {
            if key.integer().ok() == Some(wanted) {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    pub fn get_text(self, wanted: &str) -> Result<Option<Self>> {
        let mut map = self.map()?;
        while let Some((key, value)) = map.read_next()? {
            if key.text().ok() == Some(wanted) {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}
pub struct Array<'a> {
    reader: Reader<'a>,
    remaining: usize,
}
impl<'a> Array<'a> {
    pub fn len(&self) -> usize {
        self.remaining
    }
    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }
    pub fn read_next(&mut self) -> Result<Option<Value<'a>>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        self.reader.view().map(Some)
    }
}
pub struct Map<'a> {
    reader: Reader<'a>,
    remaining: usize,
}
impl<'a> Map<'a> {
    pub fn read_next(&mut self) -> Result<Option<(Value<'a>, Value<'a>)>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        Ok(Some((self.reader.view()?, self.reader.view()?)))
    }
}

/// Fixed-buffer response encoder. Callers emit keys in CTAP canonical order.
pub struct Encoder<'a> {
    output: &'a mut [u8],
    len: usize,
}
impl<'a> Encoder<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self { output, len: 0 }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.len.checked_add(bytes.len()).ok_or(Status::Other)?;
        self.output
            .get_mut(self.len..end)
            .ok_or(Status::Other)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    fn head(&mut self, major: u8, value: u64) -> Result<()> {
        if value < 24 {
            self.put(&[(major << 5) | value as u8])
        } else if value <= 255 {
            self.put(&[(major << 5) | 24, value as u8])
        } else if value <= 65535 {
            self.put(&[(major << 5) | 25])?;
            self.put(&(value as u16).to_be_bytes())
        } else if value <= u64::from(u32::MAX) {
            self.put(&[(major << 5) | 26])?;
            self.put(&(value as u32).to_be_bytes())
        } else {
            self.put(&[(major << 5) | 27])?;
            self.put(&value.to_be_bytes())
        }
    }
    pub fn unsigned(&mut self, value: u64) -> Result<()> {
        self.head(0, value)
    }
    pub fn integer(&mut self, value: i64) -> Result<()> {
        if value >= 0 {
            self.head(0, value as u64)
        } else {
            self.head(1, (-1 - value) as u64)
        }
    }
    pub fn bytes(&mut self, value: &[u8]) -> Result<()> {
        self.head(2, value.len() as u64)?;
        self.put(value)
    }
    pub fn text(&mut self, value: &str) -> Result<()> {
        self.head(3, value.len() as u64)?;
        self.put(value.as_bytes())
    }
    pub fn boolean(&mut self, value: bool) -> Result<()> {
        self.put(&[if value { 0xf5 } else { 0xf4 }])
    }
    pub fn array(&mut self, len: usize) -> Result<()> {
        self.head(4, len as u64)
    }
    pub fn map(&mut self, len: usize) -> Result<()> {
        self.head(5, len as u64)
    }
}
