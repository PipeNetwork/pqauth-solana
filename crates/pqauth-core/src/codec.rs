use alloc::vec::Vec;
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    UnexpectedEof,
    InvalidLength,
    InvalidValue,
    TrailingBytes,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::InvalidValue => f.write_str("invalid value"),
            Self::TrailingBytes => f.write_str("trailing bytes"),
        }
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    pub fn finish(self) -> Result<(), CodecError> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CodecError::InvalidLength)?;
        if end > self.data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let out = &self.data[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| CodecError::InvalidLength)?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CodecError::InvalidLength)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| CodecError::InvalidLength)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CodecError::InvalidLength)
    }
}

#[derive(Default)]
pub struct Writer {
    data: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.data.extend_from_slice(value);
    }

    pub fn u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

pub fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], CodecError> {
    let end = offset.checked_add(N).ok_or(CodecError::InvalidLength)?;
    data.get(offset..end)
        .ok_or(CodecError::UnexpectedEof)?
        .try_into()
        .map_err(|_| CodecError::InvalidLength)
}

pub fn write_array<const N: usize>(
    data: &mut [u8],
    offset: usize,
    value: &[u8; N],
) -> Result<(), CodecError> {
    let end = offset.checked_add(N).ok_or(CodecError::InvalidLength)?;
    let target = data.get_mut(offset..end).ok_or(CodecError::UnexpectedEof)?;
    target.copy_from_slice(value);
    Ok(())
}

pub fn read_u16(data: &[u8], offset: usize) -> Result<u16, CodecError> {
    Ok(u16::from_le_bytes(read_array(data, offset)?))
}

pub fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<(), CodecError> {
    write_array(data, offset, &value.to_le_bytes())
}

pub fn read_u32(data: &[u8], offset: usize) -> Result<u32, CodecError> {
    Ok(u32::from_le_bytes(read_array(data, offset)?))
}

pub fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), CodecError> {
    write_array(data, offset, &value.to_le_bytes())
}

pub fn read_u64(data: &[u8], offset: usize) -> Result<u64, CodecError> {
    Ok(u64::from_le_bytes(read_array(data, offset)?))
}

pub fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<(), CodecError> {
    write_array(data, offset, &value.to_le_bytes())
}
