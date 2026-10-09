use alloc::vec::Vec;

use crate::{
    codec::{Reader, Writer},
    ActionKind, CodecError, Digest, KeyId, ProofPurpose, Scheme, MAX_CPI_DATA,
    MAX_CPI_METAS, MAX_UPLOAD_CHUNK, META_ALLOWED_MASK,
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionTag {
    InitializeRoot = 0,
    InitializeKey = 1,
    WriteKey = 2,
    InitializeSignature = 3,
    WriteSignature = 4,
    FinalizeKey = 5,
    ActivateInitialKey = 6,
    Seal = 7,
    Rotate = 8,
    CreateVault = 9,
    Authorize = 10,
    ExecuteCpi = 11,
    ExecuteLamports = 12,
    CloseSignature = 13,
    ClosePermit = 14,
    CloseKey = 15,
}

impl TryFrom<u8> for InstructionTag {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::InitializeRoot),
            1 => Ok(Self::InitializeKey),
            2 => Ok(Self::WriteKey),
            3 => Ok(Self::InitializeSignature),
            4 => Ok(Self::WriteSignature),
            5 => Ok(Self::FinalizeKey),
            6 => Ok(Self::ActivateInitialKey),
            7 => Ok(Self::Seal),
            8 => Ok(Self::Rotate),
            9 => Ok(Self::CreateVault),
            10 => Ok(Self::Authorize),
            11 => Ok(Self::ExecuteCpi),
            12 => Ok(Self::ExecuteLamports),
            13 => Ok(Self::CloseSignature),
            14 => Ok(Self::ClosePermit),
            15 => Ok(Self::CloseKey),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqAuthInstruction {
    InitializeRoot {
        chain_id: Digest,
    },
    InitializeKey {
        generation: u32,
        key_id: KeyId,
        scheme: Scheme,
    },
    WriteKey {
        offset: u16,
        bytes: Vec<u8>,
    },
    InitializeSignature {
        purpose: ProofPurpose,
        operation_id: KeyId,
        digest: Digest,
        sequence: u64,
        valid_after_slot: u64,
        expires_slot: u64,
    },
    WriteSignature {
        offset: u16,
        bytes: Vec<u8>,
    },
    FinalizeKey,
    ActivateInitialKey,
    Seal,
    Rotate,
    CreateVault,
    Authorize {
        action: ActionKind,
    },
    ExecuteCpi {
        meta_flags: Vec<u8>,
        instruction_data: Vec<u8>,
    },
    ExecuteLamports {
        amount: u64,
    },
    CloseSignature,
    ClosePermit,
    CloseKey,
}

impl PqAuthInstruction {
    pub fn unpack(data: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(data);
        let tag = InstructionTag::try_from(reader.u8()?)?;
        let out = match tag {
            InstructionTag::InitializeRoot => Self::InitializeRoot {
                chain_id: reader.array()?,
            },
            InstructionTag::InitializeKey => Self::InitializeKey {
                generation: reader.u32()?,
                key_id: reader.array()?,
                scheme: Scheme::try_from(reader.u8()?)?,
            },
            InstructionTag::WriteKey => {
                let offset = reader.u16()?;
                let len = reader.u16()? as usize;
                if len == 0 || len > MAX_UPLOAD_CHUNK {
                    return Err(CodecError::InvalidLength);
                }
                Self::WriteKey {
                    offset,
                    bytes: reader.take(len)?.to_vec(),
                }
            }
            InstructionTag::InitializeSignature => Self::InitializeSignature {
                purpose: ProofPurpose::try_from(reader.u8()?)?,
                operation_id: reader.array()?,
                digest: reader.array()?,
                sequence: reader.u64()?,
                valid_after_slot: reader.u64()?,
                expires_slot: reader.u64()?,
            },
            InstructionTag::WriteSignature => {
                let offset = reader.u16()?;
                let len = reader.u16()? as usize;
                if len == 0 || len > MAX_UPLOAD_CHUNK {
                    return Err(CodecError::InvalidLength);
                }
                Self::WriteSignature {
                    offset,
                    bytes: reader.take(len)?.to_vec(),
                }
            }
            InstructionTag::FinalizeKey => Self::FinalizeKey,
            InstructionTag::ActivateInitialKey => Self::ActivateInitialKey,
            InstructionTag::Seal => Self::Seal,
            InstructionTag::Rotate => Self::Rotate,
            InstructionTag::CreateVault => Self::CreateVault,
            InstructionTag::Authorize => Self::Authorize {
                action: ActionKind::try_from(reader.u8()?)?,
            },
            InstructionTag::ExecuteCpi => {
                let meta_count = reader.u16()? as usize;
                if meta_count > MAX_CPI_METAS {
                    return Err(CodecError::InvalidLength);
                }
                let mut meta_flags = Vec::with_capacity(meta_count);
                for _ in 0..meta_count {
                    let flags = reader.u8()?;
                    if flags & !META_ALLOWED_MASK != 0 {
                        return Err(CodecError::InvalidValue);
                    }
                    meta_flags.push(flags);
                }
                let data_len = reader.u32()? as usize;
                if data_len > MAX_CPI_DATA {
                    return Err(CodecError::InvalidLength);
                }
                Self::ExecuteCpi {
                    meta_flags,
                    instruction_data: reader.take(data_len)?.to_vec(),
                }
            }
            InstructionTag::ExecuteLamports => Self::ExecuteLamports {
                amount: reader.u64()?,
            },
            InstructionTag::CloseSignature => Self::CloseSignature,
            InstructionTag::ClosePermit => Self::ClosePermit,
            InstructionTag::CloseKey => Self::CloseKey,
        };
        reader.finish()?;
        Ok(out)
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        match self {
            Self::InitializeRoot { chain_id } => {
                writer.u8(InstructionTag::InitializeRoot as u8);
                writer.bytes(chain_id);
            }
            Self::InitializeKey {
                generation,
                key_id,
                scheme,
            } => {
                writer.u8(InstructionTag::InitializeKey as u8);
                writer.u32(*generation);
                writer.bytes(key_id);
                writer.u8(*scheme as u8);
            }
            Self::WriteKey { offset, bytes } => {
                writer.u8(InstructionTag::WriteKey as u8);
                writer.u16(*offset);
                writer.u16(bytes.len() as u16);
                writer.bytes(bytes);
            }
            Self::InitializeSignature {
                purpose,
                operation_id,
                digest,
                sequence,
                valid_after_slot,
                expires_slot,
            } => {
                writer.u8(InstructionTag::InitializeSignature as u8);
                writer.u8(*purpose as u8);
                writer.bytes(operation_id);
                writer.bytes(digest);
                writer.u64(*sequence);
                writer.u64(*valid_after_slot);
                writer.u64(*expires_slot);
            }
            Self::WriteSignature { offset, bytes } => {
                writer.u8(InstructionTag::WriteSignature as u8);
                writer.u16(*offset);
                writer.u16(bytes.len() as u16);
                writer.bytes(bytes);
            }
            Self::FinalizeKey => writer.u8(InstructionTag::FinalizeKey as u8),
            Self::ActivateInitialKey => writer.u8(InstructionTag::ActivateInitialKey as u8),
            Self::Seal => writer.u8(InstructionTag::Seal as u8),
            Self::Rotate => writer.u8(InstructionTag::Rotate as u8),
            Self::CreateVault => writer.u8(InstructionTag::CreateVault as u8),
            Self::Authorize { action } => {
                writer.u8(InstructionTag::Authorize as u8);
                writer.u8(*action as u8);
            }
            Self::ExecuteCpi {
                meta_flags,
                instruction_data,
            } => {
                writer.u8(InstructionTag::ExecuteCpi as u8);
                writer.u16(meta_flags.len() as u16);
                for flags in meta_flags {
                    writer.u8(*flags);
                }
                writer.u32(instruction_data.len() as u32);
                writer.bytes(instruction_data);
            }
            Self::ExecuteLamports { amount } => {
                writer.u8(InstructionTag::ExecuteLamports as u8);
                writer.u64(*amount);
            }
            Self::CloseSignature => writer.u8(InstructionTag::CloseSignature as u8),
            Self::ClosePermit => writer.u8(InstructionTag::ClosePermit as u8),
            Self::CloseKey => writer.u8(InstructionTag::CloseKey as u8),
        }
        writer.into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(ix: PqAuthInstruction) {
        let bytes = ix.pack();
        assert_eq!(PqAuthInstruction::unpack(&bytes).unwrap(), ix);
    }

    #[test]
    fn all_variable_instructions_round_trip() {
        round_trip(PqAuthInstruction::InitializeRoot { chain_id: [1; 32] });
        round_trip(PqAuthInstruction::InitializeKey {
            generation: 7,
            key_id: [2; 16],
            scheme: Scheme::MlDsa44,
        });
        round_trip(PqAuthInstruction::WriteKey {
            offset: 0,
            bytes: vec![3; 20],
        });
        round_trip(PqAuthInstruction::InitializeSignature {
            purpose: ProofPurpose::Authorize,
            operation_id: [4; 16],
            digest: [5; 32],
            sequence: 9,
            valid_after_slot: 10,
            expires_slot: 20,
        });
        round_trip(PqAuthInstruction::ExecuteCpi {
            meta_flags: vec![0, 1, 3],
            instruction_data: vec![8, 9],
        });
        round_trip(PqAuthInstruction::ExecuteLamports { amount: 42 });
    }
}
