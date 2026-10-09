use crate::{
    codec::{
        read_array, read_u16, read_u32, read_u64, write_array, write_u16, write_u32,
        write_u64,
    },
    Address, CodecError, Digest, KeyId, KEY_ACCOUNT_LEN, KEY_HEADER_LEN, KEY_MAGIC,
    ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SIGNATURE_LEN, PERMIT_ACCOUNT_LEN, PERMIT_MAGIC,
    PROTOCOL_VERSION, ROOT_ACCOUNT_LEN, ROOT_MAGIC, SIGNATURE_ACCOUNT_LEN,
    SIGNATURE_HEADER_LEN, SIGNATURE_MAGIC, VAULT_ACCOUNT_LEN, VAULT_MAGIC,
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    MlDsa44 = 1,
}

impl TryFrom<u8> for Scheme {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::MlDsa44),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootStatus {
    Unsealed = 1,
    Sealed = 2,
}

impl TryFrom<u8> for RootStatus {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Unsealed),
            2 => Ok(Self::Sealed),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    Uploading = 1,
    Finalized = 2,
}

impl TryFrom<u8> for KeyStatus {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Uploading),
            2 => Ok(Self::Finalized),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofPurpose {
    KeyPossession = 1,
    Seal = 2,
    Rotate = 3,
    Authorize = 4,
}

impl TryFrom<u8> for ProofPurpose {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::KeyPossession),
            2 => Ok(Self::Seal),
            3 => Ok(Self::Rotate),
            4 => Ok(Self::Authorize),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofStatus {
    Uploading = 1,
    Ready = 2,
    Consumed = 3,
}

impl TryFrom<u8> for ProofStatus {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Uploading),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Consumed),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    Cpi = 1,
    TransferLamports = 2,
}

impl TryFrom<u8> for ActionKind {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Cpi),
            2 => Ok(Self::TransferLamports),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermitStatus {
    Ready = 1,
    Consumed = 2,
}

impl TryFrom<u8> for PermitStatus {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Consumed),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootAccount {
    pub bump: u8,
    pub status: RootStatus,
    pub scheme: Scheme,
    pub flags: u32,
    pub legacy_address: Address,
    pub chain_id: Digest,
    pub current_key: Address,
    pub current_key_hash: Digest,
    pub generation: u32,
    pub sequence: u64,
    pub created_slot: u64,
    pub sealed_slot: u64,
}

impl RootAccount {
    pub fn unpack(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != ROOT_ACCOUNT_LEN
            || read_array::<8>(data, 0)? != ROOT_MAGIC
            || data[8] != PROTOCOL_VERSION
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self {
            bump: data[9],
            status: RootStatus::try_from(data[10])?,
            scheme: Scheme::try_from(data[11])?,
            flags: read_u32(data, 12)?,
            legacy_address: read_array(data, 16)?,
            chain_id: read_array(data, 48)?,
            current_key: read_array(data, 80)?,
            current_key_hash: read_array(data, 112)?,
            generation: read_u32(data, 144)?,
            sequence: read_u64(data, 148)?,
            created_slot: read_u64(data, 156)?,
            sealed_slot: read_u64(data, 164)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), CodecError> {
        if data.len() != ROOT_ACCOUNT_LEN {
            return Err(CodecError::InvalidLength);
        }
        data.fill(0);
        write_array(data, 0, &ROOT_MAGIC)?;
        data[8] = PROTOCOL_VERSION;
        data[9] = self.bump;
        data[10] = self.status as u8;
        data[11] = self.scheme as u8;
        write_u32(data, 12, self.flags)?;
        write_array(data, 16, &self.legacy_address)?;
        write_array(data, 48, &self.chain_id)?;
        write_array(data, 80, &self.current_key)?;
        write_array(data, 112, &self.current_key_hash)?;
        write_u32(data, 144, self.generation)?;
        write_u64(data, 148, self.sequence)?;
        write_u64(data, 156, self.created_slot)?;
        write_u64(data, 164, self.sealed_slot)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyAccountHeader {
    pub bump: u8,
    pub scheme: Scheme,
    pub status: KeyStatus,
    pub generation: u32,
    pub key_id: KeyId,
    pub root: Address,
    pub uploader: Address,
    pub key_hash: Digest,
    pub key_len: u16,
    pub written_len: u16,
    pub created_slot: u64,
    pub finalized_slot: u64,
}

impl KeyAccountHeader {
    pub fn unpack(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != KEY_ACCOUNT_LEN
            || read_array::<8>(data, 0)? != KEY_MAGIC
            || data[8] != PROTOCOL_VERSION
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self {
            bump: data[9],
            scheme: Scheme::try_from(data[10])?,
            status: KeyStatus::try_from(data[11])?,
            generation: read_u32(data, 12)?,
            key_id: read_array(data, 16)?,
            root: read_array(data, 32)?,
            uploader: read_array(data, 64)?,
            key_hash: read_array(data, 96)?,
            key_len: read_u16(data, 128)?,
            written_len: read_u16(data, 130)?,
            created_slot: read_u64(data, 132)?,
            finalized_slot: read_u64(data, 140)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), CodecError> {
        if data.len() != KEY_ACCOUNT_LEN {
            return Err(CodecError::InvalidLength);
        }
        data[..KEY_HEADER_LEN].fill(0);
        write_array(data, 0, &KEY_MAGIC)?;
        data[8] = PROTOCOL_VERSION;
        data[9] = self.bump;
        data[10] = self.scheme as u8;
        data[11] = self.status as u8;
        write_u32(data, 12, self.generation)?;
        write_array(data, 16, &self.key_id)?;
        write_array(data, 32, &self.root)?;
        write_array(data, 64, &self.uploader)?;
        write_array(data, 96, &self.key_hash)?;
        write_u16(data, 128, self.key_len)?;
        write_u16(data, 130, self.written_len)?;
        write_u64(data, 132, self.created_slot)?;
        write_u64(data, 140, self.finalized_slot)?;
        Ok(())
    }

    pub fn public_key<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], CodecError> {
        if self.key_len as usize != ML_DSA_44_PUBLIC_KEY_LEN || data.len() != KEY_ACCOUNT_LEN {
            return Err(CodecError::InvalidLength);
        }
        Ok(&data[KEY_HEADER_LEN..KEY_HEADER_LEN + ML_DSA_44_PUBLIC_KEY_LEN])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureAccountHeader {
    pub bump: u8,
    pub purpose: ProofPurpose,
    pub status: ProofStatus,
    pub operation_id: KeyId,
    pub root: Address,
    pub uploader: Address,
    pub key_record: Address,
    pub digest: Digest,
    pub sequence: u64,
    pub valid_after_slot: u64,
    pub expires_slot: u64,
    pub signature_len: u16,
    pub written_len: u16,
    pub created_slot: u64,
}

impl SignatureAccountHeader {
    pub fn unpack(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != SIGNATURE_ACCOUNT_LEN
            || read_array::<8>(data, 0)? != SIGNATURE_MAGIC
            || data[8] != PROTOCOL_VERSION
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self {
            bump: data[9],
            purpose: ProofPurpose::try_from(data[10])?,
            status: ProofStatus::try_from(data[11])?,
            operation_id: read_array(data, 12)?,
            root: read_array(data, 28)?,
            uploader: read_array(data, 60)?,
            key_record: read_array(data, 92)?,
            digest: read_array(data, 124)?,
            sequence: read_u64(data, 156)?,
            valid_after_slot: read_u64(data, 164)?,
            expires_slot: read_u64(data, 172)?,
            signature_len: read_u16(data, 180)?,
            written_len: read_u16(data, 182)?,
            created_slot: read_u64(data, 184)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), CodecError> {
        if data.len() != SIGNATURE_ACCOUNT_LEN {
            return Err(CodecError::InvalidLength);
        }
        data[..SIGNATURE_HEADER_LEN].fill(0);
        write_array(data, 0, &SIGNATURE_MAGIC)?;
        data[8] = PROTOCOL_VERSION;
        data[9] = self.bump;
        data[10] = self.purpose as u8;
        data[11] = self.status as u8;
        write_array(data, 12, &self.operation_id)?;
        write_array(data, 28, &self.root)?;
        write_array(data, 60, &self.uploader)?;
        write_array(data, 92, &self.key_record)?;
        write_array(data, 124, &self.digest)?;
        write_u64(data, 156, self.sequence)?;
        write_u64(data, 164, self.valid_after_slot)?;
        write_u64(data, 172, self.expires_slot)?;
        write_u16(data, 180, self.signature_len)?;
        write_u16(data, 182, self.written_len)?;
        write_u64(data, 184, self.created_slot)?;
        Ok(())
    }

    pub fn signature<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], CodecError> {
        if self.signature_len as usize != ML_DSA_44_SIGNATURE_LEN
            || data.len() != SIGNATURE_ACCOUNT_LEN
        {
            return Err(CodecError::InvalidLength);
        }
        Ok(&data[SIGNATURE_HEADER_LEN..SIGNATURE_HEADER_LEN + ML_DSA_44_SIGNATURE_LEN])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultAccount {
    pub bump: u8,
    pub root: Address,
}

impl VaultAccount {
    pub fn unpack(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != VAULT_ACCOUNT_LEN
            || read_array::<8>(data, 0)? != VAULT_MAGIC
            || data[8] != PROTOCOL_VERSION
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self {
            bump: data[9],
            root: read_array(data, 10)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), CodecError> {
        if data.len() != VAULT_ACCOUNT_LEN {
            return Err(CodecError::InvalidLength);
        }
        data.fill(0);
        write_array(data, 0, &VAULT_MAGIC)?;
        data[8] = PROTOCOL_VERSION;
        data[9] = self.bump;
        write_array(data, 10, &self.root)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermitAccount {
    pub bump: u8,
    pub status: PermitStatus,
    pub action: ActionKind,
    pub root: Address,
    pub vault: Address,
    pub refund: Address,
    pub digest: Digest,
    pub sequence: u64,
    pub valid_after_slot: u64,
    pub expires_slot: u64,
    pub created_slot: u64,
}

impl PermitAccount {
    pub fn unpack(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != PERMIT_ACCOUNT_LEN
            || read_array::<8>(data, 0)? != PERMIT_MAGIC
            || data[8] != PROTOCOL_VERSION
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self {
            bump: data[9],
            status: PermitStatus::try_from(data[10])?,
            action: ActionKind::try_from(data[11])?,
            root: read_array(data, 12)?,
            vault: read_array(data, 44)?,
            refund: read_array(data, 76)?,
            digest: read_array(data, 108)?,
            sequence: read_u64(data, 140)?,
            valid_after_slot: read_u64(data, 148)?,
            expires_slot: read_u64(data, 156)?,
            created_slot: read_u64(data, 164)?,
        })
    }

    pub fn pack(&self, data: &mut [u8]) -> Result<(), CodecError> {
        if data.len() != PERMIT_ACCOUNT_LEN {
            return Err(CodecError::InvalidLength);
        }
        data.fill(0);
        write_array(data, 0, &PERMIT_MAGIC)?;
        data[8] = PROTOCOL_VERSION;
        data[9] = self.bump;
        data[10] = self.status as u8;
        data[11] = self.action as u8;
        write_array(data, 12, &self.root)?;
        write_array(data, 44, &self.vault)?;
        write_array(data, 76, &self.refund)?;
        write_array(data, 108, &self.digest)?;
        write_u64(data, 140, self.sequence)?;
        write_u64(data, 148, self.valid_after_slot)?;
        write_u64(data, 156, self.expires_slot)?;
        write_u64(data, 164, self.created_slot)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_round_trip() {
        let root = RootAccount {
            bump: 7,
            status: RootStatus::Sealed,
            scheme: Scheme::MlDsa44,
            flags: 1,
            legacy_address: [1; 32],
            chain_id: [2; 32],
            current_key: [3; 32],
            current_key_hash: [4; 32],
            generation: 9,
            sequence: 10,
            created_slot: 11,
            sealed_slot: 12,
        };
        let mut data = [0u8; ROOT_ACCOUNT_LEN];
        root.pack(&mut data).unwrap();
        assert_eq!(RootAccount::unpack(&data).unwrap(), root);
    }

    #[test]
    fn account_sizes_are_stable() {
        assert_eq!(KEY_ACCOUNT_LEN, 1_472);
        assert_eq!(SIGNATURE_ACCOUNT_LEN, 2_612);
        assert_eq!(PERMIT_ACCOUNT_LEN, 192);
        assert_eq!(VAULT_ACCOUNT_LEN, 64);
    }
}
