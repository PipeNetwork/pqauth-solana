//! Off-chain PDA, digest, and instruction builders for the PQAuth program.

use core::fmt;

use pqauth_core::{
    execute_cpi_preimage, execute_lamports_preimage, key_pop_preimage, rotate_preimage,
    seal_preimage, ActionKind, CpiMetaDigest, KeyId, PqAuthInstruction, ProofPurpose, Scheme,
    KEY_SEED, MAX_CPI_DATA, MAX_CPI_METAS, MAX_UPLOAD_CHUNK, META_SIGNER, META_WRITABLE,
    PERMIT_SEED, ROOT_SEED, SIGNATURE_SEED, VAULT_SEED,
};
use sha2::{Digest as ShaDigest, Sha256};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_system_interface::program as system_program;

pub const PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("8RRuQaeSmnYJJkkC2qAYNnNbzjW3eCexQSUbpHZVJv9U");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    EmptyUpload,
    UploadTooLarge,
    TooManyAccounts,
    InstructionDataTooLarge,
    NonVaultSigner,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyUpload => f.write_str("upload chunk is empty"),
            Self::UploadTooLarge => f.write_str("upload chunk exceeds MAX_UPLOAD_CHUNK"),
            Self::TooManyAccounts => f.write_str("too many CPI account metas"),
            Self::InstructionDataTooLarge => f.write_str("CPI instruction data is too large"),
            Self::NonVaultSigner => f.write_str("only the vault PDA may be elevated as a CPI signer"),
        }
    }
}

impl std::error::Error for BuildError {}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn root_address(legacy: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ROOT_SEED, legacy.as_ref()], &PROGRAM_ID)
}

pub fn key_address(root: &Pubkey, generation: u32, key_id: &KeyId) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[KEY_SEED, root.as_ref(), &generation.to_le_bytes(), key_id],
        &PROGRAM_ID,
    )
}

pub fn signature_address(root: &Pubkey, operation_id: &KeyId) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SIGNATURE_SEED, root.as_ref(), operation_id],
        &PROGRAM_ID,
    )
}

pub fn vault_address(root: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[VAULT_SEED, root.as_ref()], &PROGRAM_ID)
}

pub fn permit_address(root: &Pubkey, sequence: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[PERMIT_SEED, root.as_ref(), &sequence.to_le_bytes()],
        &PROGRAM_ID,
    )
}

pub fn key_pop_digest(
    chain_id: &[u8; 32],
    root: &Pubkey,
    generation: u32,
    key_id: &KeyId,
    public_key: &[u8],
) -> [u8; 32] {
    let key_hash = sha256(public_key);
    sha256(&key_pop_preimage(
        &PROGRAM_ID.to_bytes(),
        chain_id,
        &root.to_bytes(),
        generation,
        key_id,
        Scheme::MlDsa44 as u8,
        &key_hash,
    ))
}

pub fn seal_digest(
    chain_id: &[u8; 32],
    root: &Pubkey,
    sequence: u64,
    key_record: &Pubkey,
    key_hash: &[u8; 32],
) -> [u8; 32] {
    sha256(&seal_preimage(
        &PROGRAM_ID.to_bytes(),
        chain_id,
        &root.to_bytes(),
        sequence,
        &key_record.to_bytes(),
        key_hash,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn rotate_digest(
    chain_id: &[u8; 32],
    root: &Pubkey,
    sequence: u64,
    old_key: &Pubkey,
    old_key_hash: &[u8; 32],
    new_key: &Pubkey,
    new_key_hash: &[u8; 32],
    new_generation: u32,
) -> [u8; 32] {
    sha256(&rotate_preimage(
        &PROGRAM_ID.to_bytes(),
        chain_id,
        &root.to_bytes(),
        sequence,
        &old_key.to_bytes(),
        old_key_hash,
        &new_key.to_bytes(),
        new_key_hash,
        new_generation,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn cpi_digest(
    chain_id: &[u8; 32],
    root: &Pubkey,
    vault: &Pubkey,
    sequence: u64,
    valid_after_slot: u64,
    expires_slot: u64,
    target_program: &Pubkey,
    target_accounts: &[AccountMeta],
    instruction_data: &[u8],
) -> Result<[u8; 32], BuildError> {
    if target_accounts.len() > MAX_CPI_METAS {
        return Err(BuildError::TooManyAccounts);
    }
    if instruction_data.len() > MAX_CPI_DATA {
        return Err(BuildError::InstructionDataTooLarge);
    }
    let digest_metas = target_accounts
        .iter()
        .map(|meta| {
            if meta.is_signer && meta.pubkey != *vault {
                return Err(BuildError::NonVaultSigner);
            }
            let mut flags = 0u8;
            if meta.is_writable {
                flags |= META_WRITABLE;
            }
            if meta.is_signer {
                flags |= META_SIGNER;
            }
            Ok(CpiMetaDigest {
                address: meta.pubkey.to_bytes(),
                flags,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(sha256(&execute_cpi_preimage(
        &PROGRAM_ID.to_bytes(),
        chain_id,
        &root.to_bytes(),
        &vault.to_bytes(),
        sequence,
        valid_after_slot,
        expires_slot,
        &target_program.to_bytes(),
        &digest_metas,
        instruction_data,
    )))
}

#[allow(clippy::too_many_arguments)]
pub fn lamports_digest(
    chain_id: &[u8; 32],
    root: &Pubkey,
    vault: &Pubkey,
    sequence: u64,
    valid_after_slot: u64,
    expires_slot: u64,
    recipient: &Pubkey,
    amount: u64,
) -> [u8; 32] {
    sha256(&execute_lamports_preimage(
        &PROGRAM_ID.to_bytes(),
        chain_id,
        &root.to_bytes(),
        &vault.to_bytes(),
        sequence,
        valid_after_slot,
        expires_slot,
        &recipient.to_bytes(),
        amount,
    ))
}

fn instruction(accounts: Vec<AccountMeta>, data: PqAuthInstruction) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data: data.pack(),
    }
}

pub fn initialize_root(legacy: Pubkey, payer: Pubkey, chain_id: [u8; 32]) -> Instruction {
    let (root, _) = root_address(&legacy);
    instruction(
        vec![
            AccountMeta::new_readonly(legacy, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(root, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        PqAuthInstruction::InitializeRoot { chain_id },
    )
}

pub fn initialize_key(
    uploader: Pubkey,
    payer: Pubkey,
    root: Pubkey,
    generation: u32,
    key_id: KeyId,
) -> Instruction {
    let (key, _) = key_address(&root, generation, &key_id);
    instruction(
        vec![
            AccountMeta::new_readonly(uploader, true),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(root, false),
            AccountMeta::new(key, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        PqAuthInstruction::InitializeKey {
            generation,
            key_id,
            scheme: Scheme::MlDsa44,
        },
    )
}

pub fn write_key(uploader: Pubkey, key: Pubkey, offset: u16, bytes: Vec<u8>) -> Result<Instruction, BuildError> {
    validate_chunk(&bytes)?;
    Ok(instruction(
        vec![
            AccountMeta::new_readonly(uploader, true),
            AccountMeta::new(key, false),
        ],
        PqAuthInstruction::WriteKey { offset, bytes },
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn initialize_signature(
    uploader: Pubkey,
    payer: Pubkey,
    root: Pubkey,
    key: Pubkey,
    purpose: ProofPurpose,
    operation_id: KeyId,
    digest: [u8; 32],
    sequence: u64,
    valid_after_slot: u64,
    expires_slot: u64,
) -> Instruction {
    let (signature, _) = signature_address(&root, &operation_id);
    instruction(
        vec![
            AccountMeta::new_readonly(uploader, true),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(root, false),
            AccountMeta::new_readonly(key, false),
            AccountMeta::new(signature, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        PqAuthInstruction::InitializeSignature {
            purpose,
            operation_id,
            digest,
            sequence,
            valid_after_slot,
            expires_slot,
        },
    )
}

pub fn write_signature(
    uploader: Pubkey,
    signature: Pubkey,
    offset: u16,
    bytes: Vec<u8>,
) -> Result<Instruction, BuildError> {
    validate_chunk(&bytes)?;
    Ok(instruction(
        vec![
            AccountMeta::new_readonly(uploader, true),
            AccountMeta::new(signature, false),
        ],
        PqAuthInstruction::WriteSignature { offset, bytes },
    ))
}

pub fn finalize_key(root: Pubkey, key: Pubkey, signature: Pubkey) -> Instruction {
    instruction(
        vec![
            AccountMeta::new_readonly(root, false),
            AccountMeta::new(key, false),
            AccountMeta::new(signature, false),
        ],
        PqAuthInstruction::FinalizeKey,
    )
}

pub fn activate_initial_key(legacy: Pubkey, root: Pubkey, key: Pubkey) -> Instruction {
    instruction(
        vec![
            AccountMeta::new_readonly(legacy, true),
            AccountMeta::new(root, false),
            AccountMeta::new_readonly(key, false),
        ],
        PqAuthInstruction::ActivateInitialKey,
    )
}

pub fn seal(legacy: Pubkey, root: Pubkey, key: Pubkey, signature: Pubkey) -> Instruction {
    instruction(
        vec![
            AccountMeta::new_readonly(legacy, true),
            AccountMeta::new(root, false),
            AccountMeta::new_readonly(key, false),
            AccountMeta::new(signature, false),
        ],
        PqAuthInstruction::Seal,
    )
}

pub fn rotate(root: Pubkey, current_key: Pubkey, next_key: Pubkey, signature: Pubkey) -> Instruction {
    instruction(
        vec![
            AccountMeta::new(root, false),
            AccountMeta::new_readonly(current_key, false),
            AccountMeta::new_readonly(next_key, false),
            AccountMeta::new(signature, false),
        ],
        PqAuthInstruction::Rotate,
    )
}

pub fn create_vault(payer: Pubkey, root: Pubkey) -> Instruction {
    let (vault, _) = vault_address(&root);
    instruction(
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(root, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        PqAuthInstruction::CreateVault,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn authorize(
    payer: Pubkey,
    root: Pubkey,
    key: Pubkey,
    signature: Pubkey,
    vault: Pubkey,
    sequence: u64,
    action: ActionKind,
) -> Instruction {
    let (permit, _) = permit_address(&root, sequence);
    instruction(
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(root, false),
            AccountMeta::new_readonly(key, false),
            AccountMeta::new(signature, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(permit, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        PqAuthInstruction::Authorize { action },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_cpi(
    root: Pubkey,
    vault: Pubkey,
    permit: Pubkey,
    refund: Pubkey,
    target_program: Pubkey,
    target_accounts: Vec<AccountMeta>,
    instruction_data: Vec<u8>,
) -> Result<Instruction, BuildError> {
    if target_accounts.len() > MAX_CPI_METAS {
        return Err(BuildError::TooManyAccounts);
    }
    if instruction_data.len() > MAX_CPI_DATA {
        return Err(BuildError::InstructionDataTooLarge);
    }
    let mut flags = Vec::with_capacity(target_accounts.len());
    for meta in &target_accounts {
        if meta.is_signer && meta.pubkey != vault {
            return Err(BuildError::NonVaultSigner);
        }
        let mut value = 0u8;
        if meta.is_writable {
            value |= META_WRITABLE;
        }
        if meta.is_signer {
            value |= META_SIGNER;
        }
        flags.push(value);
    }
    let mut accounts = vec![
        AccountMeta::new_readonly(root, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(permit, false),
        AccountMeta::new(refund, false),
        AccountMeta::new_readonly(target_program, false),
    ];
    accounts.extend(target_accounts);
    Ok(instruction(
        accounts,
        PqAuthInstruction::ExecuteCpi {
            meta_flags: flags,
            instruction_data,
        },
    ))
}

pub fn execute_lamports(
    root: Pubkey,
    vault: Pubkey,
    permit: Pubkey,
    refund: Pubkey,
    recipient: Pubkey,
    amount: u64,
) -> Instruction {
    instruction(
        vec![
            AccountMeta::new_readonly(root, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(permit, false),
            AccountMeta::new(refund, false),
            AccountMeta::new(recipient, false),
        ],
        PqAuthInstruction::ExecuteLamports { amount },
    )
}

pub fn close_signature(uploader: Pubkey, signature: Pubkey) -> Instruction {
    instruction(
        vec![
            AccountMeta::new_readonly(uploader, true),
            AccountMeta::new(signature, false),
            AccountMeta::new(uploader, false),
        ],
        PqAuthInstruction::CloseSignature,
    )
}

pub fn close_permit(permit: Pubkey, refund: Pubkey) -> Instruction {
    instruction(
        vec![AccountMeta::new(permit, false), AccountMeta::new(refund, false)],
        PqAuthInstruction::ClosePermit,
    )
}

pub fn close_key(uploader: Pubkey, key: Pubkey) -> Instruction {
    instruction(
        vec![
            AccountMeta::new_readonly(uploader, true),
            AccountMeta::new(key, false),
            AccountMeta::new(uploader, false),
        ],
        PqAuthInstruction::CloseKey,
    )
}

pub fn upload_chunks(bytes: &[u8]) -> impl Iterator<Item = (u16, Vec<u8>)> + '_ {
    bytes.chunks(MAX_UPLOAD_CHUNK).enumerate().map(|(index, chunk)| {
        ((index * MAX_UPLOAD_CHUNK) as u16, chunk.to_vec())
    })
}

fn validate_chunk(bytes: &[u8]) -> Result<(), BuildError> {
    if bytes.is_empty() {
        return Err(BuildError::EmptyUpload);
    }
    if bytes.len() > MAX_UPLOAD_CHUNK {
        return Err(BuildError::UploadTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pda_helpers_are_deterministic() {
        let legacy = Pubkey::new_from_array([7; 32]);
        let (root_a, _) = root_address(&legacy);
        let (root_b, _) = root_address(&legacy);
        assert_eq!(root_a, root_b);
        let (key_a, _) = key_address(&root_a, 0, &[3; 16]);
        let (key_b, _) = key_address(&root_a, 0, &[3; 16]);
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn upload_chunking_is_append_only() {
        let bytes = vec![1u8; 2_420];
        let chunks: Vec<_> = upload_chunks(&bytes).collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[1].0, 900);
        assert_eq!(chunks[2].0, 1_800);
        assert_eq!(chunks.iter().map(|(_, b)| b.len()).sum::<usize>(), 2_420);
    }
}
