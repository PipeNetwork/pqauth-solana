use std::vec::Vec;

use pqauth_core::{
    execute_cpi_preimage, execute_lamports_preimage, key_pop_preimage, rotate_preimage,
    seal_preimage, ActionKind, Address, CpiMetaDigest, KeyAccountHeader, KeyStatus,
    PermitAccount, PermitStatus, PqAuthInstruction, ProofPurpose, ProofStatus, RootAccount,
    RootStatus, Scheme, SignatureAccountHeader, VaultAccount, KEY_ACCOUNT_LEN, KEY_HEADER_LEN,
    KEY_SEED, MAX_PERMIT_LIFETIME_SLOTS, META_SIGNER, META_WRITABLE,
    ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SIGNATURE_LEN, PERMIT_ACCOUNT_LEN, PERMIT_SEED,
    ROOT_ACCOUNT_LEN, ROOT_FLAG_ED25519_DISABLED, ROOT_SEED, SIGNATURE_ACCOUNT_LEN,
    SIGNATURE_HEADER_LEN, SIGNATURE_SEED, VAULT_ACCOUNT_LEN, VAULT_SEED,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::{clock::Clock, rent::Rent, Sysvar},
};
use solana_system_interface::{
    instruction::{allocate, assign, transfer},
    program as system_program,
};

use crate::{
    crypto::{sha256, verify_ml_dsa_44},
    error::PqAuthError,
};

pub struct Processor;

impl Processor {
    pub fn process(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let instruction = PqAuthInstruction::unpack(instruction_data)
            .map_err(|_| PqAuthError::InvalidInstruction)?;

        match instruction {
            PqAuthInstruction::InitializeRoot { chain_id } => {
                Self::initialize_root(program_id, accounts, chain_id)
            }
            PqAuthInstruction::InitializeKey {
                generation,
                key_id,
                scheme,
            } => Self::initialize_key(program_id, accounts, generation, key_id, scheme),
            PqAuthInstruction::WriteKey { offset, bytes } => {
                Self::write_key(program_id, accounts, offset, &bytes)
            }
            PqAuthInstruction::InitializeSignature {
                purpose,
                operation_id,
                digest,
                sequence,
                valid_after_slot,
                expires_slot,
            } => Self::initialize_signature(
                program_id,
                accounts,
                purpose,
                operation_id,
                digest,
                sequence,
                valid_after_slot,
                expires_slot,
            ),
            PqAuthInstruction::WriteSignature { offset, bytes } => {
                Self::write_signature(program_id, accounts, offset, &bytes)
            }
            PqAuthInstruction::FinalizeKey => Self::finalize_key(program_id, accounts),
            PqAuthInstruction::ActivateInitialKey => {
                Self::activate_initial_key(program_id, accounts)
            }
            PqAuthInstruction::Seal => Self::seal(program_id, accounts),
            PqAuthInstruction::Rotate => Self::rotate(program_id, accounts),
            PqAuthInstruction::CreateVault => Self::create_vault(program_id, accounts),
            PqAuthInstruction::Authorize { action } => {
                Self::authorize(program_id, accounts, action)
            }
            PqAuthInstruction::ExecuteCpi {
                meta_flags,
                instruction_data,
            } => Self::execute_cpi(
                program_id,
                accounts,
                &meta_flags,
                &instruction_data,
            ),
            PqAuthInstruction::ExecuteLamports { amount } => {
                Self::execute_lamports(program_id, accounts, amount)
            }
            PqAuthInstruction::CloseSignature => {
                Self::close_signature(program_id, accounts)
            }
            PqAuthInstruction::ClosePermit => Self::close_permit(program_id, accounts),
            PqAuthInstruction::CloseKey => Self::close_key(program_id, accounts),
        }
    }

    fn initialize_root(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        chain_id: [u8; 32],
    ) -> ProgramResult {
        let mut iter = accounts.iter();
        let legacy = next_account_info(&mut iter)?;
        let payer = next_account_info(&mut iter)?;
        let root_info = next_account_info(&mut iter)?;
        let system = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(legacy)?;
        require_signer(payer)?;
        require_writable(payer)?;
        require_writable(root_info)?;
        require_system_program(system)?;
        if chain_id == [0; 32] {
            return Err(PqAuthError::InvalidAccount.into());
        }

        let (expected, bump) =
            Pubkey::find_program_address(&[ROOT_SEED, legacy.key.as_ref()], program_id);
        if expected != *root_info.key {
            return Err(PqAuthError::InvalidPda.into());
        }
        let bump_seed = [bump];
        create_pda_account(
            program_id,
            payer,
            root_info,
            system,
            ROOT_ACCOUNT_LEN,
            &[ROOT_SEED, legacy.key.as_ref(), &bump_seed],
        )?;

        let state = RootAccount {
            bump,
            status: RootStatus::Unsealed,
            scheme: Scheme::MlDsa44,
            flags: 0,
            legacy_address: address(legacy.key),
            chain_id,
            current_key: [0; 32],
            current_key_hash: [0; 32],
            generation: 0,
            sequence: 0,
            created_slot: Clock::get()?.slot,
            sealed_slot: 0,
        };
        state
            .pack(&mut root_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        Ok(())
    }

    fn initialize_key(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        generation: u32,
        key_id: [u8; 16],
        scheme: Scheme,
    ) -> ProgramResult {
        let mut iter = accounts.iter();
        let uploader = next_account_info(&mut iter)?;
        let payer = next_account_info(&mut iter)?;
        let root_info = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        let system = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(uploader)?;
        require_signer(payer)?;
        require_writable(payer)?;
        require_writable(key_info)?;
        require_system_program(system)?;
        if scheme != Scheme::MlDsa44 {
            return Err(PqAuthError::UnsupportedScheme.into());
        }

        let root = load_root(program_id, root_info)?;
        match root.status {
            RootStatus::Unsealed if generation == 0 => {}
            RootStatus::Sealed if generation == root.generation.saturating_add(1) => {}
            _ => return Err(PqAuthError::WrongState.into()),
        }

        let generation_bytes = generation.to_le_bytes();
        let (expected, bump) = Pubkey::find_program_address(
            &[KEY_SEED, root_info.key.as_ref(), &generation_bytes, &key_id],
            program_id,
        );
        if expected != *key_info.key {
            return Err(PqAuthError::InvalidPda.into());
        }
        let bump_seed = [bump];
        create_pda_account(
            program_id,
            payer,
            key_info,
            system,
            KEY_ACCOUNT_LEN,
            &[
                KEY_SEED,
                root_info.key.as_ref(),
                &generation_bytes,
                &key_id,
                &bump_seed,
            ],
        )?;

        let header = KeyAccountHeader {
            bump,
            scheme,
            status: KeyStatus::Uploading,
            generation,
            key_id,
            root: address(root_info.key),
            uploader: address(uploader.key),
            key_hash: [0; 32],
            key_len: ML_DSA_44_PUBLIC_KEY_LEN as u16,
            written_len: 0,
            created_slot: Clock::get()?.slot,
            finalized_slot: 0,
        };
        header
            .pack(&mut key_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        Ok(())
    }

    fn write_key(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        offset: u16,
        bytes: &[u8],
    ) -> ProgramResult {
        let mut iter = accounts.iter();
        let uploader = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(uploader)?;
        require_writable(key_info)?;
        let mut data = key_info.try_borrow_mut_data()?;
        if key_info.owner != program_id {
            return Err(PqAuthError::InvalidOwner.into());
        }
        let mut header =
            KeyAccountHeader::unpack(&data).map_err(|_| PqAuthError::InvalidAccount)?;
        verify_key_pda(program_id, key_info, &header)?;
        if header.uploader != address(uploader.key) {
            return Err(PqAuthError::Unauthorized.into());
        }
        if header.status != KeyStatus::Uploading {
            return Err(PqAuthError::WrongState.into());
        }
        if offset != header.written_len {
            return Err(PqAuthError::UploadOffset.into());
        }
        let end = (offset as usize)
            .checked_add(bytes.len())
            .ok_or(PqAuthError::ArithmeticOverflow)?;
        if end > header.key_len as usize || bytes.is_empty() {
            return Err(PqAuthError::InvalidInstruction.into());
        }
        data[KEY_HEADER_LEN + offset as usize..KEY_HEADER_LEN + end].copy_from_slice(bytes);
        header.written_len = end as u16;
        header
            .pack(&mut data)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn initialize_signature(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        purpose: ProofPurpose,
        operation_id: [u8; 16],
        supplied_digest: [u8; 32],
        sequence: u64,
        valid_after_slot: u64,
        expires_slot: u64,
    ) -> ProgramResult {
        let mut iter = accounts.iter();
        let uploader = next_account_info(&mut iter)?;
        let payer = next_account_info(&mut iter)?;
        let root_info = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        let signature_info = next_account_info(&mut iter)?;
        let system = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(uploader)?;
        require_signer(payer)?;
        require_writable(payer)?;
        require_writable(signature_info)?;
        require_system_program(system)?;

        let root = load_root(program_id, root_info)?;
        let key = load_key(program_id, key_info)?;
        if key.root != address(root_info.key) {
            return Err(PqAuthError::InvalidAccount.into());
        }

        let expected_digest = match purpose {
            ProofPurpose::KeyPossession => {
                if key.status != KeyStatus::Uploading
                    || key.written_len != key.key_len
                    || sequence != 0
                    || valid_after_slot != 0
                    || expires_slot != 0
                {
                    return Err(PqAuthError::WrongState.into());
                }
                let key_hash = hash_key_bytes(key_info, &key)?;
                sha256(&key_pop_preimage(
                    &address(program_id),
                    &root.chain_id,
                    &address(root_info.key),
                    key.generation,
                    &key.key_id,
                    key.scheme as u8,
                    &key_hash,
                ))
            }
            ProofPurpose::Seal => {
                require_active_key(&root, key_info, &key)?;
                if root.status != RootStatus::Unsealed
                    || sequence != root.sequence
                    || valid_after_slot != 0
                    || expires_slot != 0
                {
                    return Err(PqAuthError::WrongState.into());
                }
                sha256(&seal_preimage(
                    &address(program_id),
                    &root.chain_id,
                    &address(root_info.key),
                    sequence,
                    &address(key_info.key),
                    &key.key_hash,
                ))
            }
            ProofPurpose::Rotate => {
                require_active_key(&root, key_info, &key)?;
                if root.status != RootStatus::Sealed
                    || sequence != root.sequence
                    || valid_after_slot != 0
                    || expires_slot != 0
                {
                    return Err(PqAuthError::WrongState.into());
                }
                supplied_digest
            }
            ProofPurpose::Authorize => {
                require_active_key(&root, key_info, &key)?;
                if root.status != RootStatus::Sealed || sequence != root.sequence {
                    return Err(PqAuthError::WrongState.into());
                }
                validate_lifetime(valid_after_slot, expires_slot, Clock::get()?.slot)?;
                supplied_digest
            }
        };
        if expected_digest != supplied_digest {
            return Err(PqAuthError::DigestMismatch.into());
        }

        let (expected, bump) = Pubkey::find_program_address(
            &[SIGNATURE_SEED, root_info.key.as_ref(), &operation_id],
            program_id,
        );
        if expected != *signature_info.key {
            return Err(PqAuthError::InvalidPda.into());
        }
        let bump_seed = [bump];
        create_pda_account(
            program_id,
            payer,
            signature_info,
            system,
            SIGNATURE_ACCOUNT_LEN,
            &[
                SIGNATURE_SEED,
                root_info.key.as_ref(),
                &operation_id,
                &bump_seed,
            ],
        )?;

        let header = SignatureAccountHeader {
            bump,
            purpose,
            status: ProofStatus::Uploading,
            operation_id,
            root: address(root_info.key),
            uploader: address(uploader.key),
            key_record: address(key_info.key),
            digest: supplied_digest,
            sequence,
            valid_after_slot,
            expires_slot,
            signature_len: ML_DSA_44_SIGNATURE_LEN as u16,
            written_len: 0,
            created_slot: Clock::get()?.slot,
        };
        header
            .pack(&mut signature_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        Ok(())
    }

    fn write_signature(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        offset: u16,
        bytes: &[u8],
    ) -> ProgramResult {
        let mut iter = accounts.iter();
        let uploader = next_account_info(&mut iter)?;
        let signature_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(uploader)?;
        require_writable(signature_info)?;
        if signature_info.owner != program_id {
            return Err(PqAuthError::InvalidOwner.into());
        }
        let mut data = signature_info.try_borrow_mut_data()?;
        let mut header = SignatureAccountHeader::unpack(&data)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        verify_signature_pda(program_id, signature_info, &header)?;
        if header.uploader != address(uploader.key) {
            return Err(PqAuthError::Unauthorized.into());
        }
        if header.status != ProofStatus::Uploading {
            return Err(PqAuthError::WrongState.into());
        }
        if offset != header.written_len {
            return Err(PqAuthError::UploadOffset.into());
        }
        let end = (offset as usize)
            .checked_add(bytes.len())
            .ok_or(PqAuthError::ArithmeticOverflow)?;
        if end > header.signature_len as usize || bytes.is_empty() {
            return Err(PqAuthError::InvalidInstruction.into());
        }
        data[SIGNATURE_HEADER_LEN + offset as usize..SIGNATURE_HEADER_LEN + end]
            .copy_from_slice(bytes);
        header.written_len = end as u16;
        if header.written_len == header.signature_len {
            header.status = ProofStatus::Ready;
        }
        header
            .pack(&mut data)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        Ok(())
    }

    fn finalize_key(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let root_info = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        let signature_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_writable(key_info)?;
        require_writable(signature_info)?;
        let root = load_root(program_id, root_info)?;
        let mut key = load_key(program_id, key_info)?;
        let proof = load_signature(program_id, signature_info)?;
        if key.root != address(root_info.key)
            || key.status != KeyStatus::Uploading
            || key.written_len != key.key_len
            || proof.root != address(root_info.key)
            || proof.key_record != address(key_info.key)
            || proof.purpose != ProofPurpose::KeyPossession
            || proof.status != ProofStatus::Ready
            || proof.sequence != 0
        {
            return Err(PqAuthError::WrongState.into());
        }

        let key_hash = hash_key_bytes(key_info, &key)?;
        let expected_digest = sha256(&key_pop_preimage(
            &address(program_id),
            &root.chain_id,
            &address(root_info.key),
            key.generation,
            &key.key_id,
            key.scheme as u8,
            &key_hash,
        ));
        if proof.digest != expected_digest {
            return Err(PqAuthError::DigestMismatch.into());
        }
        verify_proof_bytes(key_info, &key, signature_info, &proof, &expected_digest)?;

        key.key_hash = key_hash;
        key.status = KeyStatus::Finalized;
        key.finalized_slot = Clock::get()?.slot;
        key.pack(&mut key_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        consume_signature(signature_info, proof)?;
        Ok(())
    }

    fn activate_initial_key(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let legacy = next_account_info(&mut iter)?;
        let root_info = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(legacy)?;
        require_writable(root_info)?;
        let mut root = load_root(program_id, root_info)?;
        let key = load_key(program_id, key_info)?;
        if root.status != RootStatus::Unsealed
            || root.legacy_address != address(legacy.key)
            || key.root != address(root_info.key)
            || key.status != KeyStatus::Finalized
            || key.generation != 0
        {
            return Err(PqAuthError::Unauthorized.into());
        }
        root.current_key = address(key_info.key);
        root.current_key_hash = key.key_hash;
        root.generation = 0;
        root.pack(&mut root_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        Ok(())
    }

    fn seal(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let legacy = next_account_info(&mut iter)?;
        let root_info = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        let signature_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(legacy)?;
        require_writable(root_info)?;
        require_writable(signature_info)?;
        let mut root = load_root(program_id, root_info)?;
        let key = load_key(program_id, key_info)?;
        let proof = load_signature(program_id, signature_info)?;
        if root.status != RootStatus::Unsealed || root.legacy_address != address(legacy.key) {
            return Err(PqAuthError::Unauthorized.into());
        }
        require_active_key(&root, key_info, &key)?;
        let expected_digest = sha256(&seal_preimage(
            &address(program_id),
            &root.chain_id,
            &address(root_info.key),
            root.sequence,
            &address(key_info.key),
            &key.key_hash,
        ));
        require_proof_header(
            &proof,
            root_info,
            key_info,
            ProofPurpose::Seal,
            root.sequence,
            &expected_digest,
        )?;
        verify_proof_bytes(key_info, &key, signature_info, &proof, &expected_digest)?;

        root.status = RootStatus::Sealed;
        root.flags |= ROOT_FLAG_ED25519_DISABLED;
        root.sealed_slot = Clock::get()?.slot;
        root.sequence = root
            .sequence
            .checked_add(1)
            .ok_or(PqAuthError::ArithmeticOverflow)?;
        root.pack(&mut root_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        consume_signature(signature_info, proof)?;
        Ok(())
    }

    fn rotate(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let root_info = next_account_info(&mut iter)?;
        let current_key_info = next_account_info(&mut iter)?;
        let next_key_info = next_account_info(&mut iter)?;
        let signature_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_writable(root_info)?;
        require_writable(signature_info)?;
        let mut root = load_root(program_id, root_info)?;
        let current_key = load_key(program_id, current_key_info)?;
        let next_key = load_key(program_id, next_key_info)?;
        let proof = load_signature(program_id, signature_info)?;
        if root.status != RootStatus::Sealed {
            return Err(PqAuthError::WrongState.into());
        }
        require_active_key(&root, current_key_info, &current_key)?;
        if next_key.root != address(root_info.key)
            || next_key.status != KeyStatus::Finalized
            || next_key.generation
                != root
                    .generation
                    .checked_add(1)
                    .ok_or(PqAuthError::ArithmeticOverflow)?
        {
            return Err(PqAuthError::InvalidKey.into());
        }

        let expected_digest = sha256(&rotate_preimage(
            &address(program_id),
            &root.chain_id,
            &address(root_info.key),
            root.sequence,
            &address(current_key_info.key),
            &current_key.key_hash,
            &address(next_key_info.key),
            &next_key.key_hash,
            next_key.generation,
        ));
        require_proof_header(
            &proof,
            root_info,
            current_key_info,
            ProofPurpose::Rotate,
            root.sequence,
            &expected_digest,
        )?;
        verify_proof_bytes(
            current_key_info,
            &current_key,
            signature_info,
            &proof,
            &expected_digest,
        )?;

        root.current_key = address(next_key_info.key);
        root.current_key_hash = next_key.key_hash;
        root.generation = next_key.generation;
        root.sequence = root
            .sequence
            .checked_add(1)
            .ok_or(PqAuthError::ArithmeticOverflow)?;
        root.pack(&mut root_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        consume_signature(signature_info, proof)?;
        Ok(())
    }

    fn create_vault(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let payer = next_account_info(&mut iter)?;
        let root_info = next_account_info(&mut iter)?;
        let vault_info = next_account_info(&mut iter)?;
        let system = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(payer)?;
        require_writable(payer)?;
        require_writable(vault_info)?;
        require_system_program(system)?;
        let root = load_root(program_id, root_info)?;
        if root.status != RootStatus::Sealed {
            return Err(PqAuthError::WrongState.into());
        }

        let (expected, bump) =
            Pubkey::find_program_address(&[VAULT_SEED, root_info.key.as_ref()], program_id);
        if expected != *vault_info.key {
            return Err(PqAuthError::InvalidPda.into());
        }
        let bump_seed = [bump];
        create_pda_account(
            program_id,
            payer,
            vault_info,
            system,
            VAULT_ACCOUNT_LEN,
            &[VAULT_SEED, root_info.key.as_ref(), &bump_seed],
        )?;
        VaultAccount {
            bump,
            root: address(root_info.key),
        }
        .pack(&mut vault_info.try_borrow_mut_data()?)
        .map_err(|_| PqAuthError::InvalidAccount)?;
        Ok(())
    }

    fn authorize(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        action: ActionKind,
    ) -> ProgramResult {
        let mut iter = accounts.iter();
        let payer = next_account_info(&mut iter)?;
        let root_info = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        let signature_info = next_account_info(&mut iter)?;
        let vault_info = next_account_info(&mut iter)?;
        let permit_info = next_account_info(&mut iter)?;
        let system = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(payer)?;
        require_writable(payer)?;
        require_writable(root_info)?;
        require_writable(signature_info)?;
        require_writable(permit_info)?;
        require_system_program(system)?;

        let mut root = load_root(program_id, root_info)?;
        let key = load_key(program_id, key_info)?;
        let proof = load_signature(program_id, signature_info)?;
        let vault = load_vault(program_id, vault_info)?;
        if root.status != RootStatus::Sealed || vault.root != address(root_info.key) {
            return Err(PqAuthError::WrongState.into());
        }
        require_active_key(&root, key_info, &key)?;
        require_proof_header(
            &proof,
            root_info,
            key_info,
            ProofPurpose::Authorize,
            root.sequence,
            &proof.digest,
        )?;
        validate_lifetime(
            proof.valid_after_slot,
            proof.expires_slot,
            Clock::get()?.slot,
        )?;
        verify_proof_bytes(key_info, &key, signature_info, &proof, &proof.digest)?;

        let sequence_bytes = root.sequence.to_le_bytes();
        let (expected, bump) = Pubkey::find_program_address(
            &[PERMIT_SEED, root_info.key.as_ref(), &sequence_bytes],
            program_id,
        );
        if expected != *permit_info.key {
            return Err(PqAuthError::InvalidPda.into());
        }
        let bump_seed = [bump];
        create_pda_account(
            program_id,
            payer,
            permit_info,
            system,
            PERMIT_ACCOUNT_LEN,
            &[
                PERMIT_SEED,
                root_info.key.as_ref(),
                &sequence_bytes,
                &bump_seed,
            ],
        )?;
        PermitAccount {
            bump,
            status: PermitStatus::Ready,
            action,
            root: address(root_info.key),
            vault: address(vault_info.key),
            refund: address(payer.key),
            digest: proof.digest,
            sequence: root.sequence,
            valid_after_slot: proof.valid_after_slot,
            expires_slot: proof.expires_slot,
            created_slot: Clock::get()?.slot,
        }
        .pack(&mut permit_info.try_borrow_mut_data()?)
        .map_err(|_| PqAuthError::InvalidAccount)?;

        root.sequence = root
            .sequence
            .checked_add(1)
            .ok_or(PqAuthError::ArithmeticOverflow)?;
        root.pack(&mut root_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;
        consume_signature(signature_info, proof)?;
        Ok(())
    }

    fn execute_cpi(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        meta_flags: &[u8],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if accounts.len() < 5 || accounts.len() != 5 + meta_flags.len() {
            return Err(PqAuthError::UnexpectedAccounts.into());
        }
        let root_info = &accounts[0];
        let vault_info = &accounts[1];
        let permit_info = &accounts[2];
        let refund_info = &accounts[3];
        let target_program = &accounts[4];
        let target_accounts = &accounts[5..];

        require_writable(permit_info)?;
        require_writable(refund_info)?;
        if !target_program.executable || target_program.key == program_id {
            return Err(PqAuthError::ForbiddenCpi.into());
        }

        let root = load_root(program_id, root_info)?;
        let vault = load_vault(program_id, vault_info)?;
        let mut permit = load_permit(program_id, permit_info)?;
        validate_permit(
            &root,
            root_info,
            &vault,
            vault_info,
            &permit,
            permit_info,
            refund_info,
            ActionKind::Cpi,
            Clock::get()?.slot,
        )?;

        let mut digest_metas = Vec::with_capacity(target_accounts.len());
        let mut inner_metas = Vec::with_capacity(target_accounts.len());
        let mut inner_infos = Vec::with_capacity(target_accounts.len() + 1);
        inner_infos.push(target_program.clone());

        for (info, flags) in target_accounts.iter().zip(meta_flags.iter().copied()) {
            if info.key == root_info.key
                || info.key == permit_info.key
                || info.key == refund_info.key
                || info.key == target_program.key
                || info.key == program_id
            {
                return Err(PqAuthError::ForbiddenCpi.into());
            }
            let writable = flags & META_WRITABLE != 0;
            let signer = flags & META_SIGNER != 0;
            if writable && !info.is_writable {
                return Err(PqAuthError::NotWritable.into());
            }
            if signer && info.key != vault_info.key {
                return Err(PqAuthError::ForbiddenCpi.into());
            }
            digest_metas.push(CpiMetaDigest {
                address: address(info.key),
                flags,
            });
            inner_metas.push(if writable {
                AccountMeta::new(*info.key, signer)
            } else {
                AccountMeta::new_readonly(*info.key, signer)
            });
            inner_infos.push(info.clone());
        }

        let expected_digest = sha256(&execute_cpi_preimage(
            &address(program_id),
            &root.chain_id,
            &address(root_info.key),
            &address(vault_info.key),
            permit.sequence,
            permit.valid_after_slot,
            permit.expires_slot,
            &address(target_program.key),
            &digest_metas,
            instruction_data,
        ));
        if expected_digest != permit.digest {
            return Err(PqAuthError::DigestMismatch.into());
        }

        permit.status = PermitStatus::Consumed;
        permit
            .pack(&mut permit_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;

        let inner = Instruction {
            program_id: *target_program.key,
            accounts: inner_metas,
            data: instruction_data.to_vec(),
        };
        let bump_seed = [vault.bump];
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, root_info.key.as_ref(), &bump_seed];
        invoke_signed(&inner, &inner_infos, &[vault_seeds])?;

        close_program_account(permit_info, refund_info)?;
        Ok(())
    }

    fn execute_lamports(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let mut iter = accounts.iter();
        let root_info = next_account_info(&mut iter)?;
        let vault_info = next_account_info(&mut iter)?;
        let permit_info = next_account_info(&mut iter)?;
        let refund_info = next_account_info(&mut iter)?;
        let recipient_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_writable(vault_info)?;
        require_writable(permit_info)?;
        require_writable(refund_info)?;
        require_writable(recipient_info)?;
        if amount == 0
            || recipient_info.key == vault_info.key
            || recipient_info.key == root_info.key
            || recipient_info.key == permit_info.key
        {
            return Err(PqAuthError::InvalidAccount.into());
        }

        let root = load_root(program_id, root_info)?;
        let vault = load_vault(program_id, vault_info)?;
        let mut permit = load_permit(program_id, permit_info)?;
        validate_permit(
            &root,
            root_info,
            &vault,
            vault_info,
            &permit,
            permit_info,
            refund_info,
            ActionKind::TransferLamports,
            Clock::get()?.slot,
        )?;
        let expected_digest = sha256(&execute_lamports_preimage(
            &address(program_id),
            &root.chain_id,
            &address(root_info.key),
            &address(vault_info.key),
            permit.sequence,
            permit.valid_after_slot,
            permit.expires_slot,
            &address(recipient_info.key),
            amount,
        ));
        if expected_digest != permit.digest {
            return Err(PqAuthError::DigestMismatch.into());
        }

        permit.status = PermitStatus::Consumed;
        permit
            .pack(&mut permit_info.try_borrow_mut_data()?)
            .map_err(|_| PqAuthError::InvalidAccount)?;

        let minimum = Rent::get()?.minimum_balance(VAULT_ACCOUNT_LEN);
        let vault_balance = vault_info.lamports();
        let spendable = vault_balance
            .checked_sub(minimum)
            .ok_or(PqAuthError::RentViolation)?;
        if amount > spendable {
            return Err(PqAuthError::RentViolation.into());
        }
        {
            let mut from = vault_info.try_borrow_mut_lamports()?;
            **from = (**from)
                .checked_sub(amount)
                .ok_or(PqAuthError::ArithmeticOverflow)?;
        }
        {
            let mut to = recipient_info.try_borrow_mut_lamports()?;
            **to = (**to)
                .checked_add(amount)
                .ok_or(PqAuthError::ArithmeticOverflow)?;
        }

        close_program_account(permit_info, refund_info)?;
        Ok(())
    }

    fn close_signature(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let uploader = next_account_info(&mut iter)?;
        let signature_info = next_account_info(&mut iter)?;
        let destination = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(uploader)?;
        require_writable(signature_info)?;
        require_writable(destination)?;
        let proof = load_signature(program_id, signature_info)?;
        if proof.uploader != address(uploader.key) || destination.key != uploader.key {
            return Err(PqAuthError::Unauthorized.into());
        }
        close_program_account(signature_info, destination)
    }

    fn close_permit(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let permit_info = next_account_info(&mut iter)?;
        let refund_info = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_writable(permit_info)?;
        require_writable(refund_info)?;
        let permit = load_permit(program_id, permit_info)?;
        if permit.refund != address(refund_info.key) {
            return Err(PqAuthError::Unauthorized.into());
        }
        let now = Clock::get()?.slot;
        if permit.status != PermitStatus::Consumed && now <= permit.expires_slot {
            return Err(PqAuthError::WrongState.into());
        }
        close_program_account(permit_info, refund_info)
    }

    fn close_key(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let mut iter = accounts.iter();
        let uploader = next_account_info(&mut iter)?;
        let key_info = next_account_info(&mut iter)?;
        let destination = next_account_info(&mut iter)?;
        require_finished(&mut iter)?;

        require_signer(uploader)?;
        require_writable(key_info)?;
        require_writable(destination)?;
        let key = load_key(program_id, key_info)?;
        if key.uploader != address(uploader.key)
            || destination.key != uploader.key
            || key.status != KeyStatus::Uploading
        {
            return Err(PqAuthError::Unauthorized.into());
        }
        close_program_account(key_info, destination)
    }
}

fn address(key: &Pubkey) -> Address {
    key.to_bytes()
}

fn require_signer(account: &AccountInfo) -> ProgramResult {
    if account.is_signer {
        Ok(())
    } else {
        Err(PqAuthError::MissingSignature.into())
    }
}

fn require_writable(account: &AccountInfo) -> ProgramResult {
    if account.is_writable {
        Ok(())
    } else {
        Err(PqAuthError::NotWritable.into())
    }
}

fn require_system_program(account: &AccountInfo) -> ProgramResult {
    if system_program::check_id(account.key) {
        Ok(())
    } else {
        Err(PqAuthError::InvalidAccount.into())
    }
}

fn require_finished(iter: &mut std::slice::Iter<'_, AccountInfo<'_>>) -> ProgramResult {
    if iter.next().is_none() {
        Ok(())
    } else {
        Err(PqAuthError::UnexpectedAccounts.into())
    }
}

fn create_pda_account<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    space: usize,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    require_signer(payer)?;
    require_writable(payer)?;
    require_writable(pda)?;
    require_system_program(system)?;
    if pda.owner == program_id || pda.data_len() != 0 {
        return Err(PqAuthError::AlreadyInitialized.into());
    }
    if !system_program::check_id(pda.owner) {
        return Err(PqAuthError::InvalidOwner.into());
    }

    let minimum = Rent::get()?.minimum_balance(space);
    let current = pda.lamports();
    if current < minimum {
        invoke(
            &transfer(payer.key, pda.key, minimum - current),
            &[payer.clone(), pda.clone()],
        )?;
    }
    invoke_signed(
        &allocate(pda.key, space as u64),
        &[pda.clone()],
        &[signer_seeds],
    )?;
    invoke_signed(
        &assign(pda.key, program_id),
        &[pda.clone()],
        &[signer_seeds],
    )?;
    Ok(())
}

fn load_root(program_id: &Pubkey, account: &AccountInfo) -> Result<RootAccount, ProgramError> {
    if account.owner != program_id || account.data_len() != ROOT_ACCOUNT_LEN {
        return Err(PqAuthError::InvalidOwner.into());
    }
    let state = RootAccount::unpack(&account.try_borrow_data()?)
        .map_err(|_| PqAuthError::InvalidAccount)?;
    let legacy = Pubkey::new_from_array(state.legacy_address);
    let bump = [state.bump];
    let expected = Pubkey::create_program_address(
        &[ROOT_SEED, legacy.as_ref(), &bump],
        program_id,
    )
    .map_err(|_| PqAuthError::InvalidPda)?;
    if expected != *account.key {
        return Err(PqAuthError::InvalidPda.into());
    }
    Ok(state)
}

fn load_key(program_id: &Pubkey, account: &AccountInfo) -> Result<KeyAccountHeader, ProgramError> {
    if account.owner != program_id || account.data_len() != KEY_ACCOUNT_LEN {
        return Err(PqAuthError::InvalidOwner.into());
    }
    let header = KeyAccountHeader::unpack(&account.try_borrow_data()?)
        .map_err(|_| PqAuthError::InvalidAccount)?;
    verify_key_pda(program_id, account, &header)?;
    Ok(header)
}

fn verify_key_pda(
    program_id: &Pubkey,
    account: &AccountInfo,
    header: &KeyAccountHeader,
) -> ProgramResult {
    let root = Pubkey::new_from_array(header.root);
    let generation = header.generation.to_le_bytes();
    let bump = [header.bump];
    let expected = Pubkey::create_program_address(
        &[KEY_SEED, root.as_ref(), &generation, &header.key_id, &bump],
        program_id,
    )
    .map_err(|_| PqAuthError::InvalidPda)?;
    if expected == *account.key {
        Ok(())
    } else {
        Err(PqAuthError::InvalidPda.into())
    }
}

fn load_signature(
    program_id: &Pubkey,
    account: &AccountInfo,
) -> Result<SignatureAccountHeader, ProgramError> {
    if account.owner != program_id || account.data_len() != SIGNATURE_ACCOUNT_LEN {
        return Err(PqAuthError::InvalidOwner.into());
    }
    let header = SignatureAccountHeader::unpack(&account.try_borrow_data()?)
        .map_err(|_| PqAuthError::InvalidAccount)?;
    verify_signature_pda(program_id, account, &header)?;
    Ok(header)
}

fn verify_signature_pda(
    program_id: &Pubkey,
    account: &AccountInfo,
    header: &SignatureAccountHeader,
) -> ProgramResult {
    let root = Pubkey::new_from_array(header.root);
    let bump = [header.bump];
    let expected = Pubkey::create_program_address(
        &[SIGNATURE_SEED, root.as_ref(), &header.operation_id, &bump],
        program_id,
    )
    .map_err(|_| PqAuthError::InvalidPda)?;
    if expected == *account.key {
        Ok(())
    } else {
        Err(PqAuthError::InvalidPda.into())
    }
}

fn load_vault(program_id: &Pubkey, account: &AccountInfo) -> Result<VaultAccount, ProgramError> {
    if account.owner != program_id || account.data_len() != VAULT_ACCOUNT_LEN {
        return Err(PqAuthError::InvalidOwner.into());
    }
    let state = VaultAccount::unpack(&account.try_borrow_data()?)
        .map_err(|_| PqAuthError::InvalidAccount)?;
    let root = Pubkey::new_from_array(state.root);
    let bump = [state.bump];
    let expected = Pubkey::create_program_address(
        &[VAULT_SEED, root.as_ref(), &bump],
        program_id,
    )
    .map_err(|_| PqAuthError::InvalidPda)?;
    if expected != *account.key {
        return Err(PqAuthError::InvalidPda.into());
    }
    Ok(state)
}

fn load_permit(program_id: &Pubkey, account: &AccountInfo) -> Result<PermitAccount, ProgramError> {
    if account.owner != program_id || account.data_len() != PERMIT_ACCOUNT_LEN {
        return Err(PqAuthError::InvalidOwner.into());
    }
    let state = PermitAccount::unpack(&account.try_borrow_data()?)
        .map_err(|_| PqAuthError::InvalidAccount)?;
    let root = Pubkey::new_from_array(state.root);
    let sequence = state.sequence.to_le_bytes();
    let bump = [state.bump];
    let expected = Pubkey::create_program_address(
        &[PERMIT_SEED, root.as_ref(), &sequence, &bump],
        program_id,
    )
    .map_err(|_| PqAuthError::InvalidPda)?;
    if expected != *account.key {
        return Err(PqAuthError::InvalidPda.into());
    }
    Ok(state)
}

fn hash_key_bytes(
    key_info: &AccountInfo,
    header: &KeyAccountHeader,
) -> Result<[u8; 32], ProgramError> {
    if header.key_len as usize != ML_DSA_44_PUBLIC_KEY_LEN
        || header.written_len != header.key_len
    {
        return Err(PqAuthError::UploadIncomplete.into());
    }
    let data = key_info.try_borrow_data()?;
    Ok(sha256(
        &data[KEY_HEADER_LEN..KEY_HEADER_LEN + ML_DSA_44_PUBLIC_KEY_LEN],
    ))
}

fn require_active_key(
    root: &RootAccount,
    key_info: &AccountInfo,
    key: &KeyAccountHeader,
) -> ProgramResult {
    if key.status != KeyStatus::Finalized
        || key.root == [0; 32]
        || root.current_key != address(key_info.key)
        || root.current_key_hash != key.key_hash
        || root.generation != key.generation
    {
        return Err(PqAuthError::InvalidKey.into());
    }
    let actual_hash = hash_key_bytes(key_info, key)?;
    if actual_hash != key.key_hash {
        return Err(PqAuthError::InvalidKey.into());
    }
    Ok(())
}

fn require_proof_header(
    proof: &SignatureAccountHeader,
    root_info: &AccountInfo,
    key_info: &AccountInfo,
    purpose: ProofPurpose,
    sequence: u64,
    digest: &[u8; 32],
) -> ProgramResult {
    if proof.status != ProofStatus::Ready
        || proof.purpose != purpose
        || proof.root != address(root_info.key)
        || proof.key_record != address(key_info.key)
        || proof.sequence != sequence
        || &proof.digest != digest
        || proof.written_len != proof.signature_len
    {
        return Err(PqAuthError::WrongState.into());
    }
    Ok(())
}

fn verify_proof_bytes(
    key_info: &AccountInfo,
    key: &KeyAccountHeader,
    signature_info: &AccountInfo,
    proof: &SignatureAccountHeader,
    digest: &[u8; 32],
) -> ProgramResult {
    if key.scheme != Scheme::MlDsa44
        || key.key_len as usize != ML_DSA_44_PUBLIC_KEY_LEN
        || proof.signature_len as usize != ML_DSA_44_SIGNATURE_LEN
        || proof.written_len != proof.signature_len
    {
        return Err(PqAuthError::UnsupportedScheme.into());
    }
    let key_data = key_info.try_borrow_data()?;
    let signature_data = signature_info.try_borrow_data()?;
    verify_ml_dsa_44(
        &key_data[KEY_HEADER_LEN..KEY_HEADER_LEN + ML_DSA_44_PUBLIC_KEY_LEN],
        &signature_data
            [SIGNATURE_HEADER_LEN..SIGNATURE_HEADER_LEN + ML_DSA_44_SIGNATURE_LEN],
        digest,
    )
    .map_err(ProgramError::from)
}

fn consume_signature(
    signature_info: &AccountInfo,
    mut proof: SignatureAccountHeader,
) -> ProgramResult {
    proof.status = ProofStatus::Consumed;
    proof
        .pack(&mut signature_info.try_borrow_mut_data()?)
        .map_err(|_| PqAuthError::InvalidAccount.into())
}

fn validate_lifetime(valid_after: u64, expires: u64, now: u64) -> ProgramResult {
    if expires <= valid_after
        || expires <= now
        || expires.saturating_sub(valid_after) > MAX_PERMIT_LIFETIME_SLOTS
    {
        return Err(PqAuthError::InvalidLifetime.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_permit(
    root: &RootAccount,
    root_info: &AccountInfo,
    vault: &VaultAccount,
    vault_info: &AccountInfo,
    permit: &PermitAccount,
    permit_info: &AccountInfo,
    refund_info: &AccountInfo,
    action: ActionKind,
    now: u64,
) -> ProgramResult {
    if root.status != RootStatus::Sealed
        || root.flags & ROOT_FLAG_ED25519_DISABLED == 0
        || vault.root != address(root_info.key)
        || permit.status != PermitStatus::Ready
        || permit.action != action
        || permit.root != address(root_info.key)
        || permit.vault != address(vault_info.key)
        || permit.refund != address(refund_info.key)
        || permit_info.key == refund_info.key
    {
        return Err(PqAuthError::WrongState.into());
    }
    if now < permit.valid_after_slot {
        return Err(PqAuthError::NotYetValid.into());
    }
    if now > permit.expires_slot {
        return Err(PqAuthError::Expired.into());
    }
    Ok(())
}

fn close_program_account(source: &AccountInfo, destination: &AccountInfo) -> ProgramResult {
    require_writable(source)?;
    require_writable(destination)?;
    if source.key == destination.key {
        return Err(PqAuthError::InvalidAccount.into());
    }
    let source_lamports = source.lamports();
    {
        let mut destination_lamports = destination.try_borrow_mut_lamports()?;
        **destination_lamports = (**destination_lamports)
            .checked_add(source_lamports)
            .ok_or(PqAuthError::ArithmeticOverflow)?;
    }
    {
        let mut source_balance = source.try_borrow_mut_lamports()?;
        **source_balance = 0;
    }
    source.try_borrow_mut_data()?.fill(0);
    Ok(())
}
