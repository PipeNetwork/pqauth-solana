use alloc::vec::Vec;

use crate::{
    codec::Writer, DOMAIN_EXECUTE_CPI, DOMAIN_EXECUTE_LAMPORTS, DOMAIN_KEY_POP,
    DOMAIN_ROTATE, DOMAIN_SEAL,
};

pub type Address = [u8; 32];
pub type Digest = [u8; 32];
pub type KeyId = [u8; 16];

fn write_common(
    writer: &mut Writer,
    domain: &[u8],
    program_id: &Address,
    chain_id: &Digest,
    root: &Address,
) {
    writer.u16(domain.len() as u16);
    writer.bytes(domain);
    writer.bytes(program_id);
    writer.bytes(chain_id);
    writer.bytes(root);
}

pub fn key_pop_preimage(
    program_id: &Address,
    chain_id: &Digest,
    root: &Address,
    generation: u32,
    key_id: &KeyId,
    scheme: u8,
    key_hash: &Digest,
) -> Vec<u8> {
    let mut writer = Writer::with_capacity(160);
    write_common(&mut writer, DOMAIN_KEY_POP, program_id, chain_id, root);
    writer.u32(generation);
    writer.bytes(key_id);
    writer.u8(scheme);
    writer.bytes(key_hash);
    writer.into_vec()
}

pub fn seal_preimage(
    program_id: &Address,
    chain_id: &Digest,
    root: &Address,
    sequence: u64,
    key_record: &Address,
    key_hash: &Digest,
) -> Vec<u8> {
    let mut writer = Writer::with_capacity(176);
    write_common(&mut writer, DOMAIN_SEAL, program_id, chain_id, root);
    writer.u64(sequence);
    writer.bytes(key_record);
    writer.bytes(key_hash);
    writer.into_vec()
}

#[allow(clippy::too_many_arguments)]
pub fn rotate_preimage(
    program_id: &Address,
    chain_id: &Digest,
    root: &Address,
    sequence: u64,
    old_key_record: &Address,
    old_key_hash: &Digest,
    new_key_record: &Address,
    new_key_hash: &Digest,
    new_generation: u32,
) -> Vec<u8> {
    let mut writer = Writer::with_capacity(256);
    write_common(&mut writer, DOMAIN_ROTATE, program_id, chain_id, root);
    writer.u64(sequence);
    writer.bytes(old_key_record);
    writer.bytes(old_key_hash);
    writer.bytes(new_key_record);
    writer.bytes(new_key_hash);
    writer.u32(new_generation);
    writer.into_vec()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpiMetaDigest {
    pub address: Address,
    pub flags: u8,
}

#[allow(clippy::too_many_arguments)]
pub fn execute_cpi_preimage(
    program_id: &Address,
    chain_id: &Digest,
    root: &Address,
    vault: &Address,
    sequence: u64,
    valid_after_slot: u64,
    expires_slot: u64,
    target_program: &Address,
    metas: &[CpiMetaDigest],
    instruction_data: &[u8],
) -> Vec<u8> {
    let capacity = 192usize
        .saturating_add(metas.len().saturating_mul(33))
        .saturating_add(instruction_data.len());
    let mut writer = Writer::with_capacity(capacity);
    write_common(
        &mut writer,
        DOMAIN_EXECUTE_CPI,
        program_id,
        chain_id,
        root,
    );
    writer.bytes(vault);
    writer.u64(sequence);
    writer.u64(valid_after_slot);
    writer.u64(expires_slot);
    writer.bytes(target_program);
    writer.u16(metas.len() as u16);
    for meta in metas {
        writer.bytes(&meta.address);
        writer.u8(meta.flags);
    }
    writer.u32(instruction_data.len() as u32);
    writer.bytes(instruction_data);
    writer.into_vec()
}

#[allow(clippy::too_many_arguments)]
pub fn execute_lamports_preimage(
    program_id: &Address,
    chain_id: &Digest,
    root: &Address,
    vault: &Address,
    sequence: u64,
    valid_after_slot: u64,
    expires_slot: u64,
    recipient: &Address,
    amount: u64,
) -> Vec<u8> {
    let mut writer = Writer::with_capacity(192);
    write_common(
        &mut writer,
        DOMAIN_EXECUTE_LAMPORTS,
        program_id,
        chain_id,
        root,
    );
    writer.bytes(vault);
    writer.u64(sequence);
    writer.u64(valid_after_slot);
    writer.u64(expires_slot);
    writer.bytes(recipient);
    writer.u64(amount);
    writer.into_vec()
}
