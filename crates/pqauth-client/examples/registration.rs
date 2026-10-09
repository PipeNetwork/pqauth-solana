use pqauth_client::{
    activate_initial_key, finalize_key, initialize_key, initialize_root, key_address,
    key_pop_digest, root_address, upload_chunks, write_key,
};
use solana_program::pubkey::Pubkey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let legacy = Pubkey::new_from_array([1; 32]);
    let payer = Pubkey::new_from_array([2; 32]);
    let uploader = payer;
    let chain_id = [3; 32];
    let key_id = [4; 16];
    let public_key = vec![5u8; pqauth_core::ML_DSA_44_PUBLIC_KEY_LEN];

    let (root, _) = root_address(&legacy);
    let (key, _) = key_address(&root, 0, &key_id);

    let mut registration = vec![
        initialize_root(legacy, payer, chain_id),
        initialize_key(uploader, payer, root, 0, key_id),
    ];
    for (offset, bytes) in upload_chunks(&public_key) {
        registration.push(write_key(uploader, key, offset, bytes)?);
    }

    let proof_digest = key_pop_digest(&chain_id, &root, 0, &key_id, &public_key);
    println!("root: {root}");
    println!("key record: {key}");
    println!("registration instructions before proof: {}", registration.len());
    println!("key proof digest: {}", hex_string(&proof_digest));

    // After staging the ML-DSA signature, these are the final two state transitions.
    let signature_pda = Pubkey::new_from_array([6; 32]);
    let _finalize = finalize_key(root, key, signature_pda);
    let _activate = activate_initial_key(legacy, root, key);
    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
