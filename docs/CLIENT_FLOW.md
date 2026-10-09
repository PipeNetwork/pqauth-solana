# Client Transaction Flow

The client crate builds instructions but does not hold Solana fee-payer or legacy keypairs. The ML-DSA CLI signs only canonical 32-byte digests.

## Initial registration

Assume:

- legacy signer `L`;
- payer/uploader `P`;
- chain identifier `C`;
- generated ML-DSA public key `Q0`;
- random 16-byte key ID `K0`;
- random 16-byte operation IDs for each proof account.

### 1. Initialize root

```rust
let ix = pqauth_client::initialize_root(legacy, payer, chain_id);
```

Both legacy and payer sign the transaction.

### 2. Upload generation-0 key

```rust
let (root, _) = pqauth_client::root_address(&legacy);
let (key0, _) = pqauth_client::key_address(&root, 0, &key_id);

let mut ixs = vec![pqauth_client::initialize_key(
    uploader, payer, root, 0, key_id,
)];
for (offset, bytes) in pqauth_client::upload_chunks(&public_key) {
    ixs.push(pqauth_client::write_key(uploader, key0, offset, bytes)?);
}
```

Transactions may split the write instructions further. Offsets must remain append-only.

### 3. Prove possession and finalize

```rust
let digest = pqauth_client::key_pop_digest(
    &chain_id, &root, 0, &key_id, &public_key,
);
```

Sign `digest` with ML-DSA-44 and context `solana-pqauth-v1`. Initialize the signature PDA, upload signature chunks, then call `finalize_key`.

### 4. Activate the initial key

```rust
let ix = pqauth_client::activate_initial_key(legacy, root, key0);
```

The legacy account signs. This step is reversible only while the root remains unsealed.

### 5. Seal

Read the root account and confirm its sequence, active key, and key hash. Compute:

```rust
let digest = pqauth_client::seal_digest(
    &chain_id,
    &root,
    root_state.sequence,
    &key0,
    &key0_state.key_hash,
);
```

Upload a signature with purpose `ProofPurpose::Seal`, then submit:

```rust
let ix = pqauth_client::seal(legacy, root, key0, seal_signature_pda);
```

This transaction requires the legacy Solana signature; the program verifies the staged ML-DSA signature. After success, verify the root from independent RPC endpoints.

## Vault operation

### 1. Create and fund vault

```rust
let create = pqauth_client::create_vault(payer, root);
let (vault, _) = pqauth_client::vault_address(&root);
```

SOL may be transferred to the vault address. SPL token accounts can use the vault PDA as owner/authority.

### 2. Sign an exact action

For a SOL transfer:

```rust
let digest = pqauth_client::lamports_digest(
    &chain_id,
    &root,
    &vault,
    root_state.sequence,
    valid_after_slot,
    expires_slot,
    &recipient,
    amount,
);
```

For CPI, call `cpi_digest` using the exact ordered account metas and instruction bytes.

### 3. Authorize

Upload the ML-DSA signature with purpose `ProofPurpose::Authorize`. Then create the permit:

```rust
let authorize = pqauth_client::authorize(
    payer,
    root,
    active_key,
    signature_pda,
    vault,
    root_state.sequence,
    ActionKind::TransferLamports,
);
```

`Authorize` verifies the signature, increments the root sequence, and creates a one-time permit.

### 4. Execute

```rust
let (permit, _) = pqauth_client::permit_address(&root, signed_sequence);
let execute = pqauth_client::execute_lamports(
    root, vault, permit, payer, recipient, amount,
);
```

The execution transaction needs no PQ key. It recomputes the digest and closes the consumed permit to its fixed rent-refund address.

## Rotation

1. Upload and finalize a key at `current_generation + 1` with its own proof of possession.
2. Compute `rotate_digest` using the current sequence, both key records, both hashes, and the new generation.
3. Sign with the **current** ML-DSA key.
4. Upload the proof with purpose `Rotate`.
5. Submit `pqauth_client::rotate`.

The new key becomes active atomically and the sequence increments.
