# Wire Format

All integers are little-endian. Addresses and digests are fixed 32-byte arrays. Encodings reject trailing instruction bytes.

## Canonical hashing

Every signed operation is:

```text
digest = SHA256(canonical_preimage)
ML-DSA-Sign(context = "solana-pqauth-v1", message = digest)
```

Every preimage begins with:

```text
u16 domain_length
[domain_length] domain_utf8
[32] pqauth_program_id
[32] chain_id
[32] root_address
```

No JSON, Borsh map, text number, host-size integer, or account display string appears in signed data.

## Domains

| Operation | Domain |
|---|---|
| Key possession | `SOLANA_PQAUTH_KEY_POP_V1` |
| Seal | `SOLANA_PQAUTH_SEAL_V1` |
| Rotate | `SOLANA_PQAUTH_ROTATE_V1` |
| CPI | `SOLANA_PQAUTH_EXECUTE_CPI_V1` |
| Lamports | `SOLANA_PQAUTH_EXECUTE_LAMPORTS_V1` |

## Signed operation fields

### Key possession

```text
common
generation: u32
key_id: [16]
scheme: u8
public_key_sha256: [32]
```

### Seal

```text
common
sequence: u64
key_record: [32]
key_hash: [32]
```

### Rotate

```text
common
sequence: u64
old_key_record: [32]
old_key_hash: [32]
new_key_record: [32]
new_key_hash: [32]
new_generation: u32
```

### Execute CPI

```text
common
vault: [32]
sequence: u64
valid_after_slot: u64
expires_slot: u64
target_program: [32]
meta_count: u16
repeated meta_count times:
    address: [32]
    flags: u8       // bit 0 writable, bit 1 signer
instruction_data_length: u32
instruction_data: [instruction_data_length]
```

Only the vault address may carry the signer flag.

### Transfer lamports

```text
common
vault: [32]
sequence: u64
valid_after_slot: u64
expires_slot: u64
recipient: [32]
amount: u64
```

## Account layouts

Unused bytes are zeroed when an account is initialized or updated.

### Root — 192 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 8 | magic `PQROOT01` |
| 8 | 1 | protocol version |
| 9 | 1 | bump |
| 10 | 1 | root status |
| 11 | 1 | scheme |
| 12 | 4 | flags |
| 16 | 32 | legacy address |
| 48 | 32 | chain ID |
| 80 | 32 | current key-record address |
| 112 | 32 | current public-key hash |
| 144 | 4 | generation |
| 148 | 8 | sequence |
| 156 | 8 | created slot |
| 164 | 8 | sealed slot |
| 172 | 20 | reserved, zero |

### Key — 1,472 bytes

Header is 160 bytes; ML-DSA-44 public key bytes begin at offset 160.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 8 | magic `PQKEY001` |
| 8 | 1 | protocol version |
| 9 | 1 | bump |
| 10 | 1 | scheme |
| 11 | 1 | status |
| 12 | 4 | generation |
| 16 | 16 | key ID |
| 32 | 32 | root |
| 64 | 32 | uploader |
| 96 | 32 | public-key hash |
| 128 | 2 | declared key length |
| 130 | 2 | written length |
| 132 | 8 | created slot |
| 140 | 8 | finalized slot |
| 148 | 12 | reserved |
| 160 | 1,312 | encoded ML-DSA-44 public key |

### Signature — 2,612 bytes

Header is 192 bytes; ML-DSA-44 signature bytes begin at offset 192.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 8 | magic `PQSIG001` |
| 8 | 1 | protocol version |
| 9 | 1 | bump |
| 10 | 1 | purpose |
| 11 | 1 | status |
| 12 | 16 | operation ID |
| 28 | 32 | root |
| 60 | 32 | uploader |
| 92 | 32 | key record |
| 124 | 32 | digest |
| 156 | 8 | sequence |
| 164 | 8 | valid-after slot |
| 172 | 8 | expiry slot |
| 180 | 2 | declared signature length |
| 182 | 2 | written length |
| 184 | 8 | created slot |
| 192 | 2,420 | encoded ML-DSA-44 signature |

### Vault — 64 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 8 | magic `PQVAULT1` |
| 8 | 1 | version |
| 9 | 1 | bump |
| 10 | 32 | root |
| 42 | 22 | reserved |

### Permit — 192 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 8 | magic `PQPERM01` |
| 8 | 1 | version |
| 9 | 1 | bump |
| 10 | 1 | status |
| 11 | 1 | action |
| 12 | 32 | root |
| 44 | 32 | vault |
| 76 | 32 | rent refund address |
| 108 | 32 | action digest |
| 140 | 8 | sequence |
| 148 | 8 | valid-after slot |
| 156 | 8 | expiry slot |
| 164 | 8 | created slot |
| 172 | 20 | reserved |

## Instruction tags

| Tag | Instruction |
|---:|---|
| 0 | InitializeRoot |
| 1 | InitializeKey |
| 2 | WriteKey |
| 3 | InitializeSignature |
| 4 | WriteSignature |
| 5 | FinalizeKey |
| 6 | ActivateInitialKey |
| 7 | Seal |
| 8 | Rotate |
| 9 | CreateVault |
| 10 | Authorize |
| 11 | ExecuteCpi |
| 12 | ExecuteLamports |
| 13 | CloseSignature |
| 14 | ClosePermit |
| 15 | CloseKey |

See `crates/pqauth-core/src/instruction.rs` for the canonical payload codec and `crates/pqauth-client` for account ordering.
