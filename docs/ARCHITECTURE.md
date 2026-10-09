# Architecture

## Goals

PQAuth is designed around five properties:

1. **Pre-break provenance.** A legacy Ed25519 address records a post-quantum key while Ed25519 is still trusted.
2. **One-way sealing.** After seal, Ed25519 has no authority to change the PQ key or authorization policy.
3. **PQ-controlled custody today.** A program-derived vault can hold SOL, token accounts, and program authorities without an Ed25519 private key.
4. **Replay-safe actions.** Every state-changing PQ authorization consumes the root's monotonic sequence.
5. **Address continuity later.** A runtime extension can use the sealed record to authorize the original address directly.

## Trust phases

### Phase 0 — no registration

The legacy address is governed exactly as it is today. PQAuth provides no protection.

### Phase 1 — unsealed registration

The legacy signer creates a root and one or more generation-0 key candidates. Each key must prove possession by signing a canonical key-registration digest.

The legacy signer may choose a different finalized generation-0 key while the root remains unsealed. Therefore an unsealed root is **not** a safe migration commitment.

### Phase 2 — sealed root

Seal requires:

- the legacy Ed25519 account as a transaction signer;
- the active generation-0 ML-DSA-44 key;
- a signature over the exact root, chain identifier, key record, key hash, and current sequence.

On success:

- `status = Sealed`;
- `ROOT_FLAG_ED25519_DISABLED` is set;
- `sealed_slot` is recorded;
- the sequence is incremented.

There is no instruction that clears this flag or returns to `Unsealed`.

### Phase 3 — PQ-only operation

Only the active PQ key can:

- rotate to a finalized key at `generation + 1`;
- authorize an exact CPI or lamport transfer;
- consume the next root sequence.

The Ed25519 signer is absent from those instruction account lists.

## Staged public keys and signatures

ML-DSA-44 uses a 1,312-byte encoded public key and a 2,420-byte encoded signature. PQAuth stores each in a PDA and writes it through sequential chunks of at most 900 bytes.

Uploads are append-only:

```text
required_offset == written_len
new_written_len <= declared_len
```

The uploader can abandon and close an incomplete object. A finalized key remains an auditable commitment record. A ready or consumed signature can be closed by its uploader after use or abandonment.

A key is finalized only after the program:

1. hashes the complete encoded public key;
2. reconstructs the domain-separated key-possession digest;
3. verifies a full ML-DSA-44 proof using that public key;
4. writes the hash and finalized slot into the key header.

## Monotonic sequence

`RootAccount.sequence` is shared by all security-sensitive post-seal operations.

- Seal signs and consumes sequence `0`.
- Each rotation consumes exactly one sequence.
- Each `Authorize` instruction consumes exactly one sequence and creates a permit PDA derived from that sequence.

Two authorizations at the same sequence cannot both commit. Once the first transaction updates the root, the second fails its expected-sequence check.

## Authorization permits

A large or complex downstream operation is split into two transactions:

1. **Authorize** — verify the ML-DSA signature and create a one-time permit.
2. **Execute** — recompute the exact action digest, consume the permit, invoke the target program or transfer lamports, then close the permit.

The signed digest binds:

- protocol domain and version;
- PQAuth program ID;
- chain identifier;
- root and vault addresses;
- sequence;
- validity slots;
- target program;
- ordered account addresses and flags;
- instruction data, or recipient and amount.

A relayer may submit either transaction. Front-running execution does not redirect the action because every mutable field is included in the signed digest.

## Vault CPI policy

The vault PDA may be elevated as a signer during CPI. No other downstream account may be promoted to signer.

The program rejects CPI account lists that include the root, permit, refund destination, target program, or PQAuth program as downstream target accounts. This prevents a signed CPI from recursively mutating the authorization root or closing its own permit through aliasing.

Only the vault PDA's signer seeds are passed to `invoke_signed`.

## Native migration path

The deployable program cannot change how the System Program interprets signatures for the original Ed25519 address. The SIMD adds a transaction authorization extension:

```text
original account address
        |
        +-- sealed authorization descriptor account
        |
        +-- ML-DSA proof over the transaction signing digest
        v
runtime validates descriptor + proof
        v
original account receives is_signer = true
```

The descriptor account is supplied explicitly in the transaction and read-locked. The runtime does not perform an implicit global lookup. Existing programs need no instruction-level changes.
