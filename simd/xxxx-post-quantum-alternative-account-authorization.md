---
simd: 'XXXX'
title: Post-Quantum Alternative Account Authorization
authors:
  - David Rhodus
category: Standard
type: Core
status: Idea
created: 2026-10-08
feature: to be assigned
---

## Summary

This proposal introduces an opt-in mechanism by which an existing Solana account address can precommit to a post-quantum authorization key and later satisfy signer authorization with that key without changing the account address.

The proposal has three consensus components:

1. a native, append-only **Alternative Authorization Registry** that binds a subject address to a versioned post-quantum key lineage;
2. an **ML-DSA-44 verifier** shared by transaction authorization and a public verification precompile/syscall;
3. a versioned transaction extension carrying alternative authorization metadata and variable-length signatures.

A descriptor is initially created by the subject's legacy Ed25519 signer. It becomes security-relevant only after it is **sealed** by both the legacy signer and the selected post-quantum key. After sealing, Ed25519 alone cannot replace, delete, downgrade, or rotate the descriptor.

When a transaction carries a valid alternative proof, the runtime marks the original subject account as a signer. Programs continue to observe the same account key and `is_signer == true`; no program-level migration of balances, token accounts, stake authorities, PDAs, or address-book entries is required.

## Motivation

For an ordinary keypair-controlled Solana account, the 32-byte address is the Ed25519 verification key. A cryptographically relevant quantum computer running Shor's algorithm would attack the public key directly. Repeated signatures are not required.

A migration performed only after Ed25519 becomes forgeable cannot distinguish the legitimate owner from an attacker who derived the same private key. The network therefore needs a commitment created while Ed25519 is still trusted.

Moving every asset and authority to a new address is possible but operationally expensive and incomplete. An address may be embedded as:

- owner or authority of many token and stake accounts;
- upgrade authority or governance member;
- multisig member;
- program configuration;
- off-chain allow-list, identity, or address-book entry;
- signer expected by existing programs.

A native alternative authorization mechanism preserves the identity of the account while replacing the proof required to exercise signer authority.

The mechanism must not merely store a post-quantum key. If a future Ed25519 signature can update that stored key, a quantum attacker can replace it. The central invariant is therefore:

> After a descriptor is sealed, no valid state transition may depend on Ed25519 alone.

## Dependencies

This proposal assumes:

- a versioned transaction format that can carry variable-length alternative signatures;
- transaction/account-loading support for explicitly supplied authorization descriptor and key accounts;
- consensus-wide ML-DSA-44 verification with deterministic compute metering;
- a cluster feature-activation mechanism for any emergency Ed25519 cutoff.

It is compatible with larger transaction packets but does not require that every public key be carried in transaction bytes. Public keys are stored in read-only registry accounts and signatures are carried in the transaction authorization section.

## New Terminology

**Subject**
: The existing 32-byte account address whose signer authority is being extended.

**Legacy authorization**
: Ed25519 verification under the subject address using the current transaction signature mechanism.

**Alternative Authorization Descriptor (AAD)**
: A canonical native-program account that binds a subject to its active scheme, key record, key hash, generation, sequence, policy, creation slot, and sealed slot.

**Key record**
: A canonical account containing an encoded post-quantum public key, its hash, scheme identifier, generation, status, and proof-of-possession result.

**Sealed descriptor**
: An AAD for which both the subject's legacy Ed25519 signer and the active alternative key authorized the seal transition. A sealed descriptor cannot return to an unsealed state.

**Alternative proof**
: A variable-length signature associated with an alternative signer declaration in a versioned transaction.

**Cutoff slot**
: A cluster-governed slot after which legacy Ed25519 authorization is rejected for eligible subjects whose descriptors were sealed before that slot.

## Detailed Design

### Design overview

The feature is intentionally split between durable state and transaction verification.

```text
subject address
     |
     +---- canonical descriptor account (native registry)
                  |
                  +---- current immutable key record
                               |
                               +---- encoded ML-DSA-44 public key

Versioned transaction:
  message + Ed25519 signatures + alternative signer declarations + ML-DSA proofs
                                      |
                                      v
account load -> descriptor validation -> ML-DSA verification -> signer-bit synthesis
                                      |
                                      v
                         normal program execution
```

No runtime-global hidden lookup is required. The transaction explicitly includes and read-locks the descriptor and key record used for authorization.

### Feature gates

The implementation should use separate feature gates:

1. `enable_mldsa44_native_verification`
2. `enable_alternative_authorization_registry`
3. `enable_v2_alternative_signers`
4. `ed25519_cutoff_for_precommitted_accounts`, if ever activated

The verifier and registry may be deployed and exercised before transactions are permitted to synthesize signer privileges.

### Scheme registry

Scheme IDs are consensus values:

| ID | Scheme | Encoding |
|---:|---|---|
| `0x0001` | ML-DSA-44 | FIPS 204 encoded public key and signature |

Unknown scheme IDs are rejected. Future schemes require a new SIMD and feature gate. Existing descriptors do not silently reinterpret bytes under a new verifier.

For ML-DSA-44:

- encoded public key length: 1,312 bytes;
- encoded signature length: 2,420 bytes;
- context: `solana-alt-auth-v1`;
- signed message: the 32-byte authorization digest defined below.

### Native registry program

A new native or core-BPF program owns descriptors and key records. Its address and account formats are consensus constants.

The program exposes the following state transitions:

```text
InitializeDescriptor
InitializeKeyRecord
WriteKeyChunk
FinalizeKeyRecord
SelectInitialKey
SealDescriptor
RotateKey
DisableLegacyAuthorization
```

`InitializeDescriptor`, `SelectInitialKey`, and `SealDescriptor` require the subject to be a legacy Ed25519 signer. `SealDescriptor` additionally requires a valid signature by the selected alternative key.

After `SealDescriptor` succeeds:

- descriptor status is permanently `Sealed`;
- subject, creation slot, and sealed slot are immutable;
- scheme may change only through an authorized rotation to a scheme explicitly allowed by a future feature;
- generation must increase by exactly one;
- sequence must increase for every mutation;
- legacy authorization cannot alter any descriptor or key-lineage field;
- legacy authorization policy can move only toward greater restriction.

The registry rejects account closing for sealed descriptors and finalized key records that appear in their lineage.

### Canonical descriptor address

The descriptor is a PDA under the registry program:

```text
PDA("alt-auth", subject_address)
```

The subject address is stored in the account and the PDA derivation is revalidated on every load.

### Descriptor account

The logical descriptor fields are:

```rust
struct AlternativeAuthorizationDescriptorV1 {
    version: u8,
    bump: u8,
    status: DescriptorStatus,
    policy: LegacyPolicy,
    scheme: u16,
    subject: Pubkey,
    active_key_record: Pubkey,
    active_key_hash: [u8; 32],
    generation: u32,
    sequence: u64,
    created_slot: u64,
    sealed_slot: u64,
}
```

The exact serialized offsets must be specified in the implementation SIMD appendix and covered by consensus test vectors. Reserved bytes must be zero on creation and ignored only if a future version explicitly assigns them.

### Key records and proof of possession

A key record contains:

```rust
struct AlternativeKeyRecordV1 {
    version: u8,
    scheme: u16,
    status: KeyStatus,
    subject: Pubkey,
    descriptor: Pubkey,
    generation: u32,
    key_id: [u8; 16],
    public_key_hash: [u8; 32],
    public_key_length: u16,
    encoded_public_key: Vec<u8>,
    finalized_slot: u64,
}
```

The public key may be uploaded through append-only chunks. Finalization requires proof of possession:

```text
key_pop_digest = SHA256(
    u16_le(len("SOLANA_ALT_AUTH_KEY_POP_V1")) ||
    "SOLANA_ALT_AUTH_KEY_POP_V1" ||
    genesis_hash ||
    registry_program_id ||
    subject ||
    descriptor ||
    generation_le ||
    key_id ||
    scheme_le ||
    SHA256(encoded_public_key)
)
```

The candidate key signs `key_pop_digest` with its scheme's fixed context. A malformed encoding or failed proof leaves the record unfinalized.

### Seal transition

Before sealing, the legacy signer may select a finalized generation-0 candidate. This supports correction of an erroneous registration. An unsealed descriptor MUST NOT be treated as a trusted precommitment.

Sealing requires both:

1. normal legacy Ed25519 authorization by `subject`; and
2. an ML-DSA signature by the selected key over:

```text
seal_digest = SHA256(
    u16_le(len("SOLANA_ALT_AUTH_SEAL_V1")) ||
    "SOLANA_ALT_AUTH_SEAL_V1" ||
    genesis_hash ||
    registry_program_id ||
    subject ||
    descriptor ||
    sequence_le ||
    active_key_record ||
    active_key_hash ||
    policy
)
```

The transition records `sealed_slot`, increments `sequence`, and cannot be reversed.

### Legacy policy

V1 defines:

```rust
enum LegacyPolicy {
    AllowedUntilClusterCutoff = 1,
    DisabledImmediately = 2,
}
```

A sealed descriptor may move from `AllowedUntilClusterCutoff` to `DisabledImmediately` only with an active alternative-key signature. It may never move in the opposite direction.

Before any cluster cutoff, a subject using `AllowedUntilClusterCutoff` may be authorized by either legacy Ed25519 or an alternative proof. A subject using `DisabledImmediately` may be authorized only by an alternative proof.

This policy applies to signer synthesis for the subject. It does not change ownership or executable status.

### Key rotation

Rotation requires:

- a sealed descriptor;
- a finalized candidate key record for `generation + 1`;
- proof of possession by the candidate key;
- a signature by the currently active key over the exact candidate record, key hash, new scheme, new generation, and current sequence.

```text
rotate_digest = SHA256(
    domain || genesis_hash || registry_program_id ||
    subject || descriptor || sequence_le ||
    old_key_record || old_key_hash ||
    new_key_record || new_key_hash ||
    new_scheme_le || new_generation_le
)
```

Successful rotation updates the active key and increments the sequence atomically. The old key cannot authorize transactions whose message declares the new generation.

### Versioned transaction format

A new transaction version separates fixed message declarations from variable signature bytes.

Conceptually:

```rust
struct TransactionV2 {
    ed25519_signatures: Vec<Ed25519Signature>,
    alternative_signatures: Vec<AlternativeSignature>,
    message: MessageV2,
}

struct MessageV2 {
    header: MessageHeader,
    account_keys: Vec<Pubkey>,
    recent_blockhash: Hash,
    instructions: Vec<CompiledInstruction>,
    address_table_lookups: Vec<MessageAddressTableLookup>,
    alternative_signers: Vec<AlternativeSignerDeclaration>,
}

struct AlternativeSignerDeclaration {
    subject_index: u16,
    descriptor_index: u16,
    key_record_index: u16,
    scheme: u16,
    generation: u32,
}

struct AlternativeSignature {
    scheme: u16,
    signature: Vec<u8>,
}
```

The alternative signature vector is parallel to `alternative_signers`. Lengths and scheme encodings are validated before account loading.

`MessageHeader.num_required_signatures` continues to describe top-level Ed25519 signatures. Alternative signer subjects are declared separately and receive signer privileges only after all alternative authorization checks succeed.

A subject MUST NOT appear more than once in `alternative_signers`. A transaction MUST NOT request both legacy Ed25519 and alternative authorization for the same subject. Duplicate descriptors or key records are allowed only when they refer to different subjects and all ownership/binding checks pass.

The fee payer in V1 remains a normal Ed25519 signer or another currently supported payer. This permits a sponsor to pay fees for a PQ-authorized subject without requiring the subject to possess SOL.

### Authorization digest

Alternative signatures sign the exact versioned message, not an instruction-selected payload.

```text
message_hash = SHA256(canonical_serialize(MessageV2))

authorization_digest = SHA256(
    u16_le(len("SOLANA_ALT_AUTH_TX_V1")) ||
    "SOLANA_ALT_AUTH_TX_V1" ||
    genesis_hash ||
    message_hash ||
    subject ||
    descriptor ||
    key_record ||
    scheme_le ||
    generation_le
)
```

The scheme verifies `authorization_digest` under its fixed context. The signature bytes are outside `MessageV2`, avoiding circular serialization while binding every instruction, account, recent blockhash, address-table lookup, and signer declaration.

### Verification pipeline

For each alternative signer declaration, validators perform the following after resolving address-table lookups and loading transaction accounts, but before program execution:

1. Validate all three account indexes.
2. Require the descriptor and key record to be read-only in the transaction.
3. Require the descriptor to be owned by the registry program and located at the canonical PDA for `subject`.
4. Require descriptor status `Sealed`.
5. Require descriptor subject, active key record, key hash, scheme, and generation to match the declaration and loaded key record.
6. Recompute the encoded public-key hash.
7. Apply legacy policy and any active cutoff rule.
8. Recompute `authorization_digest` from the canonical message.
9. Verify the alternative signature with consensus-metered native code.
10. On success, set the subject account's signer bit for instruction-account construction.

If any alternative proof fails, the entire transaction is rejected before execution. There is no partial signer synthesis.

Descriptor and key accounts are included in the transaction's read locks. Programs cannot mutate them during a transaction that relies on them.

### ML-DSA native verification

The same implementation MUST be used by transaction authorization and the public verifier interface to prevent consensus divergence.

Requirements:

- exact FIPS 204 ML-DSA-44 decoding and verification semantics;
- fixed maximum input lengths;
- no secret-dependent behavior is required for public verification, but execution time must be bounded for malformed inputs;
- deterministic compute-unit charge;
- stable reject behavior for non-canonical encodings;
- corpus tests against at least two independent implementations;
- architecture-independent consensus vectors.

The public interface may be exposed as a precompile instruction, syscall, or core program. Its API is secondary to the requirement that transaction verification use the identical consensus implementation.

### Emergency cutoff

A cluster cannot safely recognize a new Ed25519-signed commitment after Ed25519 is believed forgeable. An optional cutoff feature therefore carries an immutable activation parameter:

```text
quantum_cutoff_slot: u64
```

Once active:

- if a descriptor was sealed at `sealed_slot < quantum_cutoff_slot`, legacy Ed25519 authorization for its subject is rejected regardless of `AllowedUntilClusterCutoff`;
- alternative authorization remains valid;
- descriptors sealed at or after the cutoff are not accepted as evidence of pre-break ownership;
- accounts without an eligible pre-cutoff descriptor remain under a separate recovery policy, outside this proposal.

The cutoff cannot determine who is legitimate for an uncommitted address. It only gives effect to commitments whose ordering predates the cutoff.

A cutoff feature is an extraordinary governance action and should not be activated merely because quantum hardware improves. The registry and alternative transaction path are useful without it because users can choose `DisabledImmediately`.

### Reference program

The accompanying `pqauth-solana` repository demonstrates the state machine at the program layer:

- chunked ML-DSA-44 key and signature accounts;
- dual-authority seal;
- PQ-only key rotation;
- sequence-bound one-time permits;
- a program-derived asset/CPI vault.

It does not itself alter signer semantics for the original address. Importing records from that program into the native registry is deliberately not automatic. A future import path may be specified only after the reference program ID, immutable deployment state, account format, and audit status are fixed by a separate proposal or feature.

## Edge Cases

### Descriptor supplied but no alternative declaration

The descriptor is an ordinary read-only account. It has no effect on signer status.

### Alternative declaration for an unsealed descriptor

The transaction is rejected.

### Key rotated between signing and execution

The transaction read-locks the descriptor. If rotation lands first, the old generation/key no longer matches and the transaction is rejected. If the transaction lands first, the rotation executes afterward against the incremented state as normal.

### Duplicate subject

Rejected during sanitization, even if signatures are identical.

### Subject also listed as legacy signer

Rejected to avoid ambiguous policy, signature ordering, and fee accounting.

### Descriptor or key record writable

Rejected before execution. Alternative authorization cannot rely on state that the same transaction mutates.

### Address lookup tables

Descriptor and key indexes are evaluated after lookup resolution. Implementations must use the final loaded-key index space and enforce read-only status after privilege de-duplication.

### Durable nonces

The durable-nonce instruction, nonce account, and recent-blockhash semantics are already part of the signed `MessageV2`. Alternative signatures therefore receive the same replay protection as normal transaction signatures.

### Multiple alternative signers

Allowed, subject to transaction-size and compute limits. The transaction is accepted only if all proofs verify. ML-DSA-44 signature size naturally limits the practical count in a single packet.

### Program-derived subject

A PDA has no Ed25519 legacy signer and cannot initialize a descriptor through the V1 enrollment path. Program-controlled authority migration remains the responsibility of the owning program.

### Lost post-quantum key

There is no Ed25519 fallback after `DisabledImmediately` or a cluster cutoff. Recovery, if desired, must be committed before loss through a separately specified threshold, timelock, or guardian policy. This proposal intentionally does not add discretionary social recovery.

### Failed native verifier or scheme break

A new scheme requires an explicit feature and a rotation authorized by the currently active scheme. If the current scheme is already forgeable before users rotate, cryptographic ownership is again ambiguous; no protocol can reconstruct it retroactively.

## Validator Components Affected

- transaction deserialization and version dispatch;
- packet and signature-count sanitization;
- address-table resolution;
- account loading and read-lock construction;
- signature verification stage;
- transaction cost model and compute metering;
- loaded-message signer-bit construction;
- native/core registry program;
- replay and banking-stage error reporting;
- RPC transaction encoding/decoding and simulation;
- hardware-wallet and SDK signing-message construction.

The banking stage must not forward an alternative-authorized transaction to execution until all alternative proofs have passed.

## Alternatives Considered

### Move assets to new post-quantum addresses

This is the simplest cryptographic model but changes every address and authority. It does not preserve embedded identities and creates a large application-level migration burden.

### Store a commitment in an ordinary BPF program only

Useful as a historical precommitment and vault controller, but it cannot cause the runtime or System Program to treat the original address as post-quantum authorized. It also depends on the deployed program's upgrade policy.

### Allow Ed25519 to replace the post-quantum key

Rejected. After a quantum break, an attacker can derive the same Ed25519 private key and install an attacker-controlled post-quantum key.

### Hash-chain or one-time-signature migration only

Hash-based signatures offer conservative assumptions but have larger state/signature tradeoffs and operational complexity. The scheme registry permits a future hash-based option without changing the sealed-descriptor invariant.

### Verify ML-DSA inside every application program

Rejected as the primary migration path. It duplicates expensive cryptography, produces inconsistent policies, and cannot preserve generic runtime signer semantics.

### Hide the registry lookup inside the runtime

Rejected. An implicit lookup complicates account locking, fee calculation, and deterministic execution. Explicit descriptor/key accounts make dependencies visible to the transaction scheduler.

### Put the complete public key in every transaction

Rejected. The key is stable state and 1,312 bytes. Loading a canonical key record preserves packet space and lets the runtime verify its hash and lineage.

### Treat a signature-verification precompile result as a signer

A normal precompile instruction executes in the instruction stream and does not safely alter pre-execution signer privileges. Alternative authorization must be resolved before any program instruction executes.

## Impact

### Positive

- preserves existing account addresses and program interfaces;
- creates a migration path before Ed25519 is endangered;
- supports gas sponsorship because the PQ subject need not be the fee payer;
- allows gradual opt-in and immediate PQ-only policy;
- centralizes cryptographic verification and metering;
- gives applications a normal signer bit rather than a new per-program convention.

### Costs

- larger transaction signatures;
- descriptor and key-account reads;
- native verifier implementation and audit burden;
- wallet, SDK, RPC, explorer, and hardware-signer updates;
- higher verification cost than Ed25519;
- additional consensus surface and feature activation complexity.

### Performance

Implementations should batch ML-DSA verification when profitable, but batching must not change accept/reject semantics. The cost model should charge per proof and key-byte load. Transaction admission may cap alternative proofs per transaction independently of the generic signature count.

## Security Considerations

### Sealing is the security boundary

An unsealed record is not sufficient. A post-break attacker with the Ed25519 key can still select an attacker key before seal. Wallets, RPCs, and explorers must display `Unsealed` prominently and must not label it quantum-protected.

### Historical ordering

The `sealed_slot` is consensus state. Any cutoff relies on the descriptor being sealed strictly before the cutoff slot. Equality is rejected to avoid boundary ambiguity.

### Domain and chain separation

Every proof includes a domain, genesis hash, registry program ID, descriptor, and subject. A proof from another cluster, fork, program deployment, or operation cannot be replayed.

### Downgrade resistance

Scheme identifiers and policies are signed. Unknown schemes are rejected. Legacy policy only moves toward more restrictive states.

### Descriptor substitution

The descriptor PDA, stored subject, key record, key hash, generation, and scheme are all validated. The transaction signs the descriptor and key indexes through the canonical message.

### Account privilege de-duplication

Signer synthesis occurs only after Solana's account-key de-duplication. A writable alias of the descriptor or key account causes rejection.

### Denial of service

Malformed large signatures must have bounded verification cost. Packet admission should reject impossible lengths before account loading. Native verification receives a fixed compute charge or a deterministic charge based only on the scheme and public input lengths.

### Side channels

Verification uses public data, so secret side channels are not a validator concern. Wallet signing implementations do handle secret ML-DSA material and require separate constant-time and fault-resistance review.

### Upgrade governance

The native registry's sealed-state semantics are consensus rules. A future upgrade may add schemes or account versions but must not create a transition in which Ed25519 alone modifies a sealed descriptor.

## Drawbacks

- It adds significant complexity for a threat that may remain distant.
- ML-DSA signatures consume a large fraction of a transaction packet.
- Users can permanently lose access by sealing without a sound key-backup or recovery plan.
- The cluster may carry long-lived registry state for accounts that never switch to PQ authorization.
- A future preferred post-quantum scheme may differ from ML-DSA-44, requiring additional verifier work.
- A cluster-wide cutoff is socially and operationally difficult and does not solve uncommitted accounts.

## Backwards Compatibility

The feature is opt-in and transaction-version gated.

- Legacy transactions are unchanged.
- Accounts without descriptors are unchanged.
- Existing programs receive the same `AccountInfo.key` and `is_signer` values.
- Existing serialized program instructions are unchanged.
- Nodes that do not understand the new transaction version reject it before feature activation and must upgrade before the feature is activated.

A subject choosing `DisabledImmediately` intentionally changes which transaction versions can authorize it. Wallets must warn that legacy-only software can no longer operate that account.

## Conformance

A conforming implementation must pass consensus vectors covering at least:

1. valid ML-DSA-44 FIPS 204 signatures;
2. malformed public-key and signature encodings;
3. wrong context, domain, genesis hash, subject, descriptor, generation, and key hash;
4. unsealed descriptor rejection;
5. Ed25519-only mutation rejection after seal;
6. policy downgrade rejection;
7. skipped or repeated generation rejection;
8. duplicate subject declaration rejection;
9. subject present in both legacy and alternative signer sets;
10. writable descriptor/key rejection after privilege de-duplication;
11. address-table index resolution;
12. key rotation races;
13. pre-cutoff, at-cutoff, and post-cutoff sealed slots;
14. unknown schemes;
15. transaction mutation after signature;
16. multiple alternative signers with one invalid proof;
17. maximum-size and truncated encodings;
18. cross-architecture deterministic results.

Runtime integration tests must assert that an existing program sees the original subject key with `is_signer == true` after a valid alternative proof and `false` or transaction rejection otherwise.

## Appendix A: Rollout

Recommended rollout:

1. standardize the registry account formats and canonical digests;
2. land the ML-DSA-44 native verifier behind an inactive feature;
3. deploy the registry and enable voluntary enrollment/sealing;
4. add RPC, SDK, hardware-signer, explorer, and wallet support;
5. activate versioned alternative-authorized transactions on test clusters;
6. conduct performance, consensus, and adversarial campaigns;
7. activate on mainnet with no cluster cutoff;
8. encourage users to choose `DisabledImmediately` only after recovery and wallet support mature;
9. retain the cutoff feature as an independently governed emergency mechanism.

## Appendix B: Reference Implementation Mapping

| SIMD concept | Reference repository component |
|---|---|
| Descriptor | `RootAccount` |
| Key record | `KeyAccountHeader` + encoded public-key bytes |
| Proof upload | `SignatureAccountHeader` + encoded signature bytes |
| Seal | `Seal` instruction |
| Rotation | `Rotate` instruction |
| Replay sequence | `RootAccount.sequence` |
| One-time intent | `PermitAccount` |
| Immediate custody | vault PDA and exact-action CPI/lamport execution |
| Native signer synthesis | proposal only; not possible in the BPF prototype |

## Appendix C: References

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard.
- Solana Improvement Documents repository and proposal template.
- Existing Solana signature-verification precompile proposals, including SIMD-0152.
- The `pqauth-solana` reference implementation shipped with this draft.
