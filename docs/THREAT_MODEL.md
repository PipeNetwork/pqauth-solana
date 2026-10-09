# Threat Model

## Security objective

A root sealed before a credible Ed25519 break must remain controlled by its post-quantum key lineage even if an attacker later obtains the corresponding Ed25519 private scalar.

## Assumptions

- SHA-256 remains collision and second-preimage resistant for the protocol lifetime.
- ML-DSA-44 remains unforgeable under the selected security model.
- Solana consensus faithfully preserves slots and finalized account history.
- The deployed program binary and program ID match the reviewed source.
- Before production use, the program is independently audited and its upgrade path is removed or placed behind a sufficiently strong, transparent governance process.
- The user's PQ seed is generated and stored in a trustworthy wallet, HSM, or offline system.

## Adversaries considered

### Quantum recovery of the legacy Ed25519 key

After sealing, Ed25519 appears in no rotation or spend authorization path. Recovering the legacy private key does not produce an ML-DSA signature and cannot mutate the sealed root.

### Malicious transaction relayer

A relayer can observe, delay, reorder, or submit signed operations. It cannot alter target accounts, flags, instruction data, recipient, amount, validity window, root, vault, or sequence without invalidating the digest.

A relayer may execute a valid permit before its owner. That is intentional: the outcome is already exact, and the relayer only pays transaction fees.

### Replay attacker

Every post-seal mutation is bound to the current root sequence. Authorizing an action increments that sequence and creates a permit PDA derived from the consumed value. A permit is single-use and is closed after successful execution.

### Account-substitution attacker

Every account loader validates:

- owner;
- exact data length and magic;
- protocol version;
- PDA derivation and stored bump;
- root/key/vault relationships;
- active key hash and generation.

### Prefunded-PDA denial of service

An attacker can transfer lamports to a predictable PDA before initialization. Account creation therefore does not rely on `create_account` against a zero-lamport address. It tops up the prefunded system account to rent exemption, then invokes `allocate` and `assign` with PDA signer seeds.

### CPI privilege escalation

Only the vault PDA may be marked as a signer in the signed CPI meta list. The processor rejects signer elevation for every other address and signs only with vault seeds.

### Reentrancy or recursive authorization mutation

The target program may not be PQAuth itself. Root, permit, refund, target program, and PQAuth program addresses are forbidden in the downstream account list. The permit is marked consumed before CPI; if CPI fails, Solana transaction atomicity rolls back that write and the whole transaction.

### Expired permit scavenger

Anyone may close an expired permit only to its immutable refund address. This prevents stranded rent without allowing theft of the rent reserve.

### Malicious uploader

Uploads are append-only and bound to an uploader. A key is not finalized without an ML-DSA proof of possession. The uploader identity is not an authorization authority after finalization.

### Program upgrade authority

An upgrade authority can replace the verifier or state machine. A production root should not be represented as irreversible while such unilateral authority exists. See `DEPLOYMENT.md`.

## Known prototype limitations

1. **Unaudited cryptographic integration.** RustCrypto's encoding and API are used directly; the integration needs independent vectors and audit.
2. **Compute cost.** ML-DSA-44 verification in SBF software may exceed practical compute budgets. The SIMD requires a native consensus-metered path.
3. **Vault migration required today.** Assets left under the original Ed25519 address remain vulnerable to a valid legacy signature.
4. **No social recovery.** Loss of the active PQ secret permanently loses control. Recovery policies require a separately specified threshold or delayed mechanism.
5. **No token-specific convenience layer.** The generic CPI vault can own token accounts, but production wallet UX and allow-listing policies are not included.
6. **No formal verification.** The state machine has executable model tests but no mechanized proof.
7. **One scheme in v1.** Account fields are crypto-agile, but this implementation accepts only scheme ID 1, ML-DSA-44.

## Operations guidance

- Seal immediately after verifying the displayed PQ public-key fingerprint.
- Treat an unsealed root as informational only.
- Keep the generation-0 seed offline; use a separately generated next-generation key for rotation drills.
- Test a full rotate and vault action on a non-production cluster.
- Never expose the PQ seed to an RPC server, browser extension content script, or transaction relayer.
