# Solana PQAuth

A reference implementation and standards proposal for migrating an existing Solana Ed25519 identity to post-quantum authorization without allowing a future Ed25519 compromise to replace the post-quantum key.

This repository contains two related deliverables:

1. **A deployable Solana program prototype**: an immutable-style commitment registry, ML-DSA-44 key lineage, one-time authorization permits, and a PQ-controlled PDA vault.
2. **A SIMD proposal**: a consensus/runtime path that preserves the original 32-byte account address while changing how that address satisfies signer authorization.

> **Prototype status:** experimental, unaudited, and not production-safe. The code performs ML-DSA-44 verification in SBF software. The SIMD proposes a consensus-metered native verifier before production deployment.

## Security invariant

Once a root is sealed, an Ed25519 signature alone cannot:

- replace or remove the active post-quantum key;
- rotate the key lineage;
- authorize a vault action; or
- lower the authorization policy.

The initial Ed25519 key can select a generation-0 key only while the root is unsealed. Sealing requires both the Ed25519 signer and a valid ML-DSA-44 signature by the selected key. Every later mutation requires the active post-quantum key.

## Repository map

```text
crates/pqauth-core/       Canonical account layouts, instruction codec, digest preimages
crates/pqauth-client/     PDA helpers, digest helpers, instruction builders
programs/pqauth/          Solana on-chain program
tools/pqauth-cli/         Offline ML-DSA key/signature/PDA/account utility
simd/                     SIMD-style runtime proposal
docs/                     Architecture, wire format, threat model, deployment notes
crates/pqauth-client/examples/  Client-side transaction construction example
tests/                    Independent state-model and digest-vector checks
```

## Protocol flow

```text
Ed25519 wallet
    |
    | initialize root
    v
unsealed root ---- upload ML-DSA public key ----> key record
    |                                               |
    |                          ML-DSA proof of possession
    |                                               v
    |                                        finalized key
    |                                               |
    | Ed25519 selects generation 0                  |
    +-----------------------------------------------+
    |
    | Ed25519 + active ML-DSA signature
    v
SEALED ROOT  ---- ML-DSA only ----> rotate / authorize permit / operate vault
```

Public keys and signatures are uploaded in append-only chunks. That avoids putting the 1,312-byte ML-DSA-44 public key or 2,420-byte signature in one instruction and makes the wire format usable across transaction-size regimes.

## Accounts

| Account | PDA seeds | Purpose |
|---|---|---|
| Root | `['root', legacy_address]` | Immutable legacy binding, active PQ key, generation, sequence |
| Key | `['key', root, generation_le, key_id]` | Uploaded ML-DSA-44 public key and finalized hash |
| Signature | `['sig', root, operation_id]` | Staged ML-DSA signature and signed operation metadata |
| Vault | `['vault', root]` | Program-owned SOL/SPL/CPI authority |
| Permit | `['permit', root, sequence_le]` | One-time, expiring authorization for an exact action digest |

See [docs/WIRE_FORMAT.md](docs/WIRE_FORMAT.md) for byte layouts and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full state machine.

## Build

Prerequisites:

- Rust 1.98.1 or a compatible newer stable toolchain
- an Agave/Solana installation providing `cargo-build-sbf`
- Solana CLI for deployment

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build-sbf --manifest-path programs/pqauth/Cargo.toml
```

The repository uses a reference program ID in source. Generate a deployment keypair and synchronize its address before deploying:

```bash
solana-keygen new \
  --no-bip39-passphrase \
  --outfile target/deploy/pqauth_program-keypair.json

./scripts/sync-program-id.sh target/deploy/pqauth_program-keypair.json
cargo build-sbf --manifest-path programs/pqauth/Cargo.toml
solana program deploy \
  target/deploy/pqauth_program.so \
  --program-id target/deploy/pqauth_program-keypair.json
```

For an audit candidate, deploy once under a governed upgrade authority, complete audits and compute benchmarking, then set the program upgrade authority to `none`. The commitment semantics are not meaningful if a unilateral program upgrade can rewrite them.

## Offline CLI

Generate a seed and public key:

```bash
cargo run -p pqauth-cli -- keygen \
  --seed-out ~/.config/pqauth/root.seed \
  --public-out ~/.config/pqauth/root.pub
```

Compute a root PDA:

```bash
cargo run -p pqauth-cli -- pda root --legacy <SOLANA_ADDRESS>
```

Sign a 32-byte protocol digest:

```bash
cargo run -p pqauth-cli -- sign \
  --seed ~/.config/pqauth/root.seed \
  --digest <64_HEX_CHARS> \
  --out /tmp/pqauth.sig
```

The CLI intentionally does not transmit transactions or read seed material from a remote RPC host. Transaction construction is provided by `pqauth-client`; signing and submission should remain in the wallet or HSM boundary.

## Deployable protection versus native migration

The program can protect assets **today only after those assets or authorities are moved under the PQAuth vault PDA**. A standalone registry cannot stop the System Program from accepting a valid Ed25519 signature against SOL still held directly by the legacy keypair.

The SIMD adds native alternative authorization. A transaction supplies the sealed authorization descriptor and an ML-DSA proof for the original address. After verification, the runtime marks that original account as a signer. Existing programs continue to see the same address and `is_signer == true`.

## Verification status

See [VERIFICATION.md](VERIFICATION.md). Independent Python and Node checks are included for canonical digest vectors and transition invariants. Rust/SBF compilation must be run in an environment with Cargo and the Agave SBF toolchain before deployment.

## Documents

- [Architecture](docs/ARCHITECTURE.md)
- [Wire format](docs/WIRE_FORMAT.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Deployment and immutability](docs/DEPLOYMENT.md)
- [SIMD proposal](simd/xxxx-post-quantum-alternative-account-authorization.md)
- [Verification record](VERIFICATION.md)

## License

Apache-2.0 OR MIT.
# pqauth-solana
