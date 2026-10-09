# Deployment and Immutability

## 1. Select the chain identifier

`chain_id` is a fixed 32-byte deployment identifier included in every signed digest. It must be unique across clusters and forks. Recommended value:

```text
SHA256("SOLANA_PQAUTH_CHAIN_V1" || genesis_hash || pqauth_program_id)
```

Do not use an all-zero value. Publish the selected value with deployment metadata.

## 2. Generate and synchronize a program ID

```bash
solana-keygen new \
  --no-bip39-passphrase \
  --outfile target/deploy/pqauth_program-keypair.json

./scripts/sync-program-id.sh target/deploy/pqauth_program-keypair.json
```

The script updates both the on-chain `declare_id!` and the client constant. Review the resulting diff.

## 3. Build reproducibly

Pin:

- Rust toolchain;
- Agave/Solana SBF toolchain;
- Cargo dependency lockfile;
- source commit;
- build container digest.

Record the ELF hash and reproduce it on at least two independent machines.

```bash
cargo build-sbf --manifest-path programs/pqauth/Cargo.toml
sha256sum target/deploy/pqauth_program.so
```

## 4. Benchmark before deployment

At minimum measure:

- key proof verification;
- seal verification;
- rotation verification;
- authorization verification;
- maximum CPI meta and data paths;
- heap and stack use;
- compute units with malformed worst-case signatures.

Software ML-DSA verification is expected to be the gating item. Do not raise compute limits or ship a custom validator exception as a substitute for a consensus-wide verifier.

## 5. Audit gates

Recommended gates:

1. wire-format review and independent test vectors;
2. cryptographic integration review;
3. Solana account/privilege audit;
4. fuzz instruction decoding and account layouts;
5. differential tests against a second ML-DSA implementation;
6. localnet and testnet adversarial test campaigns;
7. reproducible-build validation.

## 6. Upgrade policy

A staged deployment may begin upgradeable, but a commitment is not irrevocable while one actor can change its semantics.

Before representing roots as production precommitments:

```bash
solana program set-upgrade-authority \
  <PROGRAM_ID> \
  --final
```

If governance is retained temporarily, publish:

- signer set;
- threshold;
- timelock;
- exact emergency powers;
- on-chain monitoring path;
- date and criteria for finalization.

## 7. Client ceremony

A safe registration ceremony should:

1. generate the ML-DSA seed offline;
2. display and independently verify the public-key SHA-256 fingerprint;
3. upload and finalize the key with proof of possession;
4. activate generation 0 with the legacy wallet;
5. recompute the seal digest on the offline signer;
6. sign with ML-DSA;
7. submit the seal transaction with the legacy signer;
8. verify `status = Sealed`, `sealed_slot > 0`, and the expected key hash from two RPC sources;
9. create and fund the vault;
10. perform a small authorized transfer and a key-rotation drill before moving significant assets.
