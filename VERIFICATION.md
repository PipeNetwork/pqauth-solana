# Verification Record

## Completed in this artifact build

- Reviewed the account layouts, PDA relationships, instruction codec, and signed preimages for internal consistency.
- Added Rust unit tests for account round trips, instruction round trips, deterministic PDAs, and upload chunking.
- Added an independent Python state-model test covering registration, dual-authority seal, PQ-only rotation, authorization replay rejection, permit consumption, and legacy-key rejection after seal.
- Added cross-language canonical digest vectors generated in Python and verified independently in Node.js.
- Added static repository checks for duplicate instruction tags, account-layout bounds, placeholder/TODO markers, and brace balance.

## Environment limitation

The artifact container used to assemble this repository did not contain Rust/Cargo or the Agave SBF toolchain, and outbound package download/DNS was unavailable. Therefore the Rust workspace and SBF ELF were **not compiled in this environment**.

Before deploying, run:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build-sbf --manifest-path programs/pqauth/Cargo.toml
python3 -m unittest discover -s tests -p 'test_*.py'
node tests/verify_vectors.mjs
```

Compilation and runtime integration remain required acceptance gates. This repository is a serious prototype, not an audited production release.
