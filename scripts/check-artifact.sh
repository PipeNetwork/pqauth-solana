#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tests/generate_vectors.py >/dev/null
python3 -m unittest discover -s tests -p 'test_*.py' -v
node tests/verify_vectors.mjs

if command -v cargo >/dev/null 2>&1; then
  cargo fmt --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
else
  echo "warning: cargo not installed; Rust checks skipped" >&2
fi
