#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <program-keypair.json>" >&2
  exit 2
fi

if ! command -v solana >/dev/null 2>&1; then
  echo "solana CLI is required" >&2
  exit 1
fi

keypair=$1
if [[ ! -f "$keypair" ]]; then
  echo "keypair not found: $keypair" >&2
  exit 1
fi

new_id=$(solana address -k "$keypair")
if [[ ! "$new_id" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]; then
  echo "solana CLI returned an invalid program address: $new_id" >&2
  exit 1
fi

python3 - "$new_id" <<'PY'
from pathlib import Path
import re
import sys

new_id = sys.argv[1]
paths = [
    Path("programs/pqauth/src/lib.rs"),
    Path("crates/pqauth-client/src/lib.rs"),
]
pattern = re.compile(r"8RRuQaeSmnYJJkkC2qAYNnNbzjW3eCexQSUbpHZVJv9U|(?<=declare_id!\(\")[1-9A-HJ-NP-Za-km-z]{32,44}(?=\"\))|(?<=from_str_const\(\")[1-9A-HJ-NP-Za-km-z]{32,44}(?=\"\))")

for path in paths:
    text = path.read_text(encoding="utf-8")
    updated, count = pattern.subn(new_id, text)
    if count != 1:
        raise SystemExit(f"expected exactly one program ID in {path}, found {count}")
    path.write_text(updated, encoding="utf-8")

print(new_id)
PY
