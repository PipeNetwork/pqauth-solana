#!/usr/bin/env python3
"""Generate canonical PQAuth digest vectors without Rust dependencies."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROGRAM_ID = bytes.fromhex(
    "6e43e80d06a8cc9a95ab9b6662833275d44756b605e4df83b6d21bebca8c5647"
)
CHAIN_ID = bytes.fromhex("11" * 32)
ROOT_ADDRESS = bytes.fromhex("22" * 32)
OLD_KEY = bytes.fromhex("33" * 32)
NEW_KEY = bytes.fromhex("44" * 32)
VAULT = bytes.fromhex("55" * 32)
RECIPIENT = bytes.fromhex("66" * 32)
TARGET_PROGRAM = bytes.fromhex("77" * 32)
OLD_HASH = bytes.fromhex("88" * 32)
NEW_HASH = bytes.fromhex("99" * 32)
KEY_ID = bytes.fromhex("aa" * 16)


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def common(domain: bytes) -> bytes:
    return u16(len(domain)) + domain + PROGRAM_ID + CHAIN_ID + ROOT_ADDRESS


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def key_pop() -> tuple[bytes, bytes]:
    domain = b"SOLANA_PQAUTH_KEY_POP_V1"
    preimage = common(domain) + u32(0) + KEY_ID + bytes([1]) + OLD_HASH
    return preimage, sha(preimage)


def seal() -> tuple[bytes, bytes]:
    domain = b"SOLANA_PQAUTH_SEAL_V1"
    preimage = common(domain) + u64(0) + OLD_KEY + OLD_HASH
    return preimage, sha(preimage)


def rotate() -> tuple[bytes, bytes]:
    domain = b"SOLANA_PQAUTH_ROTATE_V1"
    preimage = (
        common(domain)
        + u64(7)
        + OLD_KEY
        + OLD_HASH
        + NEW_KEY
        + NEW_HASH
        + u32(1)
    )
    return preimage, sha(preimage)


def cpi() -> tuple[bytes, bytes]:
    domain = b"SOLANA_PQAUTH_EXECUTE_CPI_V1"
    metas = [
        (bytes.fromhex("ab" * 32), 0x01),
        (VAULT, 0x03),
        (bytes.fromhex("cd" * 32), 0x00),
    ]
    instruction_data = bytes.fromhex("01020304aabbcc")
    preimage = (
        common(domain)
        + VAULT
        + u64(8)
        + u64(1_000)
        + u64(1_200)
        + TARGET_PROGRAM
        + u16(len(metas))
        + b"".join(address + bytes([flags]) for address, flags in metas)
        + u32(len(instruction_data))
        + instruction_data
    )
    return preimage, sha(preimage)


def lamports() -> tuple[bytes, bytes]:
    domain = b"SOLANA_PQAUTH_EXECUTE_LAMPORTS_V1"
    preimage = (
        common(domain)
        + VAULT
        + u64(9)
        + u64(2_000)
        + u64(2_100)
        + RECIPIENT
        + u64(123_456_789)
    )
    return preimage, sha(preimage)


def main() -> None:
    cases = {}
    for name, function in {
        "key_pop": key_pop,
        "seal": seal,
        "rotate": rotate,
        "execute_cpi": cpi,
        "execute_lamports": lamports,
    }.items():
        preimage, digest = function()
        cases[name] = {
            "preimage_hex": preimage.hex(),
            "sha256_hex": digest.hex(),
        }

    output = {
        "version": 1,
        "program_id_base58": "8RRuQaeSmnYJJkkC2qAYNnNbzjW3eCexQSUbpHZVJv9U",
        "program_id_hex": PROGRAM_ID.hex(),
        "chain_id_hex": CHAIN_ID.hex(),
        "root_hex": ROOT_ADDRESS.hex(),
        "cases": cases,
    }
    path = ROOT / "vectors.json"
    path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
