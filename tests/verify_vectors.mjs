#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8"));

const hex = (value) => Buffer.from(value, "hex");
const u16 = (value) => {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value);
  return out;
};
const u32 = (value) => {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
};
const u64 = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
};
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const program = hex(vectors.program_id_hex);
const chain = hex(vectors.chain_id_hex);
const root = hex(vectors.root_hex);
const oldKey = Buffer.alloc(32, 0x33);
const newKey = Buffer.alloc(32, 0x44);
const vault = Buffer.alloc(32, 0x55);
const recipient = Buffer.alloc(32, 0x66);
const targetProgram = Buffer.alloc(32, 0x77);
const oldHash = Buffer.alloc(32, 0x88);
const newHash = Buffer.alloc(32, 0x99);
const keyId = Buffer.alloc(16, 0xaa);

function common(domainText) {
  const domain = Buffer.from(domainText, "utf8");
  return Buffer.concat([u16(domain.length), domain, program, chain, root]);
}

const independentlyConstructed = {
  key_pop: Buffer.concat([
    common("SOLANA_PQAUTH_KEY_POP_V1"),
    u32(0),
    keyId,
    Buffer.from([1]),
    oldHash,
  ]),
  seal: Buffer.concat([
    common("SOLANA_PQAUTH_SEAL_V1"),
    u64(0),
    oldKey,
    oldHash,
  ]),
  rotate: Buffer.concat([
    common("SOLANA_PQAUTH_ROTATE_V1"),
    u64(7),
    oldKey,
    oldHash,
    newKey,
    newHash,
    u32(1),
  ]),
  execute_cpi: Buffer.concat([
    common("SOLANA_PQAUTH_EXECUTE_CPI_V1"),
    vault,
    u64(8),
    u64(1000),
    u64(1200),
    targetProgram,
    u16(3),
    Buffer.alloc(32, 0xab), Buffer.from([0x01]),
    vault, Buffer.from([0x03]),
    Buffer.alloc(32, 0xcd), Buffer.from([0x00]),
    u32(7),
    Buffer.from("01020304aabbcc", "hex"),
  ]),
  execute_lamports: Buffer.concat([
    common("SOLANA_PQAUTH_EXECUTE_LAMPORTS_V1"),
    vault,
    u64(9),
    u64(2000),
    u64(2100),
    recipient,
    u64(123456789),
  ]),
};

for (const [name, preimage] of Object.entries(independentlyConstructed)) {
  const expected = vectors.cases[name];
  assert.equal(preimage.toString("hex"), expected.preimage_hex, `${name} preimage`);
  assert.equal(sha256(preimage), expected.sha256_hex, `${name} digest`);
}

console.log(`verified ${Object.keys(independentlyConstructed).length} canonical PQAuth vectors`);
