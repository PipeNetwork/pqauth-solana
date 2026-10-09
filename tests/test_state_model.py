#!/usr/bin/env python3
"""Executable security model for the PQAuth transition invariants."""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import dataclass, field
from enum import Enum, auto


class Status(Enum):
    UNSEALED = auto()
    SEALED = auto()


class KeyStatus(Enum):
    UPLOADING = auto()
    FINALIZED = auto()


@dataclass
class Key:
    generation: int
    material: bytes
    status: KeyStatus = KeyStatus.UPLOADING

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.material).digest()


@dataclass
class Permit:
    sequence: int
    digest: bytes
    consumed: bool = False


@dataclass
class Root:
    legacy: str
    status: Status = Status.UNSEALED
    active: Key | None = None
    generation: int = 0
    sequence: int = 0
    permits: dict[int, Permit] = field(default_factory=dict)

    def finalize_key(self, key: Key, proof_of_possession: bool) -> None:
        if not proof_of_possession:
            raise PermissionError("missing PQ proof of possession")
        expected = 0 if self.status is Status.UNSEALED else self.generation + 1
        if key.generation != expected:
            raise ValueError("wrong key generation")
        key.status = KeyStatus.FINALIZED

    def activate_initial(self, key: Key, legacy_authorized: bool) -> None:
        if self.status is not Status.UNSEALED:
            raise PermissionError("Ed25519 has no post-seal mutation path")
        if not legacy_authorized:
            raise PermissionError("legacy signer required")
        if key.status is not KeyStatus.FINALIZED or key.generation != 0:
            raise ValueError("invalid generation-0 key")
        self.active = key

    def seal(self, legacy_authorized: bool, pq_authorized: bool, sequence: int) -> None:
        if self.status is not Status.UNSEALED or self.active is None:
            raise ValueError("root cannot be sealed")
        if not legacy_authorized or not pq_authorized:
            raise PermissionError("dual authorization required")
        if sequence != self.sequence:
            raise ValueError("sequence mismatch")
        self.status = Status.SEALED
        self.sequence += 1

    def rotate(self, candidate: Key, pq_authorized: bool, sequence: int) -> None:
        if self.status is not Status.SEALED:
            raise ValueError("root is not sealed")
        if not pq_authorized:
            raise PermissionError("active PQ authorization required")
        if sequence != self.sequence:
            raise ValueError("sequence mismatch")
        if candidate.status is not KeyStatus.FINALIZED:
            raise ValueError("candidate is not finalized")
        if candidate.generation != self.generation + 1:
            raise ValueError("rotation must advance exactly one generation")
        self.active = candidate
        self.generation = candidate.generation
        self.sequence += 1

    def authorize(self, digest: bytes, pq_authorized: bool, sequence: int) -> Permit:
        if self.status is not Status.SEALED or not pq_authorized:
            raise PermissionError("PQ authorization required")
        if sequence != self.sequence:
            raise ValueError("sequence mismatch")
        permit = Permit(sequence=sequence, digest=digest)
        self.permits[sequence] = permit
        self.sequence += 1
        return permit

    def execute(self, permit: Permit, digest: bytes) -> None:
        if permit.consumed:
            raise ValueError("permit already consumed")
        if permit.digest != digest:
            raise PermissionError("digest substitution")
        permit.consumed = True


class PqAuthModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Root("legacy")
        self.k0 = Key(0, b"generation-zero-public-key")
        self.root.finalize_key(self.k0, proof_of_possession=True)
        self.root.activate_initial(self.k0, legacy_authorized=True)

    def test_seal_requires_both_authorities(self) -> None:
        with self.assertRaises(PermissionError):
            self.root.seal(True, False, 0)
        with self.assertRaises(PermissionError):
            self.root.seal(False, True, 0)
        self.root.seal(True, True, 0)
        self.assertEqual(self.root.status, Status.SEALED)
        self.assertEqual(self.root.sequence, 1)

    def test_ed25519_cannot_replace_key_after_seal(self) -> None:
        self.root.seal(True, True, 0)
        attacker = Key(0, b"attacker")
        attacker.status = KeyStatus.FINALIZED
        with self.assertRaises(PermissionError):
            self.root.activate_initial(attacker, legacy_authorized=True)
        self.assertIs(self.root.active, self.k0)

    def test_rotation_is_pq_only_and_strictly_sequential(self) -> None:
        self.root.seal(True, True, 0)
        k1 = Key(1, b"generation-one-public-key")
        self.root.finalize_key(k1, proof_of_possession=True)
        with self.assertRaises(PermissionError):
            self.root.rotate(k1, pq_authorized=False, sequence=1)
        with self.assertRaises(ValueError):
            self.root.rotate(k1, pq_authorized=True, sequence=2)
        self.root.rotate(k1, pq_authorized=True, sequence=1)
        self.assertIs(self.root.active, k1)
        self.assertEqual(self.root.generation, 1)
        self.assertEqual(self.root.sequence, 2)

    def test_authorize_consumes_sequence_and_permit_is_one_time(self) -> None:
        self.root.seal(True, True, 0)
        digest = hashlib.sha256(b"exact action").digest()
        permit = self.root.authorize(digest, pq_authorized=True, sequence=1)
        with self.assertRaises(ValueError):
            self.root.authorize(digest, pq_authorized=True, sequence=1)
        with self.assertRaises(PermissionError):
            self.root.execute(permit, hashlib.sha256(b"changed action").digest())
        self.root.execute(permit, digest)
        with self.assertRaises(ValueError):
            self.root.execute(permit, digest)

    def test_unproven_candidate_cannot_finalize(self) -> None:
        candidate = Key(0, b"unknown-owner-key")
        with self.assertRaises(PermissionError):
            self.root.finalize_key(candidate, proof_of_possession=False)


if __name__ == "__main__":
    unittest.main()
