#!/usr/bin/env python3
"""Dependency-free static consistency checks for the source artifact."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StaticChecks(unittest.TestCase):
    def test_no_unresolved_todos_in_rust(self) -> None:
        for path in ROOT.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\b(TODO|FIXME|unimplemented!|todo!)\b", str(path))

    def test_braces_are_balanced_in_rust(self) -> None:
        # This is not a parser; it catches accidental truncation in this generated artifact.
        for path in ROOT.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            for opening, closing in [("{", "}"), ("(", ")"), ("[", "]")]:
                self.assertEqual(text.count(opening), text.count(closing), str(path))

    def test_instruction_tags_are_unique(self) -> None:
        text = (ROOT / "crates/pqauth-core/src/instruction.rs").read_text(encoding="utf-8")
        enum_body = re.search(r"enum InstructionTag \{(.*?)\n\}", text, re.S)
        self.assertIsNotNone(enum_body)
        values = [int(v) for v in re.findall(r"=\s*(\d+),", enum_body.group(1))]
        self.assertEqual(len(values), len(set(values)))
        self.assertEqual(values, list(range(16)))

    def test_account_layout_constants(self) -> None:
        text = (ROOT / "crates/pqauth-core/src/constants.rs").read_text(encoding="utf-8")
        self.assertIn("ROOT_ACCOUNT_LEN: usize = 192", text)
        self.assertIn("KEY_HEADER_LEN: usize = 160", text)
        self.assertIn("ML_DSA_44_PUBLIC_KEY_LEN: usize = 1_312", text)
        self.assertIn("SIGNATURE_HEADER_LEN: usize = 192", text)
        self.assertIn("ML_DSA_44_SIGNATURE_LEN: usize = 2_420", text)
        self.assertIn("PERMIT_ACCOUNT_LEN: usize = 192", text)

    def test_program_id_matches_client(self) -> None:
        program = (ROOT / "programs/pqauth/src/lib.rs").read_text(encoding="utf-8")
        client = (ROOT / "crates/pqauth-client/src/lib.rs").read_text(encoding="utf-8")
        ids = re.findall(r"8RRuQaeSmnYJJkkC2qAYNnNbzjW3eCexQSUbpHZVJv9U", program + client)
        self.assertEqual(len(ids), 2)


if __name__ == "__main__":
    unittest.main()
