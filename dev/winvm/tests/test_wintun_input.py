#!/usr/bin/env python3
"""Tests for the tunnel-demo Wintun input validator."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "wintun-input.py"


class PublicAPIInputTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "wintun-0.14.1.zip"
        self.lock = self.root / "lock.json"

    def write_archive(self, entries):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w") as archive:
                for name, data in entries:
                    archive.writestr(name, data)

    def write_lock(self, **changes):
        entry = {
            "version": "0.14.1",
            "file": "wintun-0.14.1.zip",
            "source": "https://www.wintun.net/builds/wintun-0.14.1.zip",
            "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        }
        entry.update(changes)
        self.lock.write_text(
            json.dumps({"schemaVersion": 1, "wintun": entry}), encoding="utf-8"
        )

    def run_tool(self, architecture="amd64", output=None):
        if output is None:
            output = self.root / f"{architecture}-wintun.dll"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--lock",
                str(self.lock),
                "--archive",
                str(self.archive),
                "--architecture",
                architecture,
                "--output",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        return result, output

    def test_extracts_exact_architecture_members(self):
        self.write_archive(
            [
                ("wintun/bin/amd64/wintun.dll", b"amd64-dll"),
                ("wintun/bin/arm64/wintun.dll", b"arm64-dll"),
            ]
        )
        self.write_lock()
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture):
                result, output = self.run_tool(architecture)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_bytes(), f"{architecture}-dll".encode())

    def test_rejects_hash_mismatch_without_output(self):
        self.write_archive([("wintun/bin/amd64/wintun.dll", b"dll")])
        self.write_lock(sha256="0" * 64)
        result, output = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertFalse(output.exists())

    def test_rejects_missing_duplicate_and_empty_members(self):
        cases = (
            ([], "has 0"),
            (
                [
                    ("wintun/bin/amd64/wintun.dll", b"first"),
                    ("wintun/bin/amd64/wintun.dll", b"second"),
                ],
                "has 2",
            ),
            ([("wintun/bin/amd64/wintun.dll", b"")], "invalid"),
        )
        for index, (entries, message) in enumerate(cases):
            with self.subTest(message=message):
                self.archive = self.root / f"case-{index}.zip"
                self.lock = self.root / f"case-{index}.json"
                self.write_archive(entries)
                self.write_lock()
                result, output = self.run_tool(output=self.root / f"case-{index}.dll")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(output.exists())

    def test_rejects_invalid_lock_identity(self):
        self.write_archive([("wintun/bin/amd64/wintun.dll", b"dll")])
        cases = (
            ({"version": "14", "file": "wintun-0.14.1.zip"}, "version"),
            ({"file": "../wintun.zip"}, "file name"),
            ({"source": "https://example.invalid/wintun-0.14.1.zip"}, "source"),
            ({"sha256": "not-a-hash"}, "SHA-256"),
        )
        for index, (changes, message) in enumerate(cases):
            with self.subTest(message=message):
                self.lock = self.root / f"invalid-{index}.json"
                self.write_lock(**changes)
                result, output = self.run_tool(output=self.root / f"invalid-{index}.dll")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(output.exists())

    def test_rejects_corrupt_archive_and_existing_output(self):
        self.archive.write_bytes(b"not a zip")
        self.write_lock()
        result, output = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a zip", result.stderr)
        self.assertFalse(output.exists())

        self.write_archive([("wintun/bin/amd64/wintun.dll", b"new")])
        self.write_lock()
        output.write_bytes(b"keep")
        result, output = self.run_tool(output=output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
