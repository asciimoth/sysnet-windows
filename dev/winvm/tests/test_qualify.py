#!/usr/bin/env python3
"""Tests for Windows qualification evidence validation."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "qualify.py"
REVISION = "a" * 40


class QualificationTest(unittest.TestCase):
    def run_validator(self, mutate=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix = {
                "schemaVersion": 1,
                "driverLock": "driver-lock.json",
                "testManifest": "test-manifest.json",
                "driver": {"version": "1.3.0.0", "upstreamCommit": "upstream"},
                "requiredPacketCases": ["tcp4", "udp6"],
                "entries": [{
                    "id": "fixture", "architecture": "arm64",
                    "osCaptionPattern": "^Fixture Windows$", "minimumBuild": 42,
                    "productType": 1,
                }],
            }
            common = {
                "schemaVersion": 1, "outcome": "passed",
                "sysnetWindowsRevision": REVISION, "sysnetWindowsTreeState": "clean",
                "architecture": "arm64",
                "os": {"caption": "Fixture Windows", "version": "1.2.42", "build": "42", "productType": 1},
            }
            values = {
                "native": {**common, "suite": "native-unit", "requiredTests": ["native"]},
                "live": {
                    **common,
                    "suite": "live-driver",
                    "requiredTests": [
                        "TestDriverLifecycle",
                        "TestOwnedNetworkingCleanup",
                        "TestDNSConfigurationRestoration",
                        "TestSystemCloseAfterSplitResetFailure",
                    ],
                },
                "flow": {
                    **common,
                    "suite": "packet-flow",
                    "requiredTests": [
                        "TestPacketFlowPublicAPI",
                        "TestPacketFlowUnderlayBypass",
                    ],
                },
            }
            for name in ("live", "flow"):
                values[name]["driver"] = {
                    "version": "1.3.0.0", "upstreamCommit": "upstream",
                    "finalState": "Stopped", "files": {"driver.sys": "hash"},
                    "packageSigner": "CN=Mullvad VPN AB",
                }
            packets = [
                {"case": "tcp4", "packetPathValid": True},
                {"case": "udp6", "packetPathValid": True},
            ]
            if mutate:
                mutate(matrix, values, packets)
            (root / "matrix.json").write_text(json.dumps(matrix), encoding="utf-8")
            (root / "driver-lock.json").write_text(json.dumps({
                "version": "1.3.0.0", "upstreamCommit": "upstream",
                "architectures": {"arm64": {"files": {"driver.sys": "hash"}}}
            }), encoding="utf-8")
            (root / "test-manifest.json").write_text(json.dumps({
                "schemaVersion": 1,
                "suites": {
                    "native-unit": {"requiredTests": ["native"]},
                    "live-driver": {"requiredTests": [
                        "TestDriverLifecycle",
                        "TestOwnedNetworkingCleanup",
                        "TestDNSConfigurationRestoration",
                        "TestSystemCloseAfterSplitResetFailure",
                    ]},
                    "packet-flow": {"requiredTests": [
                        "TestPacketFlowPublicAPI",
                        "TestPacketFlowUnderlayBypass",
                    ]},
                },
            }), encoding="utf-8")
            for name, value in values.items():
                (root / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
            (root / "packets.json").write_text(json.dumps(packets), encoding="utf-8")
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--matrix", str(root / "matrix.json"),
                "--entry", "fixture", "--native-unit", str(root / "native.json"),
                "--live-driver", str(root / "live.json"), "--packet-flow", str(root / "flow.json"),
                "--packet-evidence", str(root / "packets.json"), "--output", str(root / "result.json"),
            ], check=False, capture_output=True, text=True)
            output = json.loads((root / "result.json").read_text()) if (root / "result.json").exists() else None
            return result, output

    def test_accepts_complete_matching_evidence(self):
        result, output = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["outcome"], "qualified")
        self.assertEqual(output["packetObservations"], 2)
        self.assertEqual(len(output["evidenceSha256"]), 7)

    def test_rejects_mismatched_or_incomplete_evidence(self):
        cases = [
            lambda _m, values, _p: values["flow"].update(architecture="amd64"),
            lambda _m, values, _p: values["live"].update(sysnetWindowsRevision="b" * 40),
            lambda _m, values, _p: values["live"].update(sysnetWindowsTreeState="dirty"),
            lambda _m, values, _p: values["live"].update(requiredTests=[]),
            lambda _m, values, _p: values["flow"]["driver"].update(version="wrong"),
            lambda _m, _v, packets: packets.clear(),
            lambda _m, _v, packets: packets[0].update(packetPathValid=False),
            lambda _m, _v, packets: packets.pop(),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                result, output = self.run_validator(mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(output)


if __name__ == "__main__":
    unittest.main()
