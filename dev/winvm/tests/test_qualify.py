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
SOURCE_HASH = "b" * 64
LOCKS = {"goMod": "c" * 64, "goSum": "d" * 64}


class QualificationTest(unittest.TestCase):
    def run_validator(self, mutate=None, driver_lock_mutate=None):
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
                "sourceArchiveSha256": SOURCE_HASH,
                "architecture": "arm64",
                "goVersion": "go version go1.25.5 windows/arm64",
                "dependencyLocks": LOCKS,
                "os": {"caption": "Fixture Windows", "version": "1.2.42", "build": "42", "productType": 1},
            }
            values = {
                "native": {
                    **common, "suite": "native-unit", "requiredTests": ["native"],
                    "testResults": {"native": "pass"},
                },
                "live": {
                    **common,
                    "suite": "live-driver",
                    "requiredTests": [
                        "TestDriverLifecycle",
                        "TestOwnedNetworkingCleanup",
                        "TestDNSConfigurationRestoration",
                        "TestSystemCloseAfterSplitResetFailure",
                    ],
                    "testResults": {
                        "TestDriverLifecycle": "pass",
                        "TestOwnedNetworkingCleanup": "pass",
                        "TestDNSConfigurationRestoration": "pass",
                        "TestSystemCloseAfterSplitResetFailure": "pass",
                    },
                },
                "flow": {
                    **common,
                    "suite": "packet-flow",
                    "requiredTests": [
                        "TestPacketFlowPublicAPI",
                        "TestPacketFlowUnderlayBypass",
                    ],
                    "testResults": {
                        "TestPacketFlowPublicAPI": "pass",
                        "TestPacketFlowUnderlayBypass": "pass",
                    },
                },
            }
            for name in ("live", "flow"):
                values[name]["driver"] = {
                    "version": "1.3.0.0", "upstreamCommit": "upstream",
                    "finalState": "Stopped", "files": {"driver.sys": "hash"},
                    "packageSigner": "CN=Mullvad VPN AB",
                    "installedSigner": "CN=Mullvad VPN AB",
                    "installedSignature": "Valid",
                }
            packets = [
                {"case": "tcp4", "packetPathValid": True},
                {"case": "udp6", "packetPathValid": True},
            ]
            if mutate:
                mutate(matrix, values, packets)
            (root / "matrix.json").write_text(json.dumps(matrix), encoding="utf-8")
            driver_lock = {
                "schemaVersion": 1,
                "version": "1.3.0.0", "upstreamCommit": "upstream",
                "architectures": {"arm64": {"files": {"driver.sys": "hash"}}},
            }
            if driver_lock_mutate:
                driver_lock_mutate(driver_lock)
            (root / "driver-lock.json").write_text(
                json.dumps(driver_lock), encoding="utf-8"
            )
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
        self.assertEqual(output["sourceArchiveSha256"], SOURCE_HASH)

    def test_rejects_missing_required_case(self):
        def mutate(_matrix, values, _packets):
            values["native"]["requiredTests"] = []
            values["native"]["testResults"] = {}

        result, output = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(output)

    def test_rejects_skipped_required_case(self):
        def mutate(_matrix, values, _packets):
            values["native"]["testResults"]["native"] = "skip"

        result, output = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("was skipped", result.stderr)
        self.assertIsNone(output)

    def test_rejects_mismatched_source_identity(self):
        def mutate(_matrix, values, _packets):
            values["flow"]["sourceArchiveSha256"] = "e" * 64

        result, output = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source archive identities do not match", result.stderr)
        self.assertIsNone(output)

    def test_accepts_expected_installed_driver_signers(self):
        def mutate(_matrix, values, _packets):
            for name in ("live", "flow"):
                values[name]["driver"]["installedSigner"] = (
                    "CN=Microsoft Windows Hardware Compatibility Publisher"
                )

        result, output = self.run_validator(mutate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["outcome"], "qualified")

    def test_rejects_missing_or_unexpected_driver_signatures(self):
        cases = [
            (
                "missing installed signer",
                lambda driver: driver.pop("installedSigner"),
                "installed driver signer does not match",
            ),
            (
                "unexpected installed signer",
                lambda driver: driver.update(installedSigner="CN=Unexpected Publisher"),
                "installed driver signer does not match",
            ),
            (
                "installed signer substring",
                lambda driver: driver.update(
                    installedSigner="CN=Unexpected CN=Mullvad VPN AB"
                ),
                "installed driver signer does not match",
            ),
            (
                "missing signature status",
                lambda driver: driver.pop("installedSignature"),
                "installed driver signature is not valid",
            ),
            (
                "invalid signature status",
                lambda driver: driver.update(installedSignature="HashMismatch"),
                "installed driver signature is not valid",
            ),
            (
                "missing package signer",
                lambda driver: driver.pop("packageSigner"),
                "staged package signer does not match",
            ),
            (
                "package signer substring",
                lambda driver: driver.update(
                    packageSigner="CN=Unexpected CN=Mullvad VPN AB"
                ),
                "staged package signer does not match",
            ),
        ]
        for suite in ("live", "flow"):
            for name, change, message in cases:
                with self.subTest(suite=suite, case=name):
                    def mutate(_matrix, values, _packets, suite=suite, change=change):
                        change(values[suite]["driver"])

                    result, output = self.run_validator(mutate)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
                    self.assertIsNone(output)

    def test_rejects_unsupported_driver_lock_schema(self):
        result, output = self.run_validator(
            driver_lock_mutate=lambda lock: lock.update(schemaVersion=2)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported driver lock schema", result.stderr)
        self.assertIsNone(output)

    def test_rejects_mismatched_or_incomplete_evidence(self):
        cases = [
            lambda _m, values, _p: values["flow"].update(architecture="amd64"),
            lambda _m, values, _p: values["live"].update(sysnetWindowsRevision="b" * 40),
            lambda _m, values, _p: values["live"].update(sysnetWindowsTreeState="dirty"),
            lambda _m, values, _p: values["live"].update(dependencyLocks={"goMod": "e" * 64}),
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
