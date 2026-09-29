#!/usr/bin/env python3
"""Tests for Windows qualification evidence validation."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "qualify.py"
REVISION = "a" * 40
SOURCE_BYTES = b"fixture source archive"
SOURCE_HASH = hashlib.sha256(SOURCE_BYTES).hexdigest()
NATIVE_TEST = "example.test/native::TestNative"
LIVE_TESTS = [
    "example.test/integration::TestDriverLifecycle",
    "example.test/integration::TestOwnedNetworkingCleanup",
    "example.test/integration::TestDNSConfigurationRestoration",
    "example.test/integration::TestSystemCloseAfterSplitResetFailure",
]
FLOW_TESTS = [
    "example.test/integration::TestPacketFlowPublicAPI",
    "example.test/integration::TestPacketFlowUnderlayBypass",
]
RESOURCE_TEST = "example.test/integration::TestResourceGate"


class QualificationTest(unittest.TestCase):
    def run_validator(
        self,
        mutate=None,
        driver_lock_mutate=None,
        manifest_mutate=None,
        preexisting_output=None,
        source_bytes=SOURCE_BYTES,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix = {
                "schemaVersion": 1,
                "driverLock": "driver-lock.json",
                "testManifest": "test-manifest.json",
                "dependencyLocks": {
                    "goMod": "go.mod.lock", "goSum": "go.sum.lock",
                    "flakeLock": "flake.lock", "imageLock": "image-lock.json",
                    "nativeDriverLock": "driver-lock.json",
                    "qualificationMatrix": "matrix.json",
                    "wintunLock": "wintun-lock.json",
                    "testManifest": "test-manifest.json",
                },
                "maximumSuiteSpanHours": 168,
                "codeIntegrity": {"requiredOptions": 1, "forbiddenOptions": 130},
                "resourceGate": {
                    "warmupCycles": 10, "batchCount": 4,
                    "cyclesPerBatch": 25, "cancellationCycles": 100,
                    "soakDuration": "30m",
                },
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
                "startedAt": "2026-09-29T10:00:00Z",
                "finishedAt": "2026-09-29T10:01:00Z",
                "goVersion": "go version go1.25.5 windows/arm64",
                "os": {
                    "caption": "Fixture Windows", "version": "1.2.42",
                    "build": "42", "productType": 1,
                    "nativeArchitecture": "arm64",
                    "codeIntegrity": {
                        "options": 1, "enabled": True,
                        "testSigning": False, "debugMode": False,
                    },
                },
            }
            values = {
                "portable": {
                    "schemaVersion": 1, "suite": "portable", "outcome": "passed",
                    "sysnetWindowsRevision": REVISION,
                    "sysnetWindowsTreeState": "clean",
                    "sourceArchiveSha256": SOURCE_HASH,
                    "startedAt": "2026-09-29T09:00:00Z",
                    "finishedAt": "2026-09-29T09:01:00Z",
                    "goVersion": "go version go1.25.5 linux/amd64",
                    "requiredStages": ["check-fast"],
                    "stageResults": {"check-fast": "pass"},
                },
                "native": {
                    **common, "suite": "native-unit", "requiredTests": [NATIVE_TEST],
                    "testResults": {NATIVE_TEST: "pass"},
                },
                "live": {
                    **common,
                    "suite": "live-driver",
                    "requiredTests": LIVE_TESTS,
                    "testResults": dict.fromkeys(LIVE_TESTS, "pass"),
                },
                "resource": {
                    **common,
                    "suite": "resource-gate",
                    "requiredTests": [RESOURCE_TEST],
                    "testResults": {RESOURCE_TEST: "pass"},
                    "resourceGate": {
                        "warmupCycles": 10, "batchCount": 4,
                        "cyclesPerBatch": 25, "cancellationCycles": 100,
                        "soakDuration": "30m", "diagnosticOverride": False,
                    },
                },
                "flow": {
                    **common,
                    "suite": "packet-flow",
                    "requiredTests": FLOW_TESTS,
                    "testResults": dict.fromkeys(FLOW_TESTS, "pass"),
                },
            }
            for name in ("live", "resource", "flow"):
                values[name]["driver"] = {
                    "version": "1.3.0.0", "upstreamCommit": "upstream",
                    "finalState": "Stopped",
                    "files": {"mullvad-split-tunnel.sys": "hash"},
                    "packageSigner": "CN=Mullvad VPN AB",
                    "stagedDriverSigner": "CN=Mullvad VPN AB",
                    "packageCatalogSigner": (
                        "CN=Microsoft Windows Hardware Compatibility Publisher"
                    ),
                    "installedSigner": "CN=Mullvad VPN AB",
                    "installedSignature": "Valid",
                    "installedFileSha256": "hash",
                }
                values[name]["wintun"] = {
                    "version": "0.14.1", "dllSha256": "f" * 64,
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
                "architectures": {"arm64": {"files": {
                    "mullvad-split-tunnel.sys": "hash"
                }}},
            }
            if driver_lock_mutate:
                driver_lock_mutate(driver_lock)
            (root / "driver-lock.json").write_text(
                json.dumps(driver_lock), encoding="utf-8"
            )
            test_manifest = {
                "schemaVersion": 1,
                "suites": {
                    "portable": {"requiredStages": ["check-fast"], "plannedCases": []},
                    "native-unit": {"requiredTests": [NATIVE_TEST], "plannedCases": []},
                    "live-driver": {"requiredTests": LIVE_TESTS, "plannedCases": []},
                    "resource-gate": {"requiredTests": [RESOURCE_TEST], "plannedCases": []},
                    "packet-flow": {"requiredTests": FLOW_TESTS, "plannedCases": []},
                },
            }
            if manifest_mutate:
                manifest_mutate(test_manifest)
            (root / "test-manifest.json").write_text(
                json.dumps(test_manifest), encoding="utf-8"
            )
            (root / "wintun-lock.json").write_text(json.dumps({
                "schemaVersion": 1,
                "wintun": {"version": "0.14.1", "sha256": "0" * 64},
            }), encoding="utf-8")
            for name in ("go.mod.lock", "go.sum.lock", "flake.lock", "image-lock.json"):
                (root / name).write_text(name, encoding="utf-8")
            locks = {
                name: hashlib.sha256((root / relative).read_bytes()).hexdigest()
                for name, relative in matrix["dependencyLocks"].items()
            }
            for value in values.values():
                value.setdefault("dependencyLocks", locks)
            for name, value in values.items():
                (root / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
            (root / "packets.json").write_text(json.dumps(packets), encoding="utf-8")
            (root / "worktree.tar").write_bytes(source_bytes)
            resource_snapshot = {"adapters": [], "routes": []}
            for name in ("resources-before.json", "resources-after.json"):
                (root / name).write_text(json.dumps(resource_snapshot), encoding="utf-8")
            (root / "process-resources.json").write_text(json.dumps({
                "schemaVersion": 1, "warmupCycles": 10, "batchCount": 4,
                "cyclesPerBatch": 25,
                "samples": [
                    {"cycles": cycles, "handles": 1, "goroutines": 1,
                     "privateBytes": 1}
                    for cycles in (10, 35, 60, 85, 110)
                ],
            }), encoding="utf-8")
            if preexisting_output is not None:
                (root / "result.json").write_text(
                    json.dumps(preexisting_output), encoding="utf-8"
                )
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--matrix", str(root / "matrix.json"),
                "--entry", "fixture", "--portable", str(root / "portable.json"),
                "--native-unit", str(root / "native.json"),
                "--live-driver", str(root / "live.json"),
                "--resource-gate", str(root / "resource.json"),
                "--packet-flow", str(root / "flow.json"),
                "--packet-evidence", str(root / "packets.json"), "--output", str(root / "result.json"),
                "--source-archive", str(root / "worktree.tar"),
            ], check=False, capture_output=True, text=True)
            output = json.loads((root / "result.json").read_text()) if (root / "result.json").exists() else None
            return result, output

    def test_failed_validation_removes_stale_qualification(self):
        def bad_matrix(matrix, _values, _packets):
            matrix["schemaVersion"] = 2

        def mismatched_source(_matrix, values, _packets):
            values["flow"]["sourceArchiveSha256"] = "e" * 64

        def invalid_driver(_matrix, values, _packets):
            values["live"]["driver"]["installedSignature"] = "HashMismatch"

        def missing_packet(_matrix, _values, packets):
            packets.pop()

        cases = [
            ("matrix", bad_matrix, None),
            ("driver lock", None, lambda lock: lock.update(schemaVersion=2)),
            ("suite identity", mismatched_source, None),
            ("driver evidence", invalid_driver, None),
            ("packet evidence", missing_packet, None),
        ]
        stale = {"schemaVersion": 1, "outcome": "qualified"}
        for name, mutate, lock_mutate in cases:
            with self.subTest(stage=name):
                result, output = self.run_validator(
                    mutate,
                    driver_lock_mutate=lock_mutate,
                    preexisting_output=stale,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(output)

    def test_accepts_complete_matching_evidence(self):
        result, output = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output["outcome"], "qualified")
        self.assertEqual(output["packetObservations"], 2)
        self.assertEqual(len(output["evidenceSha256"]), 13)
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
            values["native"]["testResults"][NATIVE_TEST] = "skip"

        result, output = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("was skipped", result.stderr)
        self.assertIsNone(output)

    def test_rejects_invalid_or_duplicate_required_test_identity(self):
        cases = [
            ["TestNative"],
            ["example.test/native::not-a-test"],
            ["example.test/native package::TestNative"],
            [NATIVE_TEST, NATIVE_TEST],
        ]
        for required_tests in cases:
            with self.subTest(required_tests=required_tests):
                def manifest_mutate(manifest):
                    manifest["suites"]["native-unit"]["requiredTests"] = required_tests

                result, output = self.run_validator(manifest_mutate=manifest_mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("required native-unit test identity", result.stderr)
                self.assertIsNone(output)

    def test_rejects_mismatched_source_identity(self):
        def mutate(_matrix, values, _packets):
            values["flow"]["sourceArchiveSha256"] = "e" * 64

        result, output = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source archive identities do not match", result.stderr)
        self.assertIsNone(output)

        result, output = self.run_validator(source_bytes=b"different archive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retained source archive does not match", result.stderr)
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
            (
                "unexpected staged driver signer",
                lambda driver: driver.update(stagedDriverSigner="CN=Unexpected"),
                "staged driver signer does not match",
            ),
            (
                "missing catalog signer",
                lambda driver: driver.pop("packageCatalogSigner"),
                "staged catalog signer does not match",
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

    def test_rejects_unfinished_or_failed_portable_gate(self):
        def planned(manifest):
            manifest["suites"]["portable"]["plannedCases"] = ["future check"]

        result, output = self.run_validator(manifest_mutate=planned)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("planned cases prevent qualification", result.stderr)
        self.assertIsNone(output)

        def failed(_matrix, values, _packets):
            values["portable"]["stageResults"]["check-fast"] = "skip"

        result, output = self.run_validator(failed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required stage did not pass", result.stderr)
        self.assertIsNone(output)

    def test_rejects_stale_or_invalid_suite_times(self):
        cases = [
            (
                lambda _m, values, _p: values["flow"].update(
                    finishedAt="2026-10-20T10:00:00Z"
                ),
                "stale across suite runs",
            ),
            (
                lambda _m, values, _p: values["native"].update(
                    startedAt="2026-09-29T11:00:00Z"
                ),
                "finished before it started",
            ),
            (
                lambda _m, values, _p: values["native"].update(
                    startedAt="2026-09-29T10:00:00"
                ),
                "has no time zone",
            ),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                result, output = self.run_validator(mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertIsNone(output)

    def test_rejects_invalid_platform_and_code_integrity_evidence(self):
        def wrong_architecture(_matrix, values, _packets):
            values["flow"]["os"] = dict(values["flow"]["os"])
            values["flow"]["os"]["nativeArchitecture"] = "amd64"

        def test_signing(_matrix, values, _packets):
            values["flow"]["os"] = dict(values["flow"]["os"])
            values["flow"]["os"]["codeIntegrity"] = {
                "options": 3, "enabled": True,
                "testSigning": True, "debugMode": False,
            }

        def inconsistent_flags(_matrix, values, _packets):
            values["flow"]["os"] = dict(values["flow"]["os"])
            values["flow"]["os"]["codeIntegrity"] = {
                "options": 1, "enabled": False,
                "testSigning": False, "debugMode": False,
            }

        for mutate, message in (
            (wrong_architecture, "native architecture does not match"),
            (test_signing, "forbidden code integrity options"),
            (inconsistent_flags, "flags do not match"),
        ):
            with self.subTest(message=message):
                result, output = self.run_validator(mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertIsNone(output)

    def test_rejects_binary_identity_failures_and_duplicate_packets(self):
        cases = [
            (
                lambda _m, values, _p: values["live"]["driver"].update(
                    installedFileSha256="wrong"
                ),
                "installed driver hash does not match",
            ),
            (
                lambda _m, values, _p: values["flow"]["wintun"].update(
                    dllSha256="e" * 64
                ),
                "Wintun binary identities do not match",
            ),
            (
                lambda _m, _values, packets: packets.append(dict(packets[0])),
                "duplicates a case",
            ),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                result, output = self.run_validator(mutate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertIsNone(output)

    def test_rejects_diagnostic_resource_gate(self):
        def mutate(_matrix, values, _packets):
            values["resource"]["resourceGate"].update(
                soakDuration="2m", diagnosticOverride=True
            )

        result, output = self.run_validator(mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("diagnostic soak override is not qualifying", result.stderr)
        self.assertIsNone(output)


if __name__ == "__main__":
    unittest.main()
