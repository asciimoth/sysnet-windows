#!/usr/bin/env python3
"""Validate one complete Windows qualification evidence set."""

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path


LOCK_NAMES = {
    "goMod",
    "goSum",
    "flakeLock",
    "imageLock",
    "nativeDriverLock",
    "qualificationMatrix",
    "wintunLock",
    "testManifest",
}
CODE_INTEGRITY_ENABLED = 0x1
CODE_INTEGRITY_TEST_SIGNING = 0x2
CODE_INTEGRITY_DEBUG_MODE = 0x80


def load_object(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def signer_has_identity(value, expected_identities):
    signer = str(value)
    return any(
        re.search(rf"(?:^|,\s*){re.escape(identity)}(?:,|$)", signer)
        for identity in expected_identities
    )


def expected_installed_signer(value):
    return signer_has_identity(
        value,
        (
            "CN=Mullvad VPN AB",
            "CN=Microsoft Windows Hardware Compatibility Publisher",
        )
    )


def required_test_identities(test_manifest, suite):
    identities = test_manifest["suites"][suite]["requiredTests"]
    if not isinstance(identities, list) or not identities:
        raise ValueError(f"test manifest has no required {suite} tests")
    if not all(
        isinstance(identity, str)
        and re.fullmatch(r"[^:\s]+::Test[0-9A-Za-z_]+", identity)
        for identity in identities
    ):
        raise ValueError(f"test manifest has an invalid required {suite} test identity")
    if len(set(identities)) != len(identities):
        raise ValueError(f"test manifest duplicates a required {suite} test identity")
    return set(identities)


def parse_time(path, value, field):
    raw = value.get(field)
    if not isinstance(raw, str):
        raise ValueError(f"{path}: {field} is absent")
    try:
        result = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{path}: {field} is invalid") from error
    if result.tzinfo is None:
        raise ValueError(f"{path}: {field} has no time zone")
    return result


def check_common_evidence(path, value, suite, revision, expected_locks):
    if value.get("schemaVersion") != 1:
        raise ValueError(f"{path}: unsupported evidence schema")
    if value.get("suite") != suite or value.get("outcome") != "passed":
        raise ValueError(f"{path}: {suite} did not pass")
    if value.get("sysnetWindowsRevision") != revision:
        raise ValueError(f"{path}: sysnet-windows revision does not match")
    if value.get("sysnetWindowsTreeState") != "clean":
        raise ValueError(f"{path}: sysnet-windows worktree was not clean")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(value.get("sourceArchiveSha256", ""))):
        raise ValueError(f"{path}: source archive SHA-256 is absent or invalid")
    if value.get("dependencyLocks") != expected_locks:
        raise ValueError(f"{path}: dependency lock identity is stale or invalid")
    started = parse_time(path, value, "startedAt")
    finished = parse_time(path, value, "finishedAt")
    if finished < started:
        raise ValueError(f"{path}: suite finished before it started")
    return started, finished


def check_windows_evidence(path, value, suite, entry, revision, expected_locks, policy):
    times = check_common_evidence(path, value, suite, revision, expected_locks)
    if value.get("architecture") != entry["architecture"]:
        raise ValueError(f"{path}: architecture does not match the matrix")
    if not re.fullmatch(
        rf"go version go\S+ windows/{re.escape(entry['architecture'])}",
        str(value.get("goVersion", "")),
    ):
        raise ValueError(f"{path}: Go version or architecture is invalid")
    operating_system = value.get("os")
    if not isinstance(operating_system, dict):
        raise ValueError(f"{path}: OS identity is absent")
    if not re.search(entry["osCaptionPattern"], str(operating_system.get("caption", ""))):
        raise ValueError(f"{path}: OS caption does not match the matrix")
    try:
        build = int(operating_system.get("build", 0))
        product_type = int(operating_system.get("productType", 0))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{path}: OS build or product type is invalid") from error
    if build < entry["minimumBuild"]:
        raise ValueError(f"{path}: OS build is below the matrix minimum")
    if product_type != entry["productType"]:
        raise ValueError(f"{path}: OS product type does not match the matrix")
    if operating_system.get("nativeArchitecture") != entry["architecture"]:
        raise ValueError(f"{path}: native architecture does not match the matrix")
    integrity = operating_system.get("codeIntegrity")
    if not isinstance(integrity, dict):
        raise ValueError(f"{path}: code integrity evidence is absent")
    options = integrity.get("options")
    if (
        isinstance(options, bool)
        or not isinstance(options, int)
        or not 0 <= options <= 0xFFFFFFFF
    ):
        raise ValueError(f"{path}: code integrity options are invalid")
    expected_flags = {
        "enabled": bool(options & CODE_INTEGRITY_ENABLED),
        "testSigning": bool(options & CODE_INTEGRITY_TEST_SIGNING),
        "debugMode": bool(options & CODE_INTEGRITY_DEBUG_MODE),
    }
    if any(
        integrity.get(name) is not expected
        for name, expected in expected_flags.items()
    ):
        raise ValueError(f"{path}: code integrity flags do not match the option mask")
    if (options & policy["requiredOptions"]) != policy["requiredOptions"]:
        raise ValueError(f"{path}: required code integrity options are disabled")
    if options & policy["forbiddenOptions"]:
        raise ValueError(f"{path}: forbidden code integrity options are enabled")
    return operating_system, times


def check_portable_evidence(path, value, revision, expected_locks, test_manifest):
    times = check_common_evidence(path, value, "portable", revision, expected_locks)
    if not re.fullmatch(r"go version go\S+ linux/amd64", str(value.get("goVersion", ""))):
        raise ValueError(f"{path}: portable Go version is invalid")
    required = test_manifest["suites"]["portable"]["requiredStages"]
    if (
        not isinstance(required, list)
        or not required
        or len(set(required)) != len(required)
    ):
        raise ValueError("test manifest has invalid portable required stages")
    if value.get("requiredStages") != required:
        raise ValueError("portable: required stages are absent or stale")
    results = value.get("stageResults")
    if not isinstance(results, dict) or set(results) != set(required):
        raise ValueError("portable: required stage results are absent or stale")
    failed = [stage for stage in required if results.get(stage) != "pass"]
    if failed:
        raise ValueError(f"portable: required stage did not pass: {failed[0]}")
    return times


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--entry", required=True)
    parser.add_argument("--portable", required=True, type=Path)
    parser.add_argument("--native-unit", required=True, type=Path)
    parser.add_argument("--live-driver", required=True, type=Path)
    parser.add_argument("--resource-gate", required=True, type=Path)
    parser.add_argument("--packet-flow", required=True, type=Path)
    parser.add_argument("--packet-evidence", required=True, type=Path)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    # A failed rerun must not leave an earlier successful qualification in the
    # evidence directory.
    args.output.unlink(missing_ok=True)

    matrix = load_object(args.matrix)
    if matrix.get("schemaVersion") != 1:
        raise ValueError("unsupported qualification matrix schema")
    entries = [value for value in matrix.get("entries", []) if value.get("id") == args.entry]
    if len(entries) != 1:
        raise ValueError(f"matrix entry {args.entry!r} is absent or duplicated")
    entry = entries[0]
    lock_path = args.matrix.parent / matrix["driverLock"]
    driver_file_lock = load_object(lock_path)
    if driver_file_lock.get("schemaVersion") != 1:
        raise ValueError("unsupported driver lock schema")
    test_manifest_path = args.matrix.parent / matrix["testManifest"]
    test_manifest = load_object(test_manifest_path)
    if test_manifest.get("schemaVersion") != 1:
        raise ValueError("unsupported test manifest schema")
    for suite in (
        "portable",
        "native-unit",
        "live-driver",
        "resource-gate",
        "packet-flow",
    ):
        planned = test_manifest["suites"][suite].get("plannedCases")
        if not isinstance(planned, list):
            raise ValueError(f"test manifest has invalid {suite} planned cases")
        if planned:
            raise ValueError(f"{suite}: planned cases prevent qualification")
    if driver_file_lock.get("version") != matrix["driver"]["version"]:
        raise ValueError("driver lock version does not match the matrix")
    if driver_file_lock.get("upstreamCommit") != matrix["driver"]["upstreamCommit"]:
        raise ValueError("driver lock upstream commit does not match the matrix")
    locked_architecture = driver_file_lock["architectures"][entry["architecture"]]

    lock_files = matrix.get("dependencyLocks")
    if not isinstance(lock_files, dict) or set(lock_files) != LOCK_NAMES:
        raise ValueError("qualification matrix has invalid dependency lock files")
    if not all(isinstance(path, str) and path for path in lock_files.values()):
        raise ValueError("qualification matrix has invalid dependency lock path")
    expected_locks = {
        name: sha256((args.matrix.parent / relative).resolve())
        for name, relative in lock_files.items()
    }
    integrity_policy = matrix.get("codeIntegrity")
    if not isinstance(integrity_policy, dict):
        raise ValueError("qualification matrix has no code integrity policy")
    for field in ("requiredOptions", "forbiddenOptions"):
        value = integrity_policy.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"qualification matrix has invalid {field}")
    if integrity_policy["requiredOptions"] & integrity_policy["forbiddenOptions"]:
        raise ValueError("qualification matrix code integrity policy conflicts")
    resource_policy = matrix.get("resourceGate")
    if not isinstance(resource_policy, dict):
        raise ValueError("qualification matrix has no resource gate policy")

    evidence_paths = {
        "portable": args.portable,
        "native-unit": args.native_unit,
        "live-driver": args.live_driver,
        "resource-gate": args.resource_gate,
        "packet-flow": args.packet_flow,
    }
    evidence = {name: load_object(path) for name, path in evidence_paths.items()}
    revision = evidence["portable"].get("sysnetWindowsRevision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise ValueError("sysnet-windows revision must be a full Git object name")

    suite_times = [
        check_portable_evidence(
            evidence_paths["portable"],
            evidence["portable"],
            revision,
            expected_locks,
            test_manifest,
        )
    ]
    os_identities = []
    for suite in ("native-unit", "live-driver", "resource-gate", "packet-flow"):
        operating_system, times = check_windows_evidence(
            evidence_paths[suite],
            evidence[suite],
            suite,
            entry,
            revision,
            expected_locks,
            integrity_policy,
        )
        os_identities.append(operating_system)
        suite_times.append(times)
    if any(value != os_identities[0] for value in os_identities[1:]):
        raise ValueError("suite OS identities do not match")
    source_hashes = {
        value["sourceArchiveSha256"].lower() for value in evidence.values()
    }
    if len(source_hashes) != 1:
        raise ValueError("suite source archive identities do not match")
    if sha256(args.source_archive) != next(iter(source_hashes)):
        raise ValueError("retained source archive does not match suite evidence")
    earliest = min(started for started, _ in suite_times)
    latest = max(finished for _, finished in suite_times)
    maximum_span = matrix.get("maximumSuiteSpanHours")
    if (
        isinstance(maximum_span, bool)
        or not isinstance(maximum_span, int)
        or maximum_span <= 0
    ):
        raise ValueError("qualification matrix has invalid maximum suite span")
    if (latest - earliest).total_seconds() > maximum_span * 3600:
        raise ValueError("qualification evidence is stale across suite runs")

    driver_lock = matrix["driver"]
    driver_suites = ("live-driver", "resource-gate", "packet-flow")
    for suite in driver_suites:
        driver = evidence[suite].get("driver", {})
        if driver.get("version") != driver_lock["version"]:
            raise ValueError(f"{suite}: driver version does not match")
        if driver.get("upstreamCommit") != driver_lock["upstreamCommit"]:
            raise ValueError(f"{suite}: driver upstream commit does not match")
        if driver.get("files") != locked_architecture["files"]:
            raise ValueError(f"{suite}: driver file hashes do not match")
        if not signer_has_identity(
            driver.get("packageSigner", ""), ("CN=Mullvad VPN AB",)
        ):
            raise ValueError(f"{suite}: staged package signer does not match")
        if not expected_installed_signer(driver.get("stagedDriverSigner", "")):
            raise ValueError(f"{suite}: staged driver signer does not match")
        if not expected_installed_signer(driver.get("packageCatalogSigner", "")):
            raise ValueError(f"{suite}: staged catalog signer does not match")
        if not expected_installed_signer(driver.get("installedSigner", "")):
            raise ValueError(f"{suite}: installed driver signer does not match")
        if driver.get("installedSignature") != "Valid":
            raise ValueError(f"{suite}: installed driver signature is not valid")
        if driver.get("installedFileSha256") != locked_architecture["files"].get(
            "mullvad-split-tunnel.sys"
        ):
            raise ValueError(f"{suite}: installed driver hash does not match")
        if driver.get("finalState") != "Stopped":
            raise ValueError(f"{suite}: driver service was not stopped")
    wintun_lock = load_object(
        (args.matrix.parent / lock_files["wintunLock"]).resolve()
    )["wintun"]
    wintun_evidence = [
        evidence[suite].get("wintun")
        for suite in driver_suites
    ]
    if any(
        not isinstance(value, dict)
        or value.get("version") != wintun_lock["version"]
        or not re.fullmatch(r"[0-9a-fA-F]{64}", str(value.get("dllSha256", "")))
        for value in wintun_evidence
    ):
        raise ValueError("Wintun binary identity is absent or invalid")
    if any(value != wintun_evidence[0] for value in wintun_evidence[1:]):
        raise ValueError("suite Wintun binary identities do not match")
    recorded_resource_policy = evidence["resource-gate"].get("resourceGate")
    if not isinstance(recorded_resource_policy, dict):
        raise ValueError("resource-gate: run parameters are absent")
    if recorded_resource_policy.get("diagnosticOverride") is not False:
        raise ValueError("resource-gate: diagnostic soak override is not qualifying")
    if {
        name: value
        for name, value in recorded_resource_policy.items()
        if name != "diagnosticOverride"
    } != resource_policy:
        raise ValueError("resource-gate: run parameters do not match the matrix")

    resource_artifact_paths = {
        "resources-before": args.resource_gate.parent / "resources-before.json",
        "resources-after": args.resource_gate.parent / "resources-after.json",
        "process-resources": args.resource_gate.parent / "process-resources.json",
    }
    resource_before = load_json(resource_artifact_paths["resources-before"])
    resource_after = load_json(resource_artifact_paths["resources-after"])
    if resource_before != resource_after:
        raise ValueError("resource-gate: native resource snapshots do not match")
    process_resources = load_object(resource_artifact_paths["process-resources"])
    if any(
        process_resources.get(name) != resource_policy[name]
        for name in ("warmupCycles", "batchCount", "cyclesPerBatch")
    ):
        raise ValueError("resource-gate: process resource report is incomplete")
    samples = process_resources.get("samples")
    expected_cycles = [
        resource_policy["warmupCycles"]
        + batch * resource_policy["cyclesPerBatch"]
        for batch in range(resource_policy["batchCount"] + 1)
    ]
    if (
        process_resources.get("schemaVersion") != 1
        or not isinstance(samples, list)
        or not all(isinstance(sample, dict) for sample in samples)
        or [sample.get("cycles") for sample in samples] != expected_cycles
    ):
        raise ValueError("resource-gate: process resource samples are incomplete")
    for suite in ("native-unit", "live-driver", "resource-gate", "packet-flow"):
        required_tests = required_test_identities(test_manifest, suite)
        actual_required = evidence[suite].get("requiredTests")
        if (
            not isinstance(actual_required, list)
            or len(actual_required) != len(required_tests)
            or set(actual_required) != required_tests
        ):
            raise ValueError(f"{suite}: required tests did not pass")
        test_results = evidence[suite].get("testResults", {})
        if not isinstance(test_results, dict) or set(test_results) != required_tests:
            raise ValueError(f"{suite}: required test results are invalid")
        for test in required_tests:
            if test_results.get(test) == "skip":
                raise ValueError(f"{suite}: required test {test} was skipped")
            if test_results.get(test) != "pass":
                raise ValueError(f"{suite}: required test {test} has no pass result")

    packet_results = json.loads(args.packet_evidence.read_text(encoding="utf-8"))
    if not isinstance(packet_results, list):
        raise ValueError("packet evidence is not a JSON array")
    if not all(
        isinstance(value, dict)
        and isinstance(value.get("case"), str)
        and value.get("case")
        and value.get("packetPathValid") is True
        for value in packet_results
    ):
        raise ValueError("packet evidence contains an invalid path")
    required_packet_case_list = matrix.get("requiredPacketCases")
    if (
        not isinstance(required_packet_case_list, list)
        or not required_packet_case_list
        or not all(isinstance(case, str) and case for case in required_packet_case_list)
        or len(set(required_packet_case_list)) != len(required_packet_case_list)
    ):
        raise ValueError("qualification matrix has no required packet cases")
    required_packet_cases = set(required_packet_case_list)
    observed_packet_cases = {
        value.get("case") for value in packet_results if isinstance(value.get("case"), str)
    }
    case_counts = Counter(value["case"] for value in packet_results)
    duplicated_cases = sorted(case for case, count in case_counts.items() if count > 1)
    if duplicated_cases:
        raise ValueError(f"packet evidence duplicates a case: {duplicated_cases[0]}")
    missing_packet_cases = required_packet_cases - observed_packet_cases
    if missing_packet_cases:
        missing = ", ".join(sorted(missing_packet_cases))
        raise ValueError(f"packet evidence is missing required cases: {missing}")

    result = {
        "schemaVersion": 1,
        "matrixEntry": entry["id"],
        "outcome": "qualified",
        "sysnetWindowsRevision": revision.lower(),
        "sourceArchiveSha256": next(iter(source_hashes)),
        "architecture": entry["architecture"],
        "os": os_identities[0],
        "codeIntegrity": os_identities[0]["codeIntegrity"],
        "driver": driver_lock,
        "driverFiles": locked_architecture["files"],
        "wintun": wintun_evidence[0],
        "dependencyLocks": expected_locks,
        "suitePeriod": {
            "startedAt": earliest.isoformat(),
            "finishedAt": latest.isoformat(),
        },
        "packetObservations": len(packet_results),
        "packetCases": sorted(observed_packet_cases),
        "evidenceSha256": {
            **{name: sha256(path) for name, path in evidence_paths.items()},
            **{name: sha256(path) for name, path in resource_artifact_paths.items()},
            "packet-flow-paths": sha256(args.packet_evidence),
            "source-archive": sha256(args.source_archive),
            "qualification-matrix": sha256(args.matrix),
            "driver-lock": sha256(lock_path),
            "test-manifest": sha256(test_manifest_path),
        },
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Qualified {entry['id']} at {revision}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        raise SystemExit(f"qualify.py: {error}") from error
