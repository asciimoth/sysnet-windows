#!/usr/bin/env python3
"""Validate one complete Windows qualification evidence set."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def load_object(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def check_evidence(path, value, suite, entry, revision):
    if value.get("schemaVersion") != 1:
        raise ValueError(f"{path}: unsupported evidence schema")
    if value.get("suite") != suite or value.get("outcome") != "passed":
        raise ValueError(f"{path}: {suite} did not pass")
    if value.get("architecture") != entry["architecture"]:
        raise ValueError(f"{path}: architecture does not match the matrix")
    if value.get("sysnetWindowsRevision") != revision:
        raise ValueError(f"{path}: sysnet-windows revision does not match")
    if value.get("sysnetWindowsTreeState") != "clean":
        raise ValueError(f"{path}: sysnet-windows worktree was not clean")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(value.get("sourceArchiveSha256", ""))):
        raise ValueError(f"{path}: source archive SHA-256 is absent or invalid")
    dependency_locks = value.get("dependencyLocks")
    if not isinstance(dependency_locks, dict) or not dependency_locks:
        raise ValueError(f"{path}: dependency lock identity is absent")
    if not all(
        isinstance(name, str)
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
        for name, digest in dependency_locks.items()
    ):
        raise ValueError(f"{path}: dependency lock identity is invalid")
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
    if int(operating_system.get("build", 0)) < entry["minimumBuild"]:
        raise ValueError(f"{path}: OS build is below the matrix minimum")
    if int(operating_system.get("productType", 0)) != entry["productType"]:
        raise ValueError(f"{path}: OS product type does not match the matrix")
    return operating_system


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--entry", required=True)
    parser.add_argument("--native-unit", required=True, type=Path)
    parser.add_argument("--live-driver", required=True, type=Path)
    parser.add_argument("--packet-flow", required=True, type=Path)
    parser.add_argument("--packet-evidence", required=True, type=Path)
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
    if driver_file_lock.get("version") != matrix["driver"]["version"]:
        raise ValueError("driver lock version does not match the matrix")
    if driver_file_lock.get("upstreamCommit") != matrix["driver"]["upstreamCommit"]:
        raise ValueError("driver lock upstream commit does not match the matrix")
    locked_architecture = driver_file_lock["architectures"][entry["architecture"]]

    evidence_paths = {
        "native-unit": args.native_unit,
        "live-driver": args.live_driver,
        "packet-flow": args.packet_flow,
    }
    evidence = {name: load_object(path) for name, path in evidence_paths.items()}
    revision = evidence["native-unit"].get("sysnetWindowsRevision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise ValueError("sysnet-windows revision must be a full Git object name")

    os_identities = []
    for suite, value in evidence.items():
        os_identities.append(
            check_evidence(evidence_paths[suite], value, suite, entry, revision)
        )
    if any(value != os_identities[0] for value in os_identities[1:]):
        raise ValueError("suite OS identities do not match")
    source_hashes = {
        value["sourceArchiveSha256"].lower() for value in evidence.values()
    }
    if len(source_hashes) != 1:
        raise ValueError("suite source archive identities do not match")
    dependency_locks = [value["dependencyLocks"] for value in evidence.values()]
    if any(value != dependency_locks[0] for value in dependency_locks[1:]):
        raise ValueError("suite dependency lock identities do not match")

    driver_lock = matrix["driver"]
    for suite in ("live-driver", "packet-flow"):
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
        if not expected_installed_signer(driver.get("installedSigner", "")):
            raise ValueError(f"{suite}: installed driver signer does not match")
        if driver.get("installedSignature") != "Valid":
            raise ValueError(f"{suite}: installed driver signature is not valid")
        if driver.get("finalState") != "Stopped":
            raise ValueError(f"{suite}: driver service was not stopped")
    for suite in ("native-unit", "live-driver", "packet-flow"):
        required_tests = required_test_identities(test_manifest, suite)
        if not required_tests.issubset(evidence[suite].get("requiredTests", [])):
            raise ValueError(f"{suite}: required tests did not pass")
        test_results = evidence[suite].get("testResults", {})
        for test in required_tests:
            if test_results.get(test) == "skip":
                raise ValueError(f"{suite}: required test {test} was skipped")
            if test_results.get(test) != "pass":
                raise ValueError(f"{suite}: required test {test} has no pass result")

    packet_results = json.loads(args.packet_evidence.read_text(encoding="utf-8"))
    if not isinstance(packet_results, list):
        raise ValueError("packet evidence is not a JSON array")
    if not all(
        isinstance(value, dict) and value.get("packetPathValid") is True
        for value in packet_results
    ):
        raise ValueError("packet evidence contains an invalid path")
    required_packet_cases = set(matrix.get("requiredPacketCases", []))
    if not required_packet_cases:
        raise ValueError("qualification matrix has no required packet cases")
    observed_packet_cases = {
        value.get("case") for value in packet_results if isinstance(value.get("case"), str)
    }
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
        "driver": driver_lock,
        "driverFiles": locked_architecture["files"],
        "dependencyLocks": dependency_locks[0],
        "packetObservations": len(packet_results),
        "packetCases": sorted(observed_packet_cases),
        "evidenceSha256": {
            **{name: sha256(path) for name, path in evidence_paths.items()},
            "packet-flow-paths": sha256(args.packet_evidence),
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
