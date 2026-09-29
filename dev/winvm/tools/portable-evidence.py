#!/usr/bin/env python3
"""Record a successful portable gate against one packaged source tree."""

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


LOCK_FILES = {
    "goMod": "go.mod",
    "goSum": "go.sum",
    "flakeLock": "flake.lock",
    "imageLock": "dev/winvm/image-lock.json",
    "nativeDriverLock": "dev/winvm/native-driver-lock.json",
    "qualificationMatrix": "dev/winvm/qualification-matrix.json",
    "wintunLock": "dev/winvm/wintun-lock.json",
    "testManifest": "dev/winvm/test-manifest.json",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    # A failed recorder invocation must not leave an older passing record.
    args.output.unlink(missing_ok=True)
    root = args.root.resolve()
    revision = git(root, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("repository revision is not a full Git object name")
    tree_state = "dirty" if git(root, "status", "--porcelain") else "clean"
    go_version = subprocess.run(
        ("go", "version"), check=True, capture_output=True, text=True
    ).stdout.strip()
    if not re.fullmatch(r"go version go\S+ linux/amd64", go_version):
        raise ValueError("the qualifying portable gate requires native Linux amd64")
    manifest = json.loads((root / "dev/winvm/test-manifest.json").read_text())
    required_stages = manifest["suites"]["portable"]["requiredStages"]
    if not isinstance(required_stages, list) or not required_stages:
        raise ValueError("portable required stages are absent")
    if len(set(required_stages)) != len(required_stages):
        raise ValueError("portable required stages are duplicated")

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    evidence = {
        "schemaVersion": 1,
        "suite": "portable",
        "outcome": "passed",
        # The recorder runs only after all check-fast prerequisites succeed.
        "startedAt": now,
        "finishedAt": now,
        "sysnetWindowsRevision": revision,
        "sysnetWindowsTreeState": tree_state,
        "sourceArchiveSha256": sha256(args.source_archive),
        "goVersion": go_version,
        "dependencyLocks": {
            name: sha256(root / relative) for name, relative in LOCK_FILES.items()
        },
        "requiredStages": required_stages,
        "stageResults": dict.fromkeys(required_stages, "pass"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"portable-evidence.py: {error}") from error
