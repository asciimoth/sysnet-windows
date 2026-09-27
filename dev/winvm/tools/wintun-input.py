#!/usr/bin/env python3
"""Verify the locked Wintun archive and extract one architecture DLL."""

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path


MAX_DLL_SIZE = 16 * 1024 * 1024


def locked_hash(path: Path) -> str:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "wintun"}:
        raise ValueError("invalid Wintun input lock")
    if value["schemaVersion"] != 1:
        raise ValueError("unsupported Wintun input lock schema")
    wintun = value["wintun"]
    required = {"version", "file", "source", "sha256"}
    if not isinstance(wintun, dict) or set(wintun) != required:
        raise ValueError("invalid Wintun lock entry")
    if not all(isinstance(wintun[field], str) for field in required):
        raise ValueError("invalid Wintun lock value")
    version = wintun["version"]
    file_name = wintun["file"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid locked Wintun version")
    if file_name != f"wintun-{version}.zip":
        raise ValueError("invalid locked Wintun file name")
    if wintun["source"] != f"https://www.wintun.net/builds/{file_name}":
        raise ValueError("invalid locked Wintun source")
    if not re.fullmatch(r"[0-9a-f]{64}", wintun["sha256"]):
        raise ValueError("invalid locked Wintun SHA-256")
    return wintun["sha256"]


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract(lock: Path, archive_path: Path, architecture: str, output: Path) -> None:
    expected = locked_hash(lock)
    actual = file_hash(archive_path)
    if actual != expected:
        raise ValueError(f"Wintun archive SHA-256 mismatch: expected {expected}, got {actual}")
    member_name = f"wintun/bin/{architecture}/wintun.dll"
    with zipfile.ZipFile(archive_path) as archive:
        members = [member for member in archive.infolist() if member.filename == member_name]
        if len(members) != 1:
            raise ValueError(f"archive has {len(members)} {member_name} entries; expected one")
        member = members[0]
        if member.is_dir() or member.file_size == 0 or member.file_size > MAX_DLL_SIZE:
            raise ValueError(f"invalid {member_name} size {member.file_size}")
        data = archive.read(member)
    with output.open("xb") as destination:
        destination.write(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    extract(args.lock, args.archive, args.architecture, args.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        raise SystemExit(f"wintun-input.py: {error}") from error
