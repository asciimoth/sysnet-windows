#!/usr/bin/env python3
"""Validate packet markers against the two isolated QEMU link captures."""

import argparse
import json
from pathlib import Path

EXPECTED_PATHS = {
    "tunnel",
    "underlay",
    "none",
    "tunnel-or-none-stopped",
    "underlay-or-none-stopped",
}


def marker_for(observation, line_number, seen_tokens):
    if not isinstance(observation, dict):
        raise ValueError(f"line {line_number}: observation is not an object")
    token = observation.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError(f"line {line_number}: token is not a non-empty string")
    try:
        marker = token.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"line {line_number}: token is not ASCII") from error
    if token in seen_tokens:
        raise ValueError(f"line {line_number}: duplicate token {token}")
    if any(token in existing or existing in token for existing in seen_tokens):
        raise ValueError(f"line {line_number}: token overlaps another token")
    seen_tokens.add(token)
    expected = observation.get("expectedPath")
    if expected not in EXPECTED_PATHS:
        raise ValueError(f"line {line_number}: unknown expected path {expected!r}")
    return marker


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--tunnel", required=True, type=Path)
    parser.add_argument("--underlay", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    # Parse failures must not leave packet evidence from an earlier run.
    args.output.unlink(missing_ok=True)

    tunnel = args.tunnel.read_bytes()
    underlay = args.underlay.read_bytes()
    results = []
    failures = []
    seen_tokens = set()
    with args.observations.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            observation = json.loads(line)
            marker = marker_for(observation, line_number, seen_tokens)
            tunnel_count = tunnel.count(marker)
            underlay_count = underlay.count(marker)
            expected = observation["expectedPath"]
            valid = {
                "tunnel": tunnel_count > 0 and underlay_count == 0,
                "underlay": underlay_count > 0 and tunnel_count == 0,
                "none": tunnel_count == 0 and underlay_count == 0,
                "tunnel-or-none-stopped": underlay_count == 0,
                "underlay-or-none-stopped": tunnel_count == 0,
            }[expected]
            result = dict(observation)
            result.update(
                tunnelPacketMarkers=tunnel_count,
                underlayPacketMarkers=underlay_count,
                packetPathValid=valid,
            )
            results.append(result)
            if not valid:
                failures.append(
                    f"line {line_number}: {observation['token']} expected {expected}, "
                    f"found tunnel={tunnel_count} underlay={underlay_count}"
                )
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    if not results:
        raise SystemExit("packet-flow observation file is empty")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"Validated {len(results)} packet observations")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"flow-pcap.py: {error}") from error
