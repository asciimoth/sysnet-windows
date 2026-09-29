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

PUBLIC_PROFILE_NETWORKS = {
    "ipv4": {"tcp4", "udp4"},
    "ipv6": {"tcp6", "udp6"},
    "dual": {"tcp4", "udp4", "tcp6", "udp6"},
}


def profile_coverage(networks):
    return {
        (profile, network)
        for profile, profile_networks in PUBLIC_PROFILE_NETWORKS.items()
        for network in profile_networks
        if network in networks
    }


PUBLIC_CASE_COVERAGE = {
    "E01-included-process-tunnel": profile_coverage({"tcp4", "udp4", "tcp6", "udp6"}),
    "E02-excluded-process-underlay": profile_coverage({"tcp4", "udp4", "tcp6", "udp6"}),
    "E03-excluded-descendant-underlay": profile_coverage({"tcp4", "udp4", "tcp6", "udp6"}),
    "E04-pre-existing-ipc-target-tunnel": profile_coverage({"tcp4", "udp4", "tcp6", "udp6"}),
    "E05-explicit-application-dns-underlay": profile_coverage({"udp4", "udp6"}),
    "E06-shared-windows-dns-client": {
        ("ipv4", "ip4"), ("ipv6", "ip6"), ("dual", "ip4"), ("dual", "ip6"),
    },
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
    public_cases = {name: set() for name in PUBLIC_CASE_COVERAGE}
    saw_public = False
    previous = None
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
            if observation.get("phase") == "public-api":
                saw_public = True
                is_control = observation.get("positiveControl") is True
                if is_control:
                    if observation.get("case", "").startswith("CTRL-") is False:
                        raise ValueError(
                            f"line {line_number}: positive control has no CTRL case"
                        )
                else:
                    control_token = observation.get("controlToken")
                    if (
                        previous is None
                        or previous.get("positiveControl") is not True
                        or previous.get("token") != control_token
                    ):
                        raise ValueError(
                            f"line {line_number}: public assertion lacks its immediately preceding positive control"
                        )
                    opposite = "underlay" if expected == "tunnel" else "tunnel"
                    if previous.get("expectedPath") != opposite:
                        raise ValueError(
                            f"line {line_number}: positive control does not prove the opposite link"
                        )
                    case = observation.get("case")
                    network = observation.get("network")
                    profile = observation.get("profile")
                    if case not in public_cases:
                        raise ValueError(
                            f"line {line_number}: unknown public API case {case!r}"
                        )
                    if case == "E04-pre-existing-ipc-target-tunnel" and (
                        observation.get("preExistingTarget") is not True
                        or observation.get("requestingRole") != "excluded"
                    ):
                        raise ValueError(
                            f"line {line_number}: IPC evidence does not identify the pre-existing target and excluded requester"
                        )
                    if case == "E06-shared-windows-dns-client" and not observation.get(
                        "limitation"
                    ):
                        raise ValueError(
                            f"line {line_number}: shared DNS evidence lacks its attribution limitation"
                        )
                    if profile not in PUBLIC_PROFILE_NETWORKS:
                        raise ValueError(
                            f"line {line_number}: unknown public API profile {profile!r}"
                        )
                    public_cases[case].add((profile, network))
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
            previous = observation
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    if not results:
        raise SystemExit("packet-flow observation file is empty")
    missing_public = []
    for case, required_coverage in PUBLIC_CASE_COVERAGE.items():
        missing = required_coverage - public_cases[case]
        if missing:
            missing_public.append(
                f"{case}: {', '.join('/'.join(value) for value in sorted(missing))}"
            )
    if saw_public and missing_public:
        failures.append("missing public API coverage: " + "; ".join(missing_public))
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"Validated {len(results)} packet observations")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"flow-pcap.py: {error}") from error
