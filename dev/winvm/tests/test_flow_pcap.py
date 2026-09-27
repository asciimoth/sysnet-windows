#!/usr/bin/env python3
"""Tests for the isolated packet-flow evidence validator."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "flow-pcap.py"


class FlowPcapTest(unittest.TestCase):
    def run_validator(
        self, observations, tunnel=b"", underlay=b"", preexisting_evidence=None
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observation_path = root / "observations.jsonl"
            if isinstance(observations, str):
                observation_path.write_text(observations, encoding="utf-8")
            else:
                observation_path.write_text(
                    "".join(json.dumps(value) + "\n" for value in observations),
                    encoding="utf-8",
                )
            (root / "tunnel.pcap").write_bytes(tunnel)
            (root / "underlay.pcap").write_bytes(underlay)
            output = root / "evidence.json"
            if preexisting_evidence is not None:
                output.write_text(json.dumps(preexisting_evidence), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--observations",
                    str(observation_path),
                    "--tunnel",
                    str(root / "tunnel.pcap"),
                    "--underlay",
                    str(root / "underlay.pcap"),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            evidence = json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
            return result, evidence

    def test_parse_failures_remove_stale_evidence(self):
        cases = [
            ("malformed JSON", "{not-json}\n"),
            ("invalid observation", [{"token": "TOKEN", "expectedPath": "bad"}]),
            ("duplicate token", [
                {"token": "TOKEN", "expectedPath": "none"},
                {"token": "TOKEN", "expectedPath": "none"},
            ]),
        ]
        stale = [{"token": "OLD", "packetPathValid": True}]
        for name, observations in cases:
            with self.subTest(case=name):
                result, evidence = self.run_validator(
                    observations, preexisting_evidence=stale
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(evidence)

    def test_path_failure_replaces_stale_evidence_with_failed_result(self):
        result, evidence = self.run_validator(
            [{"token": "NEW", "expectedPath": "tunnel"}],
            preexisting_evidence=[{"token": "OLD", "packetPathValid": True}],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(evidence[0]["token"], "NEW")
        self.assertFalse(evidence[0]["packetPathValid"])

    def test_accepts_every_supported_path_result(self):
        observations = [
            {"token": "TUN_A", "expectedPath": "tunnel"},
            {"token": "UND_B", "expectedPath": "underlay"},
            {"token": "NON_C", "expectedPath": "none"},
            {"token": "OLD_T_D", "expectedPath": "tunnel-or-none-stopped"},
            {"token": "NO_T_E", "expectedPath": "tunnel-or-none-stopped"},
            {"token": "OLD_U_F", "expectedPath": "underlay-or-none-stopped"},
            {"token": "NO_U_G", "expectedPath": "underlay-or-none-stopped"},
        ]
        result, evidence = self.run_validator(
            observations,
            tunnel=b" TUN_A OLD_T_D ",
            underlay=b" UND_B OLD_U_F ",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(evidence), len(observations))
        self.assertTrue(all(value["packetPathValid"] for value in evidence))
        self.assertEqual(evidence[0]["tunnelPacketMarkers"], 1)
        self.assertEqual(evidence[1]["underlayPacketMarkers"], 1)

    def test_rejects_missing_or_wrong_link_markers(self):
        cases = [
            ("tunnel", b"", b""),
            ("tunnel", b"TOKEN", b"TOKEN"),
            ("tunnel", b"", b"TOKEN"),
            ("underlay", b"", b""),
            ("underlay", b"TOKEN", b"TOKEN"),
            ("underlay", b"TOKEN", b""),
            ("none", b"TOKEN", b""),
            ("none", b"", b"TOKEN"),
            ("tunnel-or-none-stopped", b"", b"TOKEN"),
            ("underlay-or-none-stopped", b"TOKEN", b""),
        ]
        for expected, tunnel, underlay in cases:
            with self.subTest(expected=expected, tunnel=tunnel, underlay=underlay):
                result, evidence = self.run_validator(
                    [{"token": "TOKEN", "expectedPath": expected}], tunnel, underlay
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("expected", result.stderr)
                self.assertFalse(evidence[0]["packetPathValid"])

    def test_accepts_public_api_encapsulation_and_preserves_metadata(self):
        observations = [
            {
                "token": "SYSNET_INCLUDED",
                "case": "E01-included-process-tunnel",
                "phase": "public-api",
                "role": "included",
                "network": "tcp4",
                "expectedPath": "tunnel",
            },
            {
                "token": "SYSNET_DESCENDANT",
                "case": "E03-excluded-descendant-underlay",
                "phase": "public-api",
                "role": "descendant",
                "network": "udp6",
                "expectedPath": "underlay",
            },
        ]
        result, evidence = self.run_validator(
            observations,
            tunnel=b"encapsulated SYSNET_INCLUDED",
            underlay=b"direct-ip SYSNET_DESCENDANT",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(evidence[0]["phase"], "public-api")
        self.assertEqual(evidence[0]["role"], "included")
        self.assertEqual(evidence[0]["case"], "E01-included-process-tunnel")
        self.assertEqual(evidence[1]["network"], "udp6")
        self.assertTrue(all(value["packetPathValid"] for value in evidence))

    def test_rejects_empty_manifest(self):
        result, evidence = self.run_validator("\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("observation file is empty", result.stderr)
        self.assertEqual(evidence, [])

    def test_rejects_invalid_observation_fields(self):
        cases = [
            ([{"token": "TOKEN", "expectedPath": "elsewhere"}], "unknown expected path"),
            ([{"token": "", "expectedPath": "none"}], "non-empty string"),
            ([{"token": "TÖKEN", "expectedPath": "none"}], "not ASCII"),
            ([{"expectedPath": "none"}], "non-empty string"),
            ([{"token": "TOKEN"}], "unknown expected path"),
            ([[],], "not an object"),
            (
                [
                    {"token": "TOKEN", "expectedPath": "none"},
                    {"token": "TOKEN", "expectedPath": "none"},
                ],
                "duplicate token",
            ),
            (
                [
                    {"token": "TOKEN", "expectedPath": "none"},
                    {"token": "TOKEN_LONG", "expectedPath": "none"},
                ],
                "overlaps another token",
            ),
        ]
        for observations, message in cases:
            with self.subTest(message=message):
                result, evidence = self.run_validator(observations)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertIsNone(evidence)

    def test_rejects_malformed_json(self):
        result, evidence = self.run_validator("{not-json}\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expecting property name", result.stderr)
        self.assertIsNone(evidence)

    def test_reports_every_invalid_observation(self):
        observations = [
            {"token": "FIRST", "expectedPath": "tunnel"},
            {"token": "SECOND", "expectedPath": "underlay"},
        ]
        result, evidence = self.run_validator(observations)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("line 1: FIRST", result.stderr)
        self.assertIn("line 2: SECOND", result.stderr)
        self.assertEqual(len(evidence), 2)
        self.assertTrue(all(not value["packetPathValid"] for value in evidence))


if __name__ == "__main__":
    unittest.main()
