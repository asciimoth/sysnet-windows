#!/usr/bin/env python3
"""Bounded QEMU Guest Agent and QMP client."""

import argparse
import base64
import json
import socket
import sys
import time


class JSONSocket:
    def __init__(self, path: str, timeout: float):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.buffer = b""

    def send(self, value):
        self.sock.sendall(json.dumps(value, separators=(",", ":")).encode() + b"\n")

    def receive(self):
        while b"\n" not in self.buffer:
            block = self.sock.recv(65536)
            if not block:
                raise RuntimeError("socket closed before a JSON response")
            self.buffer += block
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def response(self):
        while True:
            value = self.receive()
            if "event" in value or "QMP" in value:
                continue
            if "error" in value:
                raise RuntimeError(json.dumps(value["error"], sort_keys=True))
            if "return" in value:
                return value["return"]

    def close(self):
        self.sock.close()


def request(path, timeout, command, arguments=None):
    client = JSONSocket(path, timeout)
    try:
        value = {"execute": command}
        if arguments is not None:
            value["arguments"] = arguments
        client.send(value)
        return client.response()
    finally:
        client.close()


def guest_exec(path, timeout, executable, arguments):
    result = request(path, timeout, "guest-exec", {
        "path": executable, "arg": arguments, "capture-output": True,
    })
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = request(path, min(10, max(0.1, deadline - time.monotonic())),
                         "guest-exec-status", {"pid": result["pid"]})
        if status.get("exited"):
            sys.stdout.buffer.write(base64.b64decode(status.get("out-data", "")))
            sys.stderr.buffer.write(base64.b64decode(status.get("err-data", "")))
            return int(status.get("exitcode", 0))
        time.sleep(0.25)
    raise TimeoutError(f"guest command did not finish in {timeout:g} seconds")


def qmp(path, timeout, command, arguments):
    client = JSONSocket(path, timeout)
    try:
        if "QMP" not in client.receive():
            raise RuntimeError("QMP greeting is absent")
        client.send({"execute": "qmp_capabilities"}); client.response()
        value = {"execute": command}
        if arguments is not None:
            value["arguments"] = arguments
        client.send(value)
        return client.response()
    finally:
        client.close()


def file_read(path, timeout, guest_path, limit):
    handle = request(path, timeout, "guest-file-open", {"path": guest_path, "mode": "r"})
    output = bytearray()
    try:
        while len(output) < limit:
            count = min(65536, limit - len(output))
            result = request(path, timeout, "guest-file-read", {
                "handle": handle, "count": count,
            })
            block = base64.b64decode(result.get("buf-b64", ""))
            if len(block) > count:
                raise RuntimeError("guest-file-read exceeded the requested bound")
            output.extend(block)
            if result.get("eof"):
                break
        else:
            raise RuntimeError(f"guest file exceeds {limit} bytes")
    finally:
        request(path, timeout, "guest-file-close", {"handle": handle})
    sys.stdout.buffer.write(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True); parser.add_argument("--timeout", type=float, default=10)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("ping")
    shutdown = sub.add_parser("shutdown"); shutdown.add_argument("--mode", choices=("powerdown", "halt", "reboot"), default="powerdown")
    execute = sub.add_parser("exec"); execute.add_argument("executable"); execute.add_argument("arguments", nargs=argparse.REMAINDER)
    monitor = sub.add_parser("qmp"); monitor.add_argument("command"); monitor.add_argument("--arguments", type=json.loads)
    read = sub.add_parser("read"); read.add_argument("path"); read.add_argument("--limit", type=int, default=16 * 1024 * 1024)
    args = parser.parse_args()
    if args.operation == "ping": request(args.socket, args.timeout, "guest-ping")
    elif args.operation == "shutdown": request(args.socket, args.timeout, "guest-shutdown", {"mode": args.mode})
    elif args.operation == "exec": return guest_exec(args.socket, args.timeout, args.executable, args.arguments)
    elif args.operation == "read": file_read(args.socket, args.timeout, args.path, args.limit)
    else:
        result = qmp(args.socket, args.timeout, args.command, args.arguments)
        if result not in (None, {}): print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"qga.py: {error}", file=sys.stderr)
        raise SystemExit(1)
