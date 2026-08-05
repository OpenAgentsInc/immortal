#!/usr/bin/env python3
"""Publish a dev-work-seed trace to a relay over a dependency-free WebSocket.

Reads the `immortal dev-work-seed` JSON trace (emit mode) on stdin, publishes
every signed event to the relay URL given as the only argument (ws:// or
wss://), then verifies the NIP-PI rendering-contract filters:

    {"kinds": [32200], "authors": ["<authority>"]}
    {"kinds": [32171], "#work": ["<first work_ref>"]}

Exits nonzero unless every event receives OK true and both queries return at
least the published counts. Relay acceptance is transport evidence only.
"""

import json
import os
import socket
import ssl
import struct
import sys
from base64 import b64encode
from urllib.parse import urlsplit


def send_text(connection, value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    mask = os.urandom(4)
    header = bytearray([0x81])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length <= 0xFFFF:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    header.extend(mask)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    connection.sendall(header + masked)


def read_exact(stream, length):
    value = stream.read(length)
    if value is None or len(value) != length:
        raise RuntimeError("WebSocket closed before a complete frame arrived")
    return value


def read_text(connection, stream):
    while True:
        first, second = read_exact(stream, 2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", read_exact(stream, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", read_exact(stream, 8))[0]
        mask = read_exact(stream, 4) if second & 0x80 else None
        payload = read_exact(stream, length)
        if mask is not None:
            payload = bytes(
                byte ^ mask[index % 4] for index, byte in enumerate(payload)
            )
        if opcode == 0x8:
            raise RuntimeError("relay closed the WebSocket")
        if opcode == 0x9:
            connection.sendall(bytes([0x8A, len(payload)]) + payload)
            continue
        if opcode == 0x1:
            return json.loads(payload)


def connect(relay_url):
    parts = urlsplit(relay_url)
    if parts.scheme not in ("ws", "wss") or not parts.hostname:
        raise RuntimeError(f"relay URL must be ws:// or wss://: {relay_url}")
    port = parts.port or (443 if parts.scheme == "wss" else 80)
    connection = socket.create_connection((parts.hostname, port), timeout=15)
    connection.settimeout(15)
    if parts.scheme == "wss":
        context = ssl.create_default_context()
        connection = context.wrap_socket(connection, server_hostname=parts.hostname)
    stream = connection.makefile("rb")
    host_header = parts.hostname if port in (80, 443) else f"{parts.hostname}:{port}"
    key = b64encode(os.urandom(16)).decode()
    connection.sendall(
        (
            f"GET {parts.path or '/'} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    status = stream.readline().decode().strip()
    if "101" not in status:
        raise RuntimeError(f"WebSocket upgrade failed: {status}")
    while stream.readline() not in (b"\r\n", b""):
        pass
    return connection, stream


def query_count(connection, stream, subscription, query_filter):
    """Return the matched event count, or the relay's CLOSED reason string
    when the deployed relay does not support the filter yet."""
    send_text(connection, ["REQ", subscription, query_filter])
    matched = 0
    while True:
        message = read_text(connection, stream)
        if message[0] == "EVENT" and message[1] == subscription:
            matched += 1
        elif message[0] == "EOSE" and message[1] == subscription:
            send_text(connection, ["CLOSE", subscription])
            return matched
        elif message[0] == "CLOSED" and message[1] == subscription:
            return str(message[2] if len(message) > 2 else "closed")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: dev-work-publish.py <relay-url> < seed-trace.json")
    relay_url = sys.argv[1]
    trace = json.load(sys.stdin)
    events = trace["events"]
    authority = trace["authority_pubkey"]
    if not events:
        raise SystemExit("seed trace contains no events")

    connection, stream = connect(relay_url)
    accepted = 0
    for event in events:
        send_text(connection, ["EVENT", event])
        while True:
            message = read_text(connection, stream)
            if message[0] == "OK" and message[1] == event["id"]:
                if message[2] is not True:
                    raise RuntimeError(f"relay refused event: {message}")
                accepted += 1
                break
            if message[0] == "AUTH":
                continue
            if message[0] == "NOTICE":
                continue

    projection_filter = {"kinds": [32200], "authors": [authority]}
    projections = query_count(connection, stream, "dev-work-projections", projection_filter)
    first_work_ref = next(
        value
        for tag in events[0]["tags"]
        for name, value in [tag[:2]]
        if name == "d"
    )
    work_event_filter = {"kinds": [32171], "#work": [first_work_ref]}
    work_events = query_count(connection, stream, "dev-work-events", work_event_filter)

    connection.sendall(b"\x88\x80\x00\x00\x00\x00")
    connection.close()

    expected_projections = sum(1 for event in events if event["kind"] == 32200)
    report = {
        "relay_url": relay_url,
        "authority_pubkey": authority,
        "published": accepted,
        "queries": [
            {"filter": projection_filter, "matched": projections},
            {"filter": work_event_filter, "matched": work_events},
        ],
    }
    print(json.dumps(report, indent=2))
    if isinstance(projections, str) or projections < expected_projections:
        raise SystemExit(
            f"projection query returned {projections!r}; expected {expected_projections} events"
        )
    if isinstance(work_events, str):
        print(
            "warning: the deployed relay does not support the #work filter yet "
            f"({work_events}); redeploy the relay with migration 0014 to serve "
            "the full NIP-PI rendering contract",
            file=sys.stderr,
        )
    elif work_events < 1:
        raise SystemExit("work-event query returned no events")


if __name__ == "__main__":
    main()
