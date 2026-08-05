#!/usr/bin/env python3

import http.server
import json
import os
import pathlib
import tempfile


MAX_BODY_BYTES = 64 * 1024
FORBIDDEN_NAMES = {
    "claim_key",
    "macaroon",
    "password",
    "preimage",
    "private_key",
    "refund_key",
    "seed",
    "secret",
}


def contains_forbidden_name(value):
    if isinstance(value, dict):
        return any(
            str(name).lower() in FORBIDDEN_NAMES or contains_forbidden_name(child)
            for name, child in value.items()
        )
    if isinstance(value, list):
        return any(contains_forbidden_name(child) for child in value)
    return False


def unique_object(pairs):
    value = {}
    for name, child in pairs:
        if name in value:
            raise ValueError("duplicate JSON object member")
        value[name] = child
    return value


class AlertHandler(http.server.BaseHTTPRequestHandler):
    server_version = "immortal-provider-smoke"
    sys_version = ""

    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        body = b"ready\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/provider-alert":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        try:
            alert = json.loads(body, object_pairs_hook=unique_object)
        except (UnicodeDecodeError, ValueError):
            self.send_error(400)
            return
        if contains_forbidden_name(alert):
            self.send_error(400)
            return
        output_path = pathlib.Path(os.environ["IMMORTAL_PROVIDER_SMOKE_ALERT_FILE"])
        output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            dir=output_path.parent, prefix="alert.", text=True
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(alert, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
            os.replace(temporary_path, output_path)
        except BaseException:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format_string, *arguments):
        return


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 19092), AlertHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
