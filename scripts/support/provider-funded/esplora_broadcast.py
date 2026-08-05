#!/usr/bin/env python3

import base64
import http.client
import http.server
import json
import os
import re
import sys


MAX_TRANSACTION_HEX_BYTES = 64 * 1024
LOWER_HEX = re.compile(rb"[0-9a-f]+")
TXID = re.compile(r"[0-9a-f]{64}")


def unique_object(pairs):
    value = {}
    for name, child in pairs:
        if name in value:
            raise ValueError("duplicate JSON object member")
        value[name] = child
    return value


class EsploraHandler(http.server.BaseHTTPRequestHandler):
    server_version = "immortal-lab-esplora"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self._respond(200, b"ready\n")

    def do_POST(self):
        if self.path != "/api/tx" or self.headers.get("Content-Type") != "text/plain":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(400)
            return
        if not 2 <= length <= MAX_TRANSACTION_HEX_BYTES or length % 2:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        if len(body) != length or LOWER_HEX.fullmatch(body) is None:
            self.send_error(400)
            return
        try:
            transaction_id = self._broadcast(body.decode("ascii"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            diagnostic = str(error).replace("\r", " ").replace("\n", " ")[:512]
            print(
                f"immortal-lab-esplora: broadcast refused: {diagnostic}",
                file=sys.stderr,
                flush=True,
            )
            self.send_error(502)
            return
        self._respond(200, transaction_id.encode("ascii") + b"\n")

    def _broadcast(self, raw_transaction):
        request = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": "immortal-doomsday-keyless",
                "method": "sendrawtransaction",
                "params": [raw_transaction],
            },
            separators=(",", ":"),
        ).encode()
        user = os.environ["IMMORTAL_ESPLORA_BITCOIND_RPC_USER"]
        password = os.environ["IMMORTAL_ESPLORA_BITCOIND_RPC_PASSWORD"]
        authorization = base64.b64encode(f"{user}:{password}".encode()).decode()
        connection = http.client.HTTPConnection("127.0.0.1", 18443, timeout=5)
        try:
            connection.request(
                "POST",
                "/",
                body=request,
                headers={
                    "Authorization": f"Basic {authorization}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(request)),
                },
            )
            response = connection.getresponse()
            encoded = response.read(8193)
        finally:
            connection.close()
        if len(encoded) > 8192:
            raise ValueError("bitcoind refused transaction")
        document = json.loads(encoded, object_pairs_hook=unique_object)
        if not isinstance(document, dict) or set(document) != {"result", "error", "id"}:
            raise ValueError("bitcoind response has another shape")
        if document["error"] is not None:
            error = document["error"]
            if (
                not isinstance(error, dict)
                or set(error) != {"code", "message"}
                or not isinstance(error["code"], int)
                or not isinstance(error["message"], str)
                or len(error["message"]) > 1024
            ):
                raise ValueError("bitcoind error has another shape")
            raise ValueError(
                f"bitcoind RPC {error['code']}: {error['message']}"
            )
        if response.status != 200:
            raise ValueError(f"bitcoind returned HTTP {response.status}")
        transaction_id = document["result"]
        if not isinstance(transaction_id, str) or TXID.fullmatch(transaction_id) is None:
            raise ValueError("bitcoind response has a non-canonical txid")
        return transaction_id

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *arguments):
        return


def main():
    server = http.server.HTTPServer(("127.0.0.1", 3002), EsploraHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
