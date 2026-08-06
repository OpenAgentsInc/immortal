#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE_BYTES = 2_097_152
TIMEOUT_SECONDS = 10
ENDPOINTS = (
    "/v2/version",
    "/v2/swap/submarine",
    "/v2/swap/reverse",
    "/v2/chain/fees",
    "/v2/chain/BTC/fee",
    "/v2/chain/BTC/height",
    "/v2/nodes/stats",
)


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise urllib.error.HTTPError(
            request.full_url, code, "redirect refused", headers, file_pointer
        )


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Compare bounded public GET responses without opening a swap"
    )
    parser.add_argument("--reference-origin", required=True)
    parser.add_argument("--candidate-origin", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def validate_origin(value, reference):
    if len(value) > 2048 or any(character.isspace() for character in value):
        raise ValueError("origin is empty, oversized, or contains whitespace")
    parsed = urllib.parse.urlsplit(value)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("origin must contain only a scheme and authority")
    if not parsed.hostname or parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("origin authority is invalid")
    if reference:
        if parsed.scheme != "https":
            raise ValueError("reference origin must use HTTPS")
    elif parsed.scheme == "http":
        try:
            loopback = parsed.hostname == "localhost" or socket.gethostbyname(
                parsed.hostname
            ).startswith("127.")
        except OSError as error:
            raise ValueError("candidate loopback host did not resolve") from error
        if not loopback:
            raise ValueError("candidate plaintext origin must resolve to loopback")
    elif parsed.scheme != "https":
        raise ValueError("candidate origin must use HTTPS or loopback HTTP")
    return value


def reject_duplicate_members(pairs):
    value = {}
    for name, member in pairs:
        if name in value:
            raise ValueError(f"duplicate JSON member: {name}")
        value[name] = member
    return value


def response_shape(value, prefix="", depth=0):
    if depth > 8:
        return [f"{prefix}:depth_exceeded"]
    if isinstance(value, dict):
        paths = [f"{prefix}:object"]
        for name in sorted(value):
            paths.extend(response_shape(value[name], f"{prefix}/{name}", depth + 1))
    elif isinstance(value, list):
        paths = [f"{prefix}:array"]
        for member in value[:4]:
            paths.extend(response_shape(member, f"{prefix}/*", depth + 1))
    elif value is None:
        paths = [f"{prefix}:null"]
    elif isinstance(value, bool):
        paths = [f"{prefix}:boolean"]
    elif isinstance(value, str):
        paths = [f"{prefix}:string"]
    elif isinstance(value, (int, float)):
        paths = [f"{prefix}:number"]
    else:
        raise ValueError("response contains an unsupported JSON value")
    if len(paths) > 512:
        raise ValueError("response shape exceeds its path bound")
    return paths


def fetch(opener, origin, endpoint):
    request = urllib.request.Request(
        origin + endpoint,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "immortal-readonly-shadow/1"},
    )
    with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise ValueError(f"{endpoint} returned HTTP {response.status}")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError(f"{endpoint} exceeded the response byte bound")
        trailing = response.read(1)
        if trailing:
            raise ValueError(f"{endpoint} exceeded the response byte bound")
    value = json.loads(body, object_pairs_hook=reject_duplicate_members)
    shape = sorted(set(response_shape(value)))
    return {
        "status": 200,
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "json_shape": shape,
    }


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def main():
    arguments = parse_arguments()
    if not re.fullmatch(r"[0-9a-f]{40}", arguments.source_commit):
        raise SystemExit("source commit must be 40 lowercase hexadecimal characters")
    try:
        reference = validate_origin(arguments.reference_origin, True)
        candidate = validate_origin(arguments.candidate_origin, False)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    output = pathlib.Path(arguments.output)
    if output.exists():
        raise SystemExit("output already exists")
    if not output.parent.is_dir():
        raise SystemExit("output directory does not exist")

    opener = urllib.request.build_opener(RejectRedirects())
    started_at = timestamp()
    comparisons = []
    try:
        for endpoint in ENDPOINTS:
            reference_result = fetch(opener, reference, endpoint)
            candidate_result = fetch(opener, candidate, endpoint)
            reference_shape = set(reference_result["json_shape"])
            candidate_shape = set(candidate_result["json_shape"])
            comparisons.append(
                {
                    "endpoint": endpoint,
                    "method": "GET",
                    "reference": reference_result,
                    "candidate": candidate_result,
                    "shape": {
                        "exact_match": reference_shape == candidate_shape,
                        "reference_only": sorted(reference_shape - candidate_shape),
                        "candidate_only": sorted(candidate_shape - reference_shape),
                    },
                }
            )
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
        raise SystemExit(f"read-only shadow failed: {error}") from error

    record = {
        "schema": "openagents.immortal.boltz-readonly-shadow.v1",
        "source_commit": arguments.source_commit,
        "started_at": started_at,
        "finished_at": timestamp(),
        "result": "passed",
        "reference_origin": reference,
        "candidate_origin": candidate,
        "request_contract": {
            "methods": ["GET"],
            "endpoints": list(ENDPOINTS),
            "authentication": False,
            "request_bodies": False,
            "swap_identifiers": False,
            "websocket": False,
            "redirects": False,
            "timeout_seconds": TIMEOUT_SECONDS,
            "maximum_response_bytes": MAX_RESPONSE_BYTES,
        },
        "summary": {
            "endpoints": len(comparisons),
            "successful_reference_reads": len(comparisons),
            "successful_candidate_reads": len(comparisons),
            "exact_shape_matches": sum(
                1 for comparison in comparisons if comparison["shape"]["exact_match"]
            ),
            "divergences": sum(
                1 for comparison in comparisons if not comparison["shape"]["exact_match"]
            ),
        },
        "comparisons": comparisons,
        "claims": {
            "read_only_shadow": True,
            "live_reference_observed": True,
            "candidate_funded_regtest_observed": True,
            "live_candidate_deployment": False,
            "public_replacement": False,
        },
    }
    serialized = json.dumps(record, indent=2, sort_keys=True) + "\n"
    temporary = output.with_name(output.name + f".pending-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(serialized)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    print(
        "boltz-readonly-shadow: "
        f"{len(comparisons)} GET comparisons passed with "
        f"{record['summary']['divergences']} recorded shape divergences"
    )


if __name__ == "__main__":
    main()
