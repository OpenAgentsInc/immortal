#!/usr/bin/env python3
"""Bounded loopback-to-TLS WebSocket egress bridge for the join kit.

The provider engine accepts only a loopback ``ws://`` relay URL. This bridge
listens on exactly one loopback endpoint inside the provider's network
namespace and carries each connection to exactly one operator-declared public
relay authority over certificate-verified TLS. The only byte-level change it
makes is rewriting the ``Host`` header of the first HTTP request head so the
relay's TLS front door routes the WebSocket upgrade; everything after the
head is copied verbatim in both directions. It holds no key, signs nothing,
and refuses unbounded input.
"""

import argparse
import asyncio
import re
import ssl
import sys

MAX_CONNECTIONS = 64
MAX_HEAD_BYTES = 16 * 1024
CONNECT_TIMEOUT_SECONDS = 15
IDLE_TIMEOUT_SECONDS = 300
COPY_BYTES = 64 * 1024
HOST_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def parse_endpoint(value, *, loopback):
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("endpoint must have host:port form")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port is outside 1..=65535")
    if loopback:
        if host != "127.0.0.1":
            raise ValueError("egress bridge binds only 127.0.0.1")
    else:
        if not HOST_NAME.fullmatch(host):
            raise ValueError("upstream relay host name is invalid")
    return host, port


async def copy_stream(reader, writer):
    while True:
        data = await asyncio.wait_for(reader.read(COPY_BYTES), timeout=IDLE_TIMEOUT_SECONDS)
        if not data:
            return
        writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout=IDLE_TIMEOUT_SECONDS)


def rewrite_host(head, authority):
    lines = head.split(b"\r\n")
    rewritten = []
    replaced = False
    for line in lines:
        if line.lower().startswith(b"host:"):
            if replaced:
                raise ValueError("request head repeats the Host header")
            rewritten.append(b"Host: " + authority.encode("ascii"))
            replaced = True
        else:
            rewritten.append(line)
    if not replaced:
        raise ValueError("request head has no Host header")
    return b"\r\n".join(rewritten)


class Bridge:
    def __init__(self, listen, upstream):
        self.listen = listen
        self.upstream = upstream
        self.semaphore = asyncio.Semaphore(MAX_CONNECTIONS)
        host, port = upstream
        self.authority = host if port == 443 else f"{host}:{port}"
        self.tls = ssl.create_default_context()

    async def handle(self, client_reader, client_writer):
        if self.semaphore.locked():
            client_writer.close()
            return
        async with self.semaphore:
            upstream_writer = None
            try:
                head = await asyncio.wait_for(
                    client_reader.readuntil(b"\r\n\r\n"),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
                if len(head) > MAX_HEAD_BYTES:
                    raise ValueError("request head exceeds its bound")
                head = rewrite_host(head[:-4], self.authority) + b"\r\n\r\n"
                host, port = self.upstream
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=self.tls, server_hostname=host),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
                upstream_writer.write(head)
                await upstream_writer.drain()
                results = await asyncio.gather(
                    copy_stream(client_reader, upstream_writer),
                    copy_stream(upstream_reader, client_writer),
                    return_exceptions=True,
                )
                del results
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                pass
            finally:
                for writer in (client_writer, upstream_writer):
                    if writer is None:
                        continue
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except (OSError, asyncio.TimeoutError):
                        pass

    async def run(self):
        host, port = self.listen
        server = await asyncio.start_server(self.handle, host, port, limit=MAX_HEAD_BYTES)
        print(f"immortal-join-tls-egress: ready listen={host}:{port} upstream={self.authority}", flush=True)
        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--upstream", required=True)
    arguments = parser.parse_args()
    try:
        listen = parse_endpoint(arguments.listen, loopback=True)
        upstream = parse_endpoint(arguments.upstream, loopback=False)
    except ValueError as error:
        print(f"immortal-join-tls-egress: {error}", file=sys.stderr)
        raise SystemExit(2)
    asyncio.run(Bridge(listen, upstream).run())


if __name__ == "__main__":
    main()
