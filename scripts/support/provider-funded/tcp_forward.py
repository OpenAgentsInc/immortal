#!/usr/bin/env python3

import argparse
import asyncio
import ipaddress
import re
import socket


MAX_RULES = 16
MAX_RESOLVED_ADDRESSES = 8
MAX_CONNECTIONS = 128
COPY_BYTES = 64 * 1024
CONNECT_TIMEOUT_SECONDS = 10
IDLE_TIMEOUT_SECONDS = 300
HOST_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def is_local_address(address):
    return (
        address.is_loopback
        or address.is_link_local
        or any(address in network for network in PRIVATE_NETWORKS)
    )


def parse_endpoint(value, *, bind):
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("endpoint must have host:port form")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port is outside 1..=65535")
    if bind:
        if host not in {"127.0.0.1", "0.0.0.0"}:
            raise ValueError("forwarder binds only loopback or its private container interface")
    else:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not HOST_NAME.fullmatch(host):
                raise ValueError("forward destination host is invalid") from None
        else:
            if not is_local_address(address):
                raise ValueError("forward destination is not private or loopback")
    return host, port


def parse_rule(value):
    bind_value, separator, destination_value = value.partition("=")
    if not separator:
        raise ValueError("forward rule must have bind=destination form")
    return (
        parse_endpoint(bind_value, bind=True),
        parse_endpoint(destination_value, bind=False),
    )


async def resolve_private(host, port):
    loop = asyncio.get_running_loop()
    results = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
        timeout=CONNECT_TIMEOUT_SECONDS,
    )
    addresses = []
    for family, socket_type, protocol, _, socket_address in results:
        address = ipaddress.ip_address(socket_address[0])
        if not is_local_address(address):
            raise RuntimeError("forward destination resolved outside private address space")
        candidate = (family, socket_type, protocol, str(address), socket_address[1])
        if candidate not in addresses:
            addresses.append(candidate)
        if len(addresses) > MAX_RESOLVED_ADDRESSES:
            raise RuntimeError("forward destination resolved to too many addresses")
    if not addresses:
        raise RuntimeError("forward destination did not resolve")
    return addresses


async def open_private_connection(host, port):
    last_error = None
    for family, _, _, address, resolved_port in await resolve_private(host, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, resolved_port, family=family),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except (OSError, asyncio.TimeoutError) as error:
            last_error = error
            continue
        peer = writer.get_extra_info("peername")
        if not peer:
            writer.close()
            await writer.wait_closed()
            raise RuntimeError("forward destination has no connected peer")
        peer_address = ipaddress.ip_address(peer[0])
        if not is_local_address(peer_address):
            writer.close()
            await writer.wait_closed()
            raise RuntimeError("connected forward destination is not private")
        return reader, writer
    raise RuntimeError("could not connect to private forward destination") from last_error


async def copy_stream(reader, writer):
    while True:
        data = await asyncio.wait_for(
            reader.read(COPY_BYTES), timeout=IDLE_TIMEOUT_SECONDS
        )
        if not data:
            return
        writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout=IDLE_TIMEOUT_SECONDS)


async def close_writer(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except (BrokenPipeError, ConnectionResetError):
        pass


async def forward_connection(
    client_reader, client_writer, destination, connection_limit
):
    async with connection_limit:
        remote_writer = None
        try:
            remote_reader, remote_writer = await open_private_connection(*destination)
            copies = {
                asyncio.create_task(copy_stream(client_reader, remote_writer)),
                asyncio.create_task(copy_stream(remote_reader, client_writer)),
            }
            done, pending = await asyncio.wait(
                copies, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
        except (OSError, RuntimeError, asyncio.TimeoutError):
            pass
        finally:
            if remote_writer is not None:
                await close_writer(remote_writer)
            await close_writer(client_writer)


async def run(rules):
    connection_limit = asyncio.Semaphore(MAX_CONNECTIONS)
    servers = []
    for bind, destination in rules:
        server = await asyncio.start_server(
            lambda reader, writer, destination=destination: forward_connection(
                reader, writer, destination, connection_limit
            ),
            *bind,
            start_serving=False,
        )
        servers.append(server)
    for server in servers:
        await server.start_serving()
    await asyncio.gather(*(server.serve_forever() for server in servers))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rule", action="append", required=True)
    arguments = parser.parse_args()
    if not 1 <= len(arguments.rule) <= MAX_RULES:
        parser.error(f"rule count must be inside 1..={MAX_RULES}")
    try:
        rules = [parse_rule(value) for value in arguments.rule]
    except ValueError as error:
        parser.error(str(error))
    binds = [bind for bind, _ in rules]
    if len(binds) != len(set(binds)):
        parser.error("forward rules repeat a bind endpoint")
    asyncio.run(run(rules))


if __name__ == "__main__":
    main()
