"""MUXI-REFLECT/1: tell a peer what address its packets arrive from.

NatDiscovery (UDP) and TcpPuncher.DiscoverAsync (TCP) ask several reflector ports, ideally on
more than one public IP, and compare the answers to learn how their NAT maps ports.

UDP: request ``MUXI-REFLECT/1 <nonce>``, reply ``{"nonce": ..., "ip": ..., "port": ...}``.
TCP: on accept the server writes ``{"ip": ..., "port": ...}`` and closes.

Replies are about the size of a request, and each source address gets a small budget per
second, so the reflector is not useful for amplification.

Run standalone: ``python -m muxi_p2p_signaling.reflector [--host 0.0.0.0] [--udp 45701,45702,45703]
[--tcp 45711,45712]``.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import time

MAGIC = b"MUXI-REFLECT/1 "
UDP_PORTS = (45701, 45702, 45703)
TCP_PORTS = (45711, 45712)
MAX_NONCE = 64
#: replies per source IP per second, over all ports
RATE_PER_SECOND = 40

log = logging.getLogger("muxi_p2p.reflector")


def _plain(host: str) -> str:
    """IPv4-mapped IPv6 (dual-stack sockets) is reported as plain IPv4."""
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return host
    if address.version == 6 and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def udp_reply(data: bytes, host: str, port: int) -> bytes | None:
    if not data.startswith(MAGIC):
        return None
    nonce = data[len(MAGIC):].strip()
    if not nonce or len(nonce) > MAX_NONCE:
        return None
    try:
        text = nonce.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text.isprintable():
        return None
    return json.dumps({"nonce": text, "ip": _plain(host), "port": port},
                      separators=(",", ":")).encode("ascii")


def tcp_reply(host: str, port: int) -> bytes:
    return json.dumps({"ip": _plain(host), "port": port}, separators=(",", ":")).encode("ascii")


class RateLimit:
    def __init__(self, per_second: int = RATE_PER_SECOND):
        self.per_second = per_second
        self.window = 0
        self.counts: dict[str, int] = {}

    def allow(self, host: str, now: float | None = None) -> bool:
        second = int(now if now is not None else time.monotonic())
        if second != self.window:
            self.window = second
            self.counts.clear()
        used = self.counts.get(host, 0)
        if used >= self.per_second:
            return False
        self.counts[host] = used + 1
        return True


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, limit: RateLimit):
        self.limit = limit
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        host, port = addr[0], addr[1]
        reply = udp_reply(data, host, port)
        if reply is not None and self.transport is not None and self.limit.allow(host):
            self.transport.sendto(reply, addr)

    def error_received(self, exc):  # ICMP errors from earlier sends; nothing to do
        pass


class Reflector:
    """Owns the sockets. ``start()`` binds every port; a port that cannot be bound is logged
    and skipped, so one busy port does not take the others down."""

    def __init__(self, host: str = "0.0.0.0", udp_ports=UDP_PORTS, tcp_ports=TCP_PORTS,
                 rate_per_second: int = RATE_PER_SECOND):
        self.host = host
        self.udp_ports = tuple(udp_ports)
        self.tcp_ports = tuple(tcp_ports)
        self.limit = RateLimit(rate_per_second)
        self._udp: list[asyncio.DatagramTransport] = []
        self._tcp: list[asyncio.base_events.Server] = []
        self.bound: dict[str, list[int]] = {"udp": [], "tcp": []}

    async def _on_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        try:
            if self.limit.allow(peer[0]):
                writer.write(tcp_reply(peer[0], peer[1]))
                await asyncio.wait_for(writer.drain(), 5)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()

    async def start(self) -> "Reflector":
        loop = asyncio.get_running_loop()
        for port in self.udp_ports:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _Udp(self.limit), local_addr=(self.host, port))
            except OSError as error:
                log.warning("reflector: UDP %s:%s unavailable: %s", self.host, port, error)
                continue
            self._udp.append(transport)
            self.bound["udp"].append(transport.get_extra_info("sockname")[1])
        for port in self.tcp_ports:
            try:
                server = await asyncio.start_server(self._on_tcp, self.host, port)
            except OSError as error:
                log.warning("reflector: TCP %s:%s unavailable: %s", self.host, port, error)
                continue
            self._tcp.append(server)
            self.bound["tcp"].append(server.sockets[0].getsockname()[1])
        return self

    async def stop(self) -> None:
        for transport in self._udp:
            transport.close()
        for server in self._tcp:
            server.close()
            await server.wait_closed()
        self._udp.clear()
        self._tcp.clear()


def _ports(text: str) -> list[int]:
    return [int(part) for part in text.split(",") if part.strip()]


async def _main(args) -> None:
    reflector = await Reflector(args.host, _ports(args.udp), _ports(args.tcp)).start()
    log.info("reflector listening: %s", reflector.bound)
    try:
        await asyncio.Event().wait()
    finally:
        await reflector.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--udp", default=",".join(map(str, UDP_PORTS)))
    parser.add_argument("--tcp", default=",".join(map(str, TCP_PORTS)))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    main()
