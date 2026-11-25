"""MUXI-REFLECT/1: tell a peer what address its packets arrive from.

NatDiscovery (UDP) and TcpPuncher.DiscoverAsync (TCP) ask several reflector ports, ideally on
more than one public IP, and compare the answers to learn how their NAT maps ports.

UDP: request ``MUXI-REFLECT/1 <nonce>``, reply ``{"nonce": ..., "ip": ..., "port": ...}``.
TCP: on accept the server writes ``{"ip": ..., "port": ...}`` and closes.

Replies are about the size of a request, and each source address gets a small budget per
second, so the reflector is not useful for amplification.

A UDP socket bound to 0.0.0.0 answers from whatever source address the kernel picks (the
primary one), not from the address the request was sent to. A NAT with address-dependent
filtering (most mobile and carrier NATs) drops such a reply, so the client hears only one of
two reflector addresses and cannot tell its NAT is address-dependent. With ``addresses`` set,
each one gets its own UDP socket and replies leave from the address that was asked.

MUXI-REFLECT/2 (filtering test): request ``MUXI-REFLECT/2 <nonce> <same|port|ip>``. The reply has
the v1 fields plus ``via`` (the reflector address it leaves from) and is sent from the asked
socket (``same``), from another port on the same address (``port``) or from another address on
the same port (``ip``). A client that sent only to the asked address learns its NAT's filtering:
an ``ip`` reply getting through means endpoint-independent filtering, ``port`` means
address-dependent, only ``same`` means address-and-port-dependent. When the change is not
possible here the reply comes from the asked socket with ``"unsupported": <mode>``.

Observations (live port tracking for symmetric-to-symmetric punching): a v1 request whose nonce
is ``o.<session 16 hex>.<side c|a>.<seq>`` is answered as usual and also remembered for a short
while. ``MUXI-OBS/1 <session> <side> <after>`` returns ``{"obs": [[seq, ip, port, age_ms], ...]}``
for that side with seq > after, so each side can follow the other's NAT port counters while
they punch. Entries live ``OBS_TTL`` seconds and the store is bounded.

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
from collections import OrderedDict

MAGIC = b"MUXI-REFLECT/1 "
MAGIC2 = b"MUXI-REFLECT/2 "
OBS_MAGIC = b"MUXI-OBS/1 "
MODES = ("same", "port", "ip")
OBS_TTL = 120.0
OBS_MAX_SESSIONS = 4096
OBS_MAX_PER_SIDE = 256
OBS_REPLY_MAX = 48
UDP_PORTS = (45701, 45702, 45703)
TCP_PORTS = (45711, 45712)
MAX_NONCE = 64
#: replies per source IP per second, over all ports
RATE_PER_SECOND = 120

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


def _nonce(raw: bytes) -> str | None:
    if not raw or len(raw) > MAX_NONCE:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() and " " not in text else None


def udp_reply(data: bytes, host: str, port: int) -> bytes | None:
    if not data.startswith(MAGIC):
        return None
    text = _nonce(data[len(MAGIC):].strip())
    if text is None:
        return None
    return json.dumps({"nonce": text, "ip": _plain(host), "port": port},
                      separators=(",", ":")).encode("ascii")


def parse_v2(data: bytes) -> tuple[str, str] | None:
    """``MUXI-REFLECT/2 <nonce> <mode>`` -> (nonce, mode)."""
    if not data.startswith(MAGIC2):
        return None
    parts = data[len(MAGIC2):].split()
    if not parts or len(parts) > 2:
        return None
    nonce = _nonce(parts[0])
    mode = parts[1].decode("ascii", "replace") if len(parts) == 2 else "same"
    if nonce is None or mode not in MODES:
        return None
    return nonce, mode


def _session_id(text: str) -> bool:
    return len(text) == 16 and all(c in "0123456789abcdef" for c in text)


def parse_observation(nonce: str) -> tuple[str, str, int] | None:
    """``o.<session>.<side>.<seq>`` -> (session, side, seq)."""
    parts = nonce.split(".")
    if len(parts) != 4 or parts[0] != "o":
        return None
    session, side, seq = parts[1].lower(), parts[2], parts[3]
    if not _session_id(session) or side not in ("c", "a") or not seq.isdigit() or len(seq) > 6:
        return None
    return session, side, int(seq)


def parse_obs_query(data: bytes) -> tuple[str, str, int] | None:
    """``MUXI-OBS/1 <session> <side> <after>`` -> (session, side, after)."""
    if not data.startswith(OBS_MAGIC):
        return None
    try:
        parts = data[len(OBS_MAGIC):].decode("ascii").split()
    except UnicodeDecodeError:
        return None
    if len(parts) != 3:
        return None
    session, side, after = parts[0].lower(), parts[1], parts[2]
    if not _session_id(session) or side not in ("c", "a"):
        return None
    try:
        number = int(after)
    except ValueError:
        return None
    return session, side, max(-1, min(number, 999999))


class Observations:
    """Ports the reflector saw for each (session, side), newest last; bounded and short-lived."""

    def __init__(self, ttl: float = OBS_TTL, max_sessions: int = OBS_MAX_SESSIONS,
                 max_per_side: int = OBS_MAX_PER_SIDE):
        self.ttl = ttl
        self.max_sessions = max_sessions
        self.max_per_side = max_per_side
        #: session -> (created, {side: [(seq, ip, port, at)]})
        self._sessions: OrderedDict[str, tuple[float, dict[str, list[tuple[int, str, int, float]]]]] = OrderedDict()

    def _purge(self, now: float) -> None:
        while self._sessions:
            session, (created, _) = next(iter(self._sessions.items()))
            if now - created <= self.ttl and len(self._sessions) <= self.max_sessions:
                break
            del self._sessions[session]

    def record(self, session: str, side: str, seq: int, ip: str, port: int, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._purge(now)
        entry = self._sessions.get(session)
        if entry is None:
            entry = (now, {})
            self._sessions[session] = entry
            self._purge(now)
        sides = entry[1]
        seen = sides.setdefault(side, [])
        if len(seen) >= self.max_per_side or any(item[0] == seq for item in seen):
            return
        seen.append((seq, ip, port, now))

    def since(self, session: str, side: str, after: int, now: float | None = None) -> list[list]:
        now = time.monotonic() if now is None else now
        self._purge(now)
        entry = self._sessions.get(session)
        if entry is None:
            return []
        items = [item for item in entry[1].get(side, []) if item[0] > after]
        items.sort(key=lambda item: item[0])
        return [[seq, ip, port, int((now - at) * 1000)] for seq, ip, port, at in items[:OBS_REPLY_MAX]]


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
    def __init__(self, owner: "Reflector"):
        self.owner = owner
        self.limit = owner.limit
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        host, port = addr[0], addr[1]
        if self.transport is None:
            return
        if data.startswith(MAGIC2):
            parsed = parse_v2(data)
            if parsed is None or not self.limit.allow(host):
                return
            nonce, mode = parsed
            via, unsupported = self.owner.sibling(self.transport, mode)
            local = via.get_extra_info("sockname") or ("?", 0)
            body = {"nonce": nonce, "ip": _plain(host), "port": port,
                    "via": f"{_plain(local[0])}:{local[1]}"}
            if unsupported:
                body["unsupported"] = mode
            via.sendto(json.dumps(body, separators=(",", ":")).encode("ascii"), addr)
            return
        if data.startswith(OBS_MAGIC):
            query = parse_obs_query(data)
            if query is None or not self.limit.allow(host):
                return
            session, side, after = query
            body = {"session": session, "side": side,
                    "obs": self.owner.observations.since(session, side, after)}
            self.transport.sendto(json.dumps(body, separators=(",", ":")).encode("ascii"), addr)
            return
        reply = udp_reply(data, host, port)
        if reply is None or not self.limit.allow(host):
            return
        observation = parse_observation(data[len(MAGIC):].strip().decode("ascii", "replace"))
        if observation is not None:
            session, side, seq = observation
            self.owner.observations.record(session, side, seq, _plain(host), port)
        self.transport.sendto(reply, addr)

    def error_received(self, exc):  # ICMP errors from earlier sends; nothing to do
        pass


class Reflector:
    """Owns the sockets. ``start()`` binds every port; a port that cannot be bound is logged
    and skipped, so one busy port does not take the others down."""

    def __init__(self, host: str = "0.0.0.0", udp_ports=UDP_PORTS, tcp_ports=TCP_PORTS,
                 rate_per_second: int = RATE_PER_SECOND, addresses=()):
        self.host = host
        #: public addresses to bind one UDP socket each (see the module docstring); used only
        #: when every one of them is local, otherwise UDP falls back to ``host``.
        self.addresses = tuple(str(a) for a in addresses if _is_ipv4(str(a)))
        self.udp_ports = tuple(udp_ports)
        self.tcp_ports = tuple(tcp_ports)
        self.limit = RateLimit(rate_per_second)
        self.observations = Observations()
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

    async def _bind_udp(self, host: str, port: int) -> asyncio.DatagramTransport:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _Udp(self), local_addr=(host, port))
        return transport

    def sibling(self, asked: asyncio.DatagramTransport, mode: str) -> tuple[asyncio.DatagramTransport, bool]:
        """The socket a v2 reply leaves from, and whether the asked change was impossible."""
        if mode == "same":
            return asked, False
        here = asked.get_extra_info("sockname") or ("", 0)
        for other in self._udp:
            there = other.get_extra_info("sockname") or ("", 0)
            if mode == "port" and there[0] == here[0] and there[1] != here[1]:
                return other, False
            if (mode == "ip" and there[1] == here[1] and there[0] != here[0]
                    and there[0] not in ("0.0.0.0", "::")):
                return other, False
        return asked, True

    async def _bind_per_address(self, port: int) -> list[asyncio.DatagramTransport] | None:
        """One socket per address, or None (nothing left bound) when any address is not local."""
        bound: list[asyncio.DatagramTransport] = []
        for address in self.addresses:
            try:
                bound.append(await self._bind_udp(address, port))
            except OSError:
                for transport in bound:
                    transport.close()
                return None
        return bound

    async def start(self) -> "Reflector":
        wildcard = self.host in ("0.0.0.0", "", "::")
        for port in self.udp_ports:
            per_address = await self._bind_per_address(port) if wildcard and len(self.addresses) > 1 else None
            if per_address:
                self._udp.extend(per_address)
                self.bound["udp"].append(port)
                continue
            try:
                transport = await self._bind_udp(self.host, port)
            except OSError as error:
                log.warning("reflector: UDP %s:%s unavailable: %s", self.host, port, error)
                continue
            self._udp.append(transport)
            self.bound["udp"].append(transport.get_extra_info("sockname")[1])
        if self.addresses and wildcard:
            self.bound["udp_per_address"] = len(self._udp) > len(self.bound["udp"])
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


def _is_ipv4(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False


def _ports(text: str) -> list[int]:
    return [int(part) for part in text.split(",") if part.strip()]


async def _main(args) -> None:
    addresses = [a for a in args.addresses.split(",") if a.strip()]
    reflector = await Reflector(args.host, _ports(args.udp), _ports(args.tcp), addresses=addresses).start()
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
    parser.add_argument("--addresses", default="",
                        help="comma-separated public IPv4 addresses to answer UDP from individually")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    main()
