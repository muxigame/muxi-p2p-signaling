"""MUXI-REFLECT/1 over real loopback sockets, in the shapes NatDiscovery and TcpPuncher expect."""
import asyncio
import json
import socket
import unittest

from muxi_p2p_signaling import reflector


class ReflectorTests(unittest.TestCase):
    def test_v2_and_observation_parsing(self):
        self.assertEqual(("n1", "port"), reflector.parse_v2(reflector.MAGIC2 + b"n1 port"))
        self.assertEqual(("n1", "same"), reflector.parse_v2(reflector.MAGIC2 + b"n1"))
        self.assertIsNone(reflector.parse_v2(reflector.MAGIC2 + b"n1 bogus"))
        self.assertIsNone(reflector.parse_v2(reflector.MAGIC2 + b"n1 ip extra"))
        session = "0123456789abcdef"
        self.assertEqual((session, "c", 7), reflector.parse_observation(f"o.{session}.c.7"))
        self.assertIsNone(reflector.parse_observation(f"o.{session}.x.7"))
        self.assertIsNone(reflector.parse_observation("o.0123.c.7"))
        self.assertIsNone(reflector.parse_observation(f"r0p1.{session}.c.7"))
        self.assertEqual((session, "a", -1), reflector.parse_obs_query(reflector.OBS_MAGIC + f"{session} a -1".encode()))
        self.assertIsNone(reflector.parse_obs_query(reflector.OBS_MAGIC + f"{session} a".encode()))
        # a v1 nonce never contains a space, so a v2-looking body sent as v1 is refused
        self.assertIsNone(reflector.udp_reply(reflector.MAGIC + b"n1 port", "8.8.8.8", 1))

    def test_observation_store_is_bounded_and_expires(self):
        store = reflector.Observations(ttl=10, max_sessions=2, max_per_side=3)
        store.record("s1", "c", 1, "1.1.1.1", 100, now=0)
        store.record("s1", "c", 1, "1.1.1.1", 101, now=0)  # duplicate seq ignored
        store.record("s1", "c", 2, "1.1.1.1", 102, now=1)
        store.record("s1", "a", 1, "2.2.2.2", 200, now=1)
        self.assertEqual([[1, "1.1.1.1", 100, 2000], [2, "1.1.1.1", 102, 1000]], store.since("s1", "c", -1, now=2))
        self.assertEqual([[2, "1.1.1.1", 102, 1000]], store.since("s1", "c", 1, now=2))
        for seq in range(3, 10):
            store.record("s1", "c", seq, "1.1.1.1", 100 + seq, now=2)
        self.assertEqual(3, len(store.since("s1", "c", -1, now=2)))
        store.record("s2", "c", 1, "1.1.1.1", 1, now=3)
        store.record("s3", "c", 1, "1.1.1.1", 1, now=3)  # evicts the oldest session
        self.assertEqual([], store.since("s1", "c", -1, now=3))
        self.assertEqual([], store.since("s2", "c", -1, now=30))  # expired

    def test_filtering_modes_and_observations_over_loopback(self):
        async def scenario():
            server = await reflector.Reflector("127.0.0.1", [0, 0], []).start()
            try:
                first, second = server.bound["udp"]
                loop = asyncio.get_running_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                sock.setblocking(False)

                async def ask(payload):
                    await loop.sock_sendto(sock, payload, ("127.0.0.1", first))
                    data, source = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), 3)
                    return json.loads(data), source[1]

                same, same_from = await ask(reflector.MAGIC2 + b"f1 same")
                port, port_from = await ask(reflector.MAGIC2 + b"f2 port")
                ip, ip_from = await ask(reflector.MAGIC2 + b"f3 ip")

                session = "00000000000000aa"
                await ask(reflector.MAGIC + f"o.{session}.c.1".encode())
                await ask(reflector.MAGIC + f"o.{session}.c.2".encode())
                obs, _ = await ask(reflector.OBS_MAGIC + f"{session} c 1".encode())
                none, _ = await ask(reflector.OBS_MAGIC + f"{session} a -1".encode())
                mine = sock.getsockname()[1]
                sock.close()
                return first, second, mine, (same, same_from), (port, port_from), (ip, ip_from), obs, none
            finally:
                await server.stop()

        first, second, mine, same, port, ip, obs, none = asyncio.run(scenario())
        self.assertEqual(first, same[1])
        self.assertEqual(f"127.0.0.1:{first}", same[0]["via"])
        self.assertEqual(second, port[1])
        self.assertEqual(f"127.0.0.1:{second}", port[0]["via"])
        self.assertNotIn("unsupported", port[0])
        self.assertEqual(first, ip[1])
        self.assertEqual("ip", ip[0]["unsupported"])
        self.assertEqual(mine, same[0]["port"])
        self.assertEqual([2], [row[0] for row in obs["obs"]])
        self.assertEqual(["127.0.0.1", mine], obs["obs"][0][1:3])
        self.assertEqual([], none["obs"])

    def test_reply_shapes(self):
        self.assertIsNone(reflector.udp_reply(b"hello", "8.8.8.8", 1))
        self.assertIsNone(reflector.udp_reply(reflector.MAGIC, "8.8.8.8", 1))
        self.assertIsNone(reflector.udp_reply(reflector.MAGIC + b"x" * 65, "8.8.8.8", 1))
        reply = json.loads(reflector.udp_reply(reflector.MAGIC + b"r0p1n2a", "::ffff:8.8.8.8", 4000))
        self.assertEqual({"nonce": "r0p1n2a", "ip": "8.8.8.8", "port": 4000}, reply)

    def test_rate_limit_is_per_source(self):
        limit = reflector.RateLimit(2)
        self.assertEqual([True, True, False], [limit.allow("a", 1.0) for _ in range(3)])
        self.assertTrue(limit.allow("b", 1.0))
        self.assertTrue(limit.allow("a", 2.0))

    def test_udp_and_tcp_over_loopback(self):
        async def scenario():
            server = await reflector.Reflector("127.0.0.1", [0], [0]).start()
            try:
                udp_port, tcp_port = server.bound["udp"][0], server.bound["tcp"][0]
                loop = asyncio.get_running_loop()

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                sock.setblocking(False)
                await loop.sock_sendto(sock, reflector.MAGIC + b"n1", ("127.0.0.1", udp_port))
                data = await asyncio.wait_for(loop.sock_recv(sock, 512), 3)
                udp = json.loads(data), sock.getsockname()[1]
                sock.close()

                reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
                tcp = json.loads(await asyncio.wait_for(reader.read(256), 3))
                local = writer.get_extra_info("sockname")[1]
                writer.close()
                return udp, (tcp, local)
            finally:
                await server.stop()

        (udp, udp_local), (tcp, tcp_local) = asyncio.run(scenario())
        self.assertEqual({"nonce": "n1", "ip": "127.0.0.1", "port": udp_local}, udp)
        self.assertEqual({"ip": "127.0.0.1", "port": tcp_local}, tcp)

    @staticmethod
    def _free_udp_port() -> int:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("0.0.0.0", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port

    def test_each_address_replies_from_itself(self):
        # A wildcard socket would answer both from the primary address; a NAT with
        # address-dependent filtering drops the reply that comes from the wrong one.
        port = self._free_udp_port()

        async def scenario():
            server = await reflector.Reflector("0.0.0.0", [port], [], addresses=["127.0.0.1", "127.0.0.2"]).start()
            try:
                loop = asyncio.get_running_loop()
                sources = []
                for address in ("127.0.0.1", "127.0.0.2"):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(("127.0.0.1", 0))
                    sock.setblocking(False)
                    await loop.sock_sendto(sock, reflector.MAGIC + b"n", (address, port))
                    _data, source = await asyncio.wait_for(loop.sock_recvfrom(sock, 512), 3)
                    sources.append(source[0])
                    sock.close()
                return server.bound, sources
            finally:
                await server.stop()

        bound, sources = asyncio.run(scenario())
        self.assertEqual([port], bound["udp"])
        self.assertTrue(bound["udp_per_address"])
        self.assertEqual(["127.0.0.1", "127.0.0.2"], sources)

    def test_non_local_address_falls_back_to_wildcard(self):
        port = self._free_udp_port()

        async def scenario():
            server = await reflector.Reflector("0.0.0.0", [port], [], addresses=["127.0.0.1", "192.0.2.1"]).start()
            try:
                return server.bound
            finally:
                await server.stop()

        bound = asyncio.run(scenario())
        self.assertEqual([port], bound["udp"])
        self.assertFalse(bound["udp_per_address"])


if __name__ == "__main__":
    unittest.main()
