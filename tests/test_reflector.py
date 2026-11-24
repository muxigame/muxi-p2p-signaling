"""MUXI-REFLECT/1 over real loopback sockets, in the shapes NatDiscovery and TcpPuncher expect."""
import asyncio
import json
import socket
import unittest

from muxi_p2p_signaling import reflector


class ReflectorTests(unittest.TestCase):
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
