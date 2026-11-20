"""configure(): per-agent secrets, an access guard and switching off diagnostics."""
import asyncio
import hashlib
import hmac
import json
import time
import unittest

import httpx
from fastapi import FastAPI, HTTPException, Request

from muxi_p2p_signaling import tunnel_registry as registry

TOKENS = {"dev-a": "token-for-a", "dev-b": "token-for-b"}


def signed(token: str, body: bytes = b"") -> dict:
    secret = registry.derive_secret(token)
    stamp = repr(time.time())
    signature = hmac.new(secret, stamp.encode("ascii") + body, hashlib.sha256).hexdigest()
    return {"X-Muxi-Signature": signature, "X-Muxi-Timestamp": stamp}


async def guard(request: Request, server_id: str) -> None:
    if request.headers.get("x-user") != "alice":
        raise HTTPException(status_code=401, detail="sign in")


class EmbeddingTests(unittest.TestCase):
    def setUp(self):
        for table in (registry._registrations, registry._punches, registry._punch_quota,
                      registry._punch_events, registry._agents_parked, registry._agent_last_poll):
            table.clear()
        registry.configure(secret_provider=TOKENS.get, access_guard=guard, diagnostics=False)
        self.addCleanup(registry.configure)
        self.app = FastAPI()
        self.app.include_router(registry.router)

    def call(self, method, url, **kwargs):
        async def run():
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, url, **kwargs)
        return asyncio.run(run())

    def register(self, server_id, token):
        body = json.dumps({"serverId": server_id, "tunnelPort": 25540, "mcPort": 5900,
                           "endpoints": [], "udpCandidates": ["8.8.8.8:1234"]}).encode()
        return self.call("POST", "/api/v1/tunnel/register", content=body,
                         headers={**signed(token, body), "X-Forwarded-For": "8.8.8.8"})

    def test_each_agent_signs_with_its_own_token(self):
        self.assertEqual(200, self.register("dev-a", "token-for-a").status_code)
        self.assertEqual(401, self.register("dev-a", "token-for-b").status_code)
        self.assertEqual(401, self.register("unknown", "token-for-a").status_code)

    def test_pending_is_verified_per_agent(self):
        ok = self.call("GET", "/api/v1/tunnel/punch/pending?server_id=dev-b",
                       headers=signed("token-for-b"))
        self.assertEqual(200, ok.status_code, ok.text)
        wrong = self.call("GET", "/api/v1/tunnel/punch/pending?server_id=dev-b",
                          headers=signed("token-for-a"))
        self.assertEqual(401, wrong.status_code)

    def test_client_side_needs_the_guard(self):
        for method, url in (("GET", "/api/v1/tunnel/endpoints?server_id=dev-a"),
                            ("GET", "/api/v1/tunnel/client-token?server_id=dev-a")):
            self.assertEqual(401, self.call(method, url).status_code, url)
            self.assertEqual(200, self.call(method, url, headers={"x-user": "alice"}).status_code)
        punch = self.call("POST", "/api/v1/tunnel/punch?server_id=dev-a",
                          json={"sessionId": "00000000000000aa", "candidates": ["8.8.4.4:4000"]})
        self.assertEqual(401, punch.status_code)

    def test_client_token_is_per_agent(self):
        headers = {"x-user": "alice"}
        a = self.call("GET", "/api/v1/tunnel/client-token?server_id=dev-a", headers=headers).json()
        b = self.call("GET", "/api/v1/tunnel/client-token?server_id=dev-b", headers=headers).json()
        self.assertNotEqual(a["token"], b["token"])

    def test_diagnostics_can_be_switched_off(self):
        self.assertEqual(404, self.call("POST", "/api/v1/tunnel/diag", content=b"x").status_code)
        self.assertEqual(404, self.call("GET", "/api/v1/tunnel/diag").status_code)


if __name__ == "__main__":
    unittest.main()
