"""Standalone signaling service; run with one worker (in-memory registry)."""
from fastapi import FastAPI
from .tunnel_registry import router

app = FastAPI(title="Muxi P2P Signaling", docs_url=None, redoc_url=None)
app.include_router(router)

@app.get("/healthz")
def health():
    return {"status": "ok"}
