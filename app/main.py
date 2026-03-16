"""
Props Anonymous Expert Oracle — Day 1 FastAPI app.
Minimal endpoint to confirm dstack TDX attestation works on Phala Cloud.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="Props Oracle", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_tappd_client():
    """
    Props L2 — TEE + attestation (section 3.1)
    Returns a TappdClient connected via the mounted Unix socket.
    Falls back to None outside TEE for graceful degradation.
    """
    try:
        from dstack_sdk import TappdClient
        client = TappdClient()
        return client
    except Exception:
        return None


@app.get("/")
async def root():
    return {
        "service": "Props Anonymous Expert Oracle",
        "version": "0.1.0",
        "status": "running",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health():
    """Health check for Phala Cloud."""
    return {"status": "ok"}


# Props L2 — TEE + attestation (section 3.1)
# Returns a real TDX attestation quote from dstack-sdk.
# This is the Day 1 success criterion: a real quote from a real enclave.
@app.get("/api/attestation")
async def get_attestation():
    client = get_tappd_client()

    if client is None:
        return JSONResponse(
            status_code=503,
            content={
                "error": "dstack-sdk not available",
                "hint": "This endpoint only works inside a Phala Cloud TDX enclave "
                        "with /var/run/dstack.sock mounted.",
            },
        )

    try:
        # Build a payload and hash it — TDX report_data is 64 bytes max
        payload = json.dumps({
            "service": "props-oracle",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "purpose": "attestation_test",
        }).encode()
        report_data = hashlib.sha256(payload).digest()  # 32 bytes

        # Props L2: get a real TDX quote from the enclave hardware via dstack
        result = client.tdx_quote(report_data)

        return {
            "attestation": {
                "quote": result.quote,
                "event_log": result.event_log if hasattr(result, "event_log") else None,
                "payload_hash": report_data.hex(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "enclave": "intel-tdx",
                "platform": "phala-cloud",
            },
            "status": "real_tdx_quote",
        }

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Attestation failed: {str(e)}",
                "hint": "Ensure /var/run/dstack.sock is mounted and dstack daemon is running.",
            },
        )


# Props L2 — TDX key derivation (section 3.1)
# Derives a deterministic key from the enclave measurement.
# Same enclave code + same path = same key every time. Different enclave = different key.
@app.get("/api/tdx-key")
async def get_tdx_key():
    client = get_tappd_client()

    if client is None:
        return JSONResponse(
            status_code=503,
            content={"error": "dstack-sdk not available"},
        )

    try:
        # derive_key(path, subject) → deterministic key bound to this enclave
        result = client.derive_key("/props-oracle", "signing-key")
        key_bytes = result.toBytes() if hasattr(result, "toBytes") else str(result).encode()
        return {
            "derived_key_hash": hashlib.sha256(key_bytes).hexdigest(),
            "purpose": "enclave-deterministic signing key",
            "note": "Same enclave measurement always produces the same key",
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Key derivation failed: {str(e)}"},
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
