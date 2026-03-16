"""
Props Anonymous Expert Oracle — Session 1 (Day 1)
==================================================
Goal: Prove that our app is running inside a real Intel TDX enclave on Phala Cloud
and can produce a real hardware-signed attestation quote.

WHY THIS MATTERS:
Everything in this project — the doctor credential fetch, the LLM, the redaction filter —
must happen inside a tamper-proof hardware box (TEE) that nobody can cheat.
This file proves that box exists and is real.

The Day 1 test: curl /api/attestation → get a real TDX quote back.
If that works, all subsequent sessions can trust they're building on verified hardware.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="Props Oracle", version="0.1.0")

# Allow the frontend (running in a browser) to call this API.
# Required because the frontend and API are on different domains.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_tappd_client():
    """
    Props L2 — TEE + attestation (Props paper, section 3.1)

    TappdClient is the dstack-sdk class that talks to the TEE hardware
    via a Unix socket mounted at /var/run/dstack.sock (see docker-compose.yaml).

    WHY: Without this client, we cannot get attestation quotes or derive
    enclave-bound signing keys. This is the bridge between our Python app
    and the Intel TDX chip running underneath Phala Cloud.

    Returns None gracefully if run outside a real enclave (e.g. local dev).
    """
    try:
        from dstack_sdk import TappdClient
        # TappdClient auto-connects to /var/run/dstack.sock
        client = TappdClient()
        return client
    except Exception:
        return None


@app.get("/")
async def root():
    """Basic service info. Confirms the app is running."""
    return {
        "service": "Props Anonymous Expert Oracle",
        "version": "0.1.0",
        "status": "running",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health():
    """
    Health check endpoint used by Phala Cloud to confirm the container is alive.
    Must return 200 OK or Phala will restart the container.
    """
    return {"status": "ok"}


# =============================================================================
# Props L2 — TEE + Attestation (section 3.1)
# =============================================================================
# WHY THIS ENDPOINT EXISTS:
# The entire trust model of Props depends on being able to prove that computation
# happened inside a real, unmodified TEE. This endpoint does that.
#
# A TDX attestation quote is a blob of data signed by Intel's hardware.
# It cryptographically proves:
#   1. This code is running inside a real Intel TDX enclave
#   2. The exact version of the code running (via enclave measurement)
#   3. Nobody has tampered with it
#
# In later sessions, the attestation will include the credential certificate,
# the LLM model hash, and the list of disclosed fields — all signed together.
# This endpoint is the foundation for all of that.
# =============================================================================
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
        # We hash a small payload to create the report_data field in the TDX quote.
        # TDX report_data is max 64 bytes — we SHA-256 hash our payload to fit.
        # In session 4, this payload will be the certificate data we want attested.
        payload = json.dumps({
            "service": "props-oracle",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "purpose": "attestation_test",
        }).encode()
        report_data = hashlib.sha256(payload).digest()  # 32 bytes

        # This call asks the Intel TDX hardware to sign our report_data.
        # The returned quote can be verified by anyone using Intel's public keys.
        result = client.tdx_quote(report_data)

        return {
            "attestation": {
                # The actual hardware-signed quote (hex encoded).
                # Contains enclave measurement, report_data, and Intel's signature.
                "quote": result.quote,
                # The event log records every step of the enclave boot process.
                # Verifiers use this to confirm the exact code that was loaded.
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


# =============================================================================
# Props L2 — Enclave-Derived Signing Key (section 3.1)
# =============================================================================
# WHY THIS ENDPOINT EXISTS:
# In session 4, the enclave will sign every credential certificate it produces.
# That signature proves the certificate came from THIS specific enclave build
# and not from a tampered or fake version.
#
# The key is DETERMINISTIC: same enclave code + same path = same key, every time.
# If the code changes (tampered), the key changes, and old signatures become invalid.
# This is what makes certificate verification trustworthy.
# =============================================================================
@app.get("/api/tdx-key")
async def get_tdx_key():
    client = get_tappd_client()

    if client is None:
        return JSONResponse(
            status_code=503,
            content={"error": "dstack-sdk not available"},
        )

    try:
        # derive_key(path, subject) asks the TEE to derive a key bound to this enclave.
        # We never expose the raw key — only its hash, for verification purposes.
        result = client.derive_key("/props-oracle", "signing-key")
        key_bytes = result.toBytes() if hasattr(result, "toBytes") else str(result).encode()
        return {
            "derived_key_hash": hashlib.sha256(key_bytes).hexdigest(),
            "purpose": "enclave-deterministic signing key",
            "note": "Same enclave measurement always produces the same key. "
                    "Deploy different code and this hash changes.",
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
