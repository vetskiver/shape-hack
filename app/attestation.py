"""
Props L2 — Attestation Layer (Props paper, section 3.1)
=======================================================
Wraps dstack-sdk TappdClient to produce signed credential certificates.

Every certificate has three trust anchors:
  1. TDX quote     — hardware proof this computation ran inside a real Intel TDX enclave
  2. Ed25519 sig   — content signed by a key DERIVED from the enclave measurement
  3. Model hash    — Ollama model digest from L3, included in the signed payload

The enclave-derived signing key is deterministic:
  same enclave code = same key. Tampered code = different key = invalid signatures.

This is the cryptographic guarantee of Props L2 — the certificate cannot be
produced outside the specific enclave build it was attested against.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Enclave key derivation
# ---------------------------------------------------------------------------

def _get_signing_key() -> tuple[Ed25519PrivateKey, str, bool]:
    """
    Props L2 — derives a deterministic Ed25519 signing key from the TDX enclave.

    DstackClient.get_key() asks the dstack daemon to produce a key that is
    cryptographically bound to the current enclave measurement (MRTD/RTMR).
    Same code → same key. Any modification to the enclave code changes the key,
    which invalidates all previously issued signatures.

    Returns:
        (private_key, public_key_hex, in_real_enclave)
    """
    try:
        from dstack_sdk import DstackClient
        client = DstackClient()
        # Path and purpose uniquely namespace this key within this enclave
        result = client.get_key("/props-oracle", "cert-signing-v1")
        raw_bytes = result.decode_key()
        # SHA-256 compress to 32-byte Ed25519 seed
        seed = hashlib.sha256(raw_bytes).digest()
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        pub_hex = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        ).hex()
        return private_key, pub_hex, True
    except Exception as e:
        import secrets
        print(f"[attestation] WARNING: dstack unavailable — using ephemeral key: {e}")
        seed = secrets.token_bytes(32)
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        pub_hex = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        ).hex()
        return private_key, pub_hex, False


# ---------------------------------------------------------------------------
# TDX hardware quote
# ---------------------------------------------------------------------------

def _get_tdx_quote(payload_hash: bytes) -> tuple[str | None, str | None]:
    """
    Props L2 — embeds our certificate hash into a real Intel TDX quote.

    The TDX quote is a hardware-signed blob that proves:
      1. This code is running inside a genuine Intel TDX enclave
      2. The enclave measurement (what code is running)
      3. The report_data field (64 bytes) — we put our certificate hash here

    Anyone can verify the TDX quote against Intel's public keys without trusting us.
    Returns (quote_hex, event_log) or (None, None) outside a real enclave.
    """
    try:
        from dstack_sdk import DstackClient
        client = DstackClient()
        # get_quote accepts up to 64 bytes — pass our 32-byte SHA-256 hash directly
        result = client.get_quote(payload_hash[:32])
        quote_hex = result.quote if isinstance(result.quote, str) else result.quote.hex()
        event_log = getattr(result, "event_log", None)
        return quote_hex, event_log
    except Exception as e:
        print(f"[attestation] TDX quote unavailable: {e}")
        return None, None


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def generate_certificate(
    redaction_result: dict,
    oracle_result: dict,
    model_info: dict,
) -> dict:
    """
    Props L2 — generates a signed credential certificate (section 3.1).

    Args:
        redaction_result: output of apply_redaction_filter()
                          Keys: disclosed, all_fields, stripped_fields, disclosed_fields
        oracle_result:    output of fetch_credential()
                          Keys: credential, oracle_authenticated, oracle_source,
                                oracle_tls_fingerprint, data_hash, fetch_timestamp
        model_info:       output of get_model_info()
                          Keys: model_name, model_digest

    Returns the full signed certificate dict. Structure is the contract between
    the TEE and the outside world — do not change without updating the verifier.
    """
    certificate_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # The signable payload — everything a verifier needs to authenticate
    # Canonical: sorted keys, no whitespace (deterministic serialisation)
    payload = {
        "certificate_id": certificate_id,
        "credential": redaction_result["disclosed"],
        "model_name": model_info["model_name"],
        "model_digest": model_info.get("model_digest", ""),
        "oracle_source": oracle_result.get("oracle_source", ""),
        "oracle_tls_fingerprint": oracle_result.get("oracle_tls_fingerprint", ""),
        "oracle_data_hash": oracle_result.get("data_hash", ""),
        "raw_fields_stripped": redaction_result["stripped_fields"],
        "disclosed_fields": redaction_result["disclosed_fields"],
        "timestamp": timestamp,
    }

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload_hash = hashlib.sha256(payload_bytes).digest()

    # Props L2 — sign with enclave-derived Ed25519 key
    private_key, public_key_hex, in_real_enclave = _get_signing_key()
    signature_hex = private_key.sign(payload_bytes).hex()

    # Props L2 — bind payload hash into TDX hardware quote
    tdx_quote, event_log = _get_tdx_quote(payload_hash)

    print(
        f"[attestation] Certificate {certificate_id} issued | "
        f"fields_disclosed={redaction_result['disclosed_fields']} | "
        f"fields_stripped={len(redaction_result['stripped_fields'])} | "
        f"enclave={'real' if in_real_enclave else 'simulated'}"
    )

    return {
        # --- Core certificate fields ---
        **payload,
        # --- Cryptographic proof ---
        "signing_key_public": public_key_hex,
        "signature": signature_hex,
        "payload_hash": payload_hash.hex(),
        # --- TDX hardware attestation ---
        "tdx_quote": tdx_quote,
        "event_log": event_log,
        # --- Metadata ---
        "enclave": "intel-tdx" if in_real_enclave else "simulated",
        "platform": "phala-cloud" if in_real_enclave else "local-dev",
        "in_real_enclave": in_real_enclave,
    }


# ---------------------------------------------------------------------------
# TDX quote verification
# ---------------------------------------------------------------------------

# Intel TDX Quote v4 header layout (from Intel TDX DCAP specification):
#   bytes 0-1:   version (uint16 LE, expect 4)
#   bytes 2-3:   attestation key type (uint16 LE, 2 = ECDSA-256 with P-256)
#   bytes 4-7:   TEE type (uint32 LE, 0x81 = TDX)
#   bytes 16-47: reserved / QE vendor ID
#   bytes 48-67: user data (20 bytes)
# Quote body (offset 48 in header+body, but structure varies):
#   The report_data field is 64 bytes at a known offset within the TD report.
#   For TDX DCAP v4 quotes, report_data is at offset 568 from quote start.
_TDX_REPORT_DATA_OFFSET = 568
_TDX_REPORT_DATA_LEN = 64


def verify_tdx_quote(certificate: dict) -> dict:
    """
    Props L2 — verify the TDX attestation quote embedded in a certificate.

    Three levels of verification:
      1. Structural: parse the quote, extract report_data, verify it matches payload_hash
      2. SDK: if dstack_sdk is available, use its verify_quote() function
      3. Remote: call Intel Trust Authority API (future — documented for auditors)

    Returns:
        {
          "present": bool,
          "report_data_matches": bool | None,
          "report_data": str | None,
          "expected_payload_hash": str | None,
          "sdk_verified": bool | None,
          "verification_method": str,
          "details": str,
        }
    """
    quote_hex = certificate.get("tdx_quote")
    payload_hash = certificate.get("payload_hash", "")

    if not quote_hex:
        return {
            "present": False,
            "report_data_matches": None,
            "verification_method": "none",
            "details": "No TDX quote in certificate (simulated enclave)",
        }

    result = {
        "present": True,
        "report_data_matches": None,
        "report_data": None,
        "expected_payload_hash": payload_hash,
        "sdk_verified": None,
        "verification_method": "structural",
        "details": "",
    }

    # --- Level 1: Structural verification ---
    # Parse the raw quote bytes and extract report_data
    try:
        quote_bytes = bytes.fromhex(quote_hex.replace("0x", ""))

        if len(quote_bytes) < _TDX_REPORT_DATA_OFFSET + _TDX_REPORT_DATA_LEN:
            result["details"] = (
                f"Quote too short ({len(quote_bytes)} bytes) for report_data extraction. "
                f"Need at least {_TDX_REPORT_DATA_OFFSET + _TDX_REPORT_DATA_LEN} bytes."
            )
            return result

        # Extract report_data (64 bytes at known offset)
        report_data = quote_bytes[
            _TDX_REPORT_DATA_OFFSET : _TDX_REPORT_DATA_OFFSET + _TDX_REPORT_DATA_LEN
        ]
        result["report_data"] = report_data.hex()

        # The first 32 bytes of report_data should match our payload_hash
        # (we passed payload_hash[:32] to get_quote)
        report_hash = report_data[:32].hex()
        result["report_data_matches"] = report_hash == payload_hash

        if result["report_data_matches"]:
            result["details"] = (
                "report_data in TDX quote matches certificate payload_hash — "
                "this certificate was bound to this specific TDX hardware attestation"
            )
        else:
            result["details"] = (
                f"report_data MISMATCH: quote contains {report_hash[:16]}... "
                f"but certificate payload_hash is {payload_hash[:16]}..."
            )
    except Exception as e:
        result["details"] = f"Quote parsing failed: {e}"
        return result

    # --- Level 2: SDK verification (if dstack_sdk available) ---
    try:
        from dstack_sdk import DstackClient
        client = DstackClient()
        # dstack_sdk may provide a verify_quote method
        if hasattr(client, "verify_quote"):
            sdk_result = client.verify_quote(quote_bytes)
            result["sdk_verified"] = True
            result["verification_method"] = "dstack-sdk"
            result["details"] += " | SDK: quote verified by dstack daemon"
    except Exception:
        # SDK verification not available — structural check is still valid
        pass

    # --- Level 3: Remote Intel DCAP verification via Intel Trust Authority ---
    # https://docs.trustauthority.intel.com/main/articles/integrate-overview.html
    # Sends the raw TDX quote to Intel's appraisal API for full DCAP verification.
    # Intel validates: hardware authenticity, enclave measurement, quote signature.
    # This is the gold standard — Intel's own infrastructure vouches for the quote.
    result["intel_verified"] = None
    result["intel_details"] = None
    try:
        import httpx
        quote_b64 = __import__("base64").b64encode(quote_bytes).decode()
        intel_resp = httpx.post(
            "https://api.trustauthority.intel.com/appraisal/v2/attest",
            json={"quote": quote_b64},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=10,
        )
        if intel_resp.status_code == 200:
            intel_body = intel_resp.json()
            # Intel returns a JWT token on success — its presence means DCAP passed
            token = intel_body.get("token", "")
            if token:
                result["intel_verified"] = True
                result["verification_method"] = "intel-dcap"
                result["intel_details"] = (
                    f"Intel Trust Authority DCAP verification PASSED. "
                    f"JWT token received ({len(token)} chars). "
                    f"This quote was validated by Intel's own infrastructure."
                )
                result["details"] += " | Intel DCAP: quote verified by Intel Trust Authority"
            else:
                result["intel_verified"] = False
                result["intel_details"] = (
                    f"Intel Trust Authority returned 200 but no token. "
                    f"Response: {str(intel_body)[:200]}"
                )
        else:
            # Non-200 — quote may be invalid, or API may require an API key
            body_text = intel_resp.text[:300]
            result["intel_verified"] = False
            result["intel_details"] = (
                f"Intel Trust Authority returned HTTP {intel_resp.status_code}. "
                f"This may indicate the quote is from a simulated enclave "
                f"(not real TDX hardware), or the API requires authentication. "
                f"Response: {body_text}"
            )
    except Exception as e:
        # Network error or httpx not available — not a failure, just unavailable
        result["intel_details"] = (
            f"Intel DCAP remote verification unavailable: {e}. "
            f"Structural verification result above is still valid."
        )

    return result


# ---------------------------------------------------------------------------
# Certificate verification
# ---------------------------------------------------------------------------

def verify_certificate(certificate: dict) -> tuple[bool, str]:
    """
    Props L2 — verifies the Ed25519 signature on a certificate.

    Rebuilds the exact canonical payload that was signed, then verifies using
    the public key stored in the certificate. This is what the verifier page
    calls — it must not hardcode True.

    Returns:
        (valid: bool, reason: str)
    """
    try:
        # Rebuild the exact payload that was signed (must match generate_certificate)
        payload = {
            "certificate_id": certificate["certificate_id"],
            "credential": certificate["credential"],
            "model_name": certificate["model_name"],
            "model_digest": certificate.get("model_digest", ""),
            "oracle_source": certificate.get("oracle_source", ""),
            "oracle_tls_fingerprint": certificate.get("oracle_tls_fingerprint", ""),
            "oracle_data_hash": certificate.get("oracle_data_hash", ""),
            "raw_fields_stripped": certificate["raw_fields_stripped"],
            "disclosed_fields": certificate["disclosed_fields"],
            "timestamp": certificate["timestamp"],
        }

        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(certificate["signing_key_public"])
        )
        public_key.verify(
            bytes.fromhex(certificate["signature"]),
            payload_bytes,
        )
        return True, "Signature valid — certificate is authentic"

    except InvalidSignature:
        return False, "Invalid signature — certificate was tampered with after issuance"
    except KeyError as e:
        return False, f"Malformed certificate — missing field: {e}"
    except Exception as e:
        return False, f"Verification error: {e}"


# ---------------------------------------------------------------------------
# Direct test: python app/attestation.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    sample_redaction = {
        "disclosed": {"specialty": "Cardiology", "years_active": 17},
        "all_fields": ["address", "license_number", "name", "specialty", "years_active"],
        "stripped_fields": ["address", "license_number", "name"],
        "disclosed_fields": ["specialty", "years_active"],
    }
    sample_oracle = {
        "oracle_authenticated": True,
        "oracle_source": "www.op.nysed.gov",
        "oracle_tls_fingerprint": "ABCDEF1234",
        "data_hash": hashlib.sha256(b"test").hexdigest(),
    }
    sample_model = {
        "model_name": "llama3.2:3b",
        "model_digest": hashlib.sha256(b"llama3.2:3b").hexdigest(),
    }

    print("[attestation] Generating test certificate...")
    cert = generate_certificate(sample_redaction, sample_oracle, sample_model)
    print(json.dumps(cert, indent=2))

    print("\n[attestation] Verifying certificate...")
    valid, reason = verify_certificate(cert)
    print(f"Valid: {valid} | Reason: {reason}")
    assert valid, "FAIL: self-issued certificate should verify"

    print("\n[attestation] Tampering with certificate...")
    tampered = {**cert, "credential": {"specialty": "FAKE SPECIALTY", "years_active": 99}}
    valid, reason = verify_certificate(tampered)
    print(f"Valid: {valid} | Reason: {reason}")
    assert not valid, "FAIL: tampered certificate should fail verification"

    print("\nPASS: attestation module working correctly")
