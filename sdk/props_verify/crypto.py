"""
Props Verify SDK — cryptographic verification primitives.

Provides standalone Ed25519 signature verification and payload hash
checking for Props certificates. No server trust required.
"""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


# The canonical payload fields, in the order used by generate_certificate().
# json.dumps(sort_keys=True, separators=(",",":")) ensures determinism.
_PAYLOAD_FIELDS = (
    "certificate_id",
    "credential",
    "model_name",
    "model_digest",
    "oracle_source",
    "oracle_tls_fingerprint",
    "oracle_data_hash",
    "raw_fields_stripped",
    "disclosed_fields",
    "timestamp",
)


def _rebuild_payload(certificate: dict) -> bytes:
    """Rebuild the canonical payload bytes that were signed."""
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
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verify_signature(certificate: dict) -> tuple[bool, str]:
    """
    Verify the Ed25519 signature on a Props certificate.

    Rebuilds the canonical payload and checks it against the signature
    using the public key embedded in the certificate.  This requires
    no trust in the Props server — verification is purely local.

    Args:
        certificate: The full certificate dict (as returned by the
                     ``/api/certificate/:id`` endpoint).

    Returns:
        ``(valid, reason)`` — a boolean and a human-readable explanation.
    """
    try:
        payload_bytes = _rebuild_payload(certificate)

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


def verify_payload_hash(certificate: dict) -> tuple[bool, str]:
    """
    Verify the SHA-256 payload hash stored in a Props certificate.

    The ``payload_hash`` field is the SHA-256 digest of the canonical
    signed payload.  This function recomputes it and compares.

    Args:
        certificate: The full certificate dict.

    Returns:
        ``(valid, reason)`` — a boolean and a human-readable explanation.
    """
    try:
        payload_bytes = _rebuild_payload(certificate)
        expected = hashlib.sha256(payload_bytes).hexdigest()
        actual = certificate.get("payload_hash", "")

        if not actual:
            return False, "Certificate has no payload_hash field"
        if actual == expected:
            return True, "Payload hash matches"
        return False, f"Payload hash mismatch: expected {expected[:16]}…, got {actual[:16]}…"

    except KeyError as e:
        return False, f"Malformed certificate — missing field: {e}"
    except Exception as e:
        return False, f"Hash verification error: {e}"
