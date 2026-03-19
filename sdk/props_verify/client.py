"""
Props Verify SDK — HTTP client for Props oracle instances.

All read operations (verification, certificate fetch, oracle listing) are
public and require no API key. This is by design — Props is a protocol,
not a SaaS. Anyone can verify a certificate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from props_verify.crypto import verify_signature, verify_payload_hash


@dataclass
class VerifyResult:
    """Result of verifying a Props certificate."""

    valid: bool
    reason: str
    certificate_id: str
    credential: dict | None
    model_name: str | None = None
    model_digest: str | None = None
    oracle_source: str | None = None
    oracle_type: str | None = None
    timestamp: str | None = None
    enclave: str | None = None
    in_real_enclave: bool = False
    on_chain_verified: bool = False
    on_chain_tx: str | None = None
    tdx_quote_present: bool = False
    raw: dict = field(default_factory=dict)


class PropsClient:
    """
    Client for a Props oracle instance.

    Args:
        base_url: The Props instance URL (e.g. "https://...phala.network:8080")
        timeout: HTTP request timeout in seconds (default 30)
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def verify(self, certificate_id: str) -> VerifyResult:
        """
        Verify a certificate by ID.

        Calls GET /api/verify/{certificate_id} on the Props instance.
        Returns a VerifyResult with credential facts if valid.
        """
        resp = self._client.get(f"{self.base_url}/api/verify/{certificate_id}")
        resp.raise_for_status()
        data = resp.json()

        return VerifyResult(
            valid=data.get("valid", False),
            reason=data.get("reason", ""),
            certificate_id=data.get("certificate_id", certificate_id),
            credential=data.get("credential"),
            model_name=data.get("model_name"),
            model_digest=data.get("model_digest"),
            oracle_source=data.get("oracle_source"),
            oracle_type=data.get("oracle_type"),
            timestamp=data.get("timestamp"),
            enclave=data.get("enclave"),
            in_real_enclave=data.get("in_real_enclave", False),
            on_chain_verified=data.get("on_chain_verified", False),
            on_chain_tx=data.get("on_chain_tx"),
            tdx_quote_present=data.get("tdx_quote_present", False),
            raw=data,
        )

    def get_certificate(self, certificate_id: str) -> dict:
        """
        Fetch the full signed certificate JSON.

        Returns the raw certificate dict containing all fields needed
        for independent offline verification via verify_signature().
        """
        resp = self._client.get(
            f"{self.base_url}/api/certificate/{certificate_id}"
        )
        resp.raise_for_status()
        return resp.json()

    def verify_offline(self, certificate_id: str) -> tuple[bool, str]:
        """
        Fetch a certificate and verify its Ed25519 signature locally.

        This requires no trust in the Props server — the signature is
        verified using the public key embedded in the certificate.
        """
        cert = self.get_certificate(certificate_id)
        return verify_signature(cert)

    def list_oracles(self) -> dict:
        """
        List available oracle types with metadata.

        Returns a dict of oracle_type → oracle_info.
        """
        resp = self._client.get(f"{self.base_url}/api/oracles")
        resp.raise_for_status()
        data = resp.json()
        return data.get("live_oracles", {})

    def info(self) -> dict:
        """Get service status and configuration."""
        resp = self._client.get(f"{self.base_url}/api/info")
        resp.raise_for_status()
        return resp.json()

    def developer_docs(self) -> dict:
        """Get developer API documentation."""
        resp = self._client.get(f"{self.base_url}/api/developer")
        resp.raise_for_status()
        return resp.json()

    def close(self):
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
