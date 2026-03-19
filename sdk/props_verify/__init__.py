"""
Props Verify SDK — verify Props certificates from any Python application.

Usage:
    from props_verify import PropsClient

    client = PropsClient("https://your-props-instance.phala.network")

    # Verify a certificate
    result = client.verify("certificate-id-here")
    if result.valid:
        print(f"Credential: {result.credential}")
        print(f"On-chain: {result.on_chain_verified}")

    # List available oracles
    oracles = client.list_oracles()
    for name, oracle in oracles.items():
        print(f"{name}: {oracle['description']}")

    # Verify locally (no server trust)
    from props_verify import verify_signature
    valid = verify_signature(certificate_json)
"""

from props_verify.client import PropsClient
from props_verify.crypto import verify_signature, verify_payload_hash

__version__ = "0.1.0"
__all__ = ["PropsClient", "verify_signature", "verify_payload_hash"]
