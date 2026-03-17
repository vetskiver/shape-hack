"""
Props on-chain certificate registry — app/onchain.py
=====================================================
Props L2 extension — on-chain permanence.
Stores certificate hashes on Base Sepolia so they exist permanently without
depending on this server. A journalist or court can verify a certificate in 2030
even if the Props server is gone.

Best-effort: never raises, returns None on any failure so the certificate is
always returned to the user regardless of whether on-chain storage succeeded.
"""

import logging
import os

from web3 import Web3

logger = logging.getLogger(__name__)

BASE_SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com"
CHAIN_ID = 11155111

# Minimal ABI — only the two functions we call
_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "certificateId", "type": "bytes32"},
            {"internalType": "bytes32", "name": "attestationHash", "type": "bytes32"},
        ],
        "name": "store",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "certificateId", "type": "bytes32"},
        ],
        "name": "verify",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def _cert_id_to_bytes32(certificate_id: str) -> bytes:
    """Convert UUID string → bytes32 via keccak256."""
    return Web3.keccak(text=certificate_id)


def _hex_to_bytes32(hex_str: str) -> bytes:
    """Convert hex string (with or without 0x prefix) → bytes32, padded to 32 bytes."""
    clean = hex_str.replace("0x", "").replace("0X", "")
    # Take first 64 hex chars (32 bytes), zero-pad if shorter
    padded = clean[:64].ljust(64, "0")
    return bytes.fromhex(padded)


def store_certificate(certificate_id: str, attestation_hash: str) -> str | None:
    """
    Props L2 extension — store certificate hash on Base Sepolia testnet.

    Converts the UUID certificate_id to bytes32 via keccak256, converts the
    Ed25519 signature hex to bytes32, calls store() on the registry contract,
    and waits for the transaction receipt (Base Sepolia blocks every ~2 seconds).

    Args:
        certificate_id:   UUID string from the certificate (e.g. "abc123-...")
        attestation_hash: hex Ed25519 signature from the certificate

    Returns:
        Transaction hash string ("0x...") on success, None on any failure.
    """
    contract_address = os.environ.get("CONTRACT_ADDRESS", "").strip()
    private_key = os.environ.get("PRIVATE_KEY", "").strip()

    if not contract_address or not private_key:
        logger.info("[onchain] CONTRACT_ADDRESS or PRIVATE_KEY not set — skipping on-chain storage")
        return None

    try:
        w3 = Web3(Web3.HTTPProvider(BASE_SEPOLIA_RPC))
        if not w3.is_connected():
            logger.warning("[onchain] Cannot connect to Base Sepolia RPC")
            return None

        account = w3.eth.account.from_key(private_key)
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=_ABI,
        )

        cert_bytes32 = _cert_id_to_bytes32(certificate_id)
        hash_bytes32 = _hex_to_bytes32(attestation_hash)

        nonce = w3.eth.get_transaction_count(account.address)
        tx = contract.functions.store(cert_bytes32, hash_bytes32).build_transaction({
            "chainId": CHAIN_ID,
            "from": account.address,
            "nonce": nonce,
            "gas": 80000,
            "gasPrice": w3.eth.gas_price,
        })

        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        tx_hex = tx_hash.hex()
        if not tx_hex.startswith("0x"):
            tx_hex = "0x" + tx_hex

        logger.info(f"[onchain] Certificate {certificate_id[:8]}... stored: {tx_hex}")
        return tx_hex

    except Exception as e:
        logger.error(f"[onchain] Failed to store certificate on-chain: {e}")
        return None
