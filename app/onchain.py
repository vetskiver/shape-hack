"""
Props on-chain certificate registry — app/onchain.py
=====================================================
Props L2 extension — on-chain permanence.
Stores certificate hashes on Ethereum Sepolia so they exist permanently without
depending on this server. A journalist or court can verify a certificate in 2030
even if the Props server is gone.

Uses raw JSON-RPC calls via httpx — no web3 dependency.
"""

import logging
import os
from typing import Optional

import httpx
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa import util as ecdsa_util

logger = logging.getLogger(__name__)

SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com"
CHAIN_ID = 11155111

# ---------------------------------------------------------------------------
# Pure-Python Keccak-256 (NOT SHA3-256 — different padding byte: 0x01 vs 0x06)
# ---------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]


def _rot64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(state: bytes) -> bytes:
    """Keccak-f[1600] permutation — 24 rounds."""
    lanes = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            o = 8 * (x + 5 * y)
            lanes[x][y] = int.from_bytes(state[o:o + 8], "little")
    for rc in _RC:
        # θ
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x][y] ^= d[x]
        # ρ and π
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rot64(lanes[x][y], _ROT[x][y])
        # χ
        for x in range(5):
            for y in range(5):
                lanes[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        # ι
        lanes[0][0] ^= rc
    out = bytearray(200)
    for x in range(5):
        for y in range(5):
            o = 8 * (x + 5 * y)
            out[o:o + 8] = (lanes[x][y] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    return bytes(out)


def _keccak256(data: bytes) -> bytes:
    """Keccak-256 hash. Padding byte 0x01 (not 0x06 like SHA3-256)."""
    rate = 136  # 1088 bits for Keccak-256 (capacity = 512)
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    state = bytearray(200)
    for i in range(0, len(padded), rate):
        for j in range(rate):
            state[j] ^= padded[i + j]
        state = bytearray(_keccak_f(state))
    return bytes(state[:32])


# ---------------------------------------------------------------------------
# Minimal RLP encoder (handles bytes and lists only — sufficient for txs)
# ---------------------------------------------------------------------------

def _min_bytes(n: int) -> bytes:
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _rlp_encode(item) -> bytes:
    if isinstance(item, bytes):
        if len(item) == 0:
            return b"\x80"
        if len(item) == 1 and item[0] < 0x80:
            return item
        if len(item) < 56:
            return bytes([0x80 + len(item)]) + item
        bl = _min_bytes(len(item))
        return bytes([0xB7 + len(bl)]) + bl + item
    if isinstance(item, list):
        payload = b"".join(_rlp_encode(x) for x in item)
        if len(payload) < 56:
            return bytes([0xC0 + len(payload)]) + payload
        bl = _min_bytes(len(payload))
        return bytes([0xF7 + len(bl)]) + bl + payload
    raise TypeError(f"Cannot RLP-encode {type(item)}")


def _int_to_bytes(n: int) -> bytes:
    """Integer → minimal big-endian bytes (0 → empty bytes, per Ethereum RLP convention)."""
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


# ---------------------------------------------------------------------------
# ABI encoding helpers
# ---------------------------------------------------------------------------

# Precomputed function selectors: keccak256(signature)[:4]
_STORE_SEL = _keccak256(b"store(bytes32,bytes32)")[:4]
_VERIFY_SEL = _keccak256(b"verify(bytes32)")[:4]


def _abi_encode_store(cert_id: bytes, attest_hash: bytes) -> bytes:
    return _STORE_SEL + cert_id.rjust(32, b"\x00") + attest_hash.rjust(32, b"\x00")


def _abi_encode_verify(cert_id: bytes) -> bytes:
    return _VERIFY_SEL + cert_id.rjust(32, b"\x00")


# ---------------------------------------------------------------------------
# EIP-155 transaction signing (secp256k1 via ecdsa library)
# ---------------------------------------------------------------------------

def _sign_tx(*, nonce, gas_price, gas_limit, to_hex, value, data, chain_id, pk_hex):
    """Build and sign an EIP-155 legacy transaction. Returns raw RLP bytes."""
    to_bytes = bytes.fromhex(to_hex.replace("0x", "").replace("0X", ""))

    # EIP-155 pre-image: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
    pre_items = [
        _int_to_bytes(nonce),
        _int_to_bytes(gas_price),
        _int_to_bytes(gas_limit),
        to_bytes,
        _int_to_bytes(value),
        data,
        _int_to_bytes(chain_id),
        b"",
        b"",
    ]
    msg_hash = _keccak256(_rlp_encode(pre_items))

    # Sign with secp256k1 (deterministic RFC-6979)
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    sig = sk.sign_digest(msg_hash, sigencode=ecdsa_util.sigencode_string)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")

    # Enforce low-s (EIP-2)
    order = SECP256k1.order
    if s > order // 2:
        s = order - s

    # Determine recovery_id by comparing recovered pubkeys with our known pubkey
    vk = sk.get_verifying_key()
    pub = vk.to_string()
    norm_sig = ecdsa_util.sigencode_string(r, s, order)
    recovered = VerifyingKey.from_public_key_recovery_with_digest(
        norm_sig, msg_hash, SECP256k1, sigdecode=ecdsa_util.sigdecode_string,
    )
    rec_id = 0
    for i, k in enumerate(recovered):
        if k.to_string() == pub:
            rec_id = i
            break

    v = chain_id * 2 + 35 + rec_id

    # Encode signed transaction
    signed_items = [
        _int_to_bytes(nonce),
        _int_to_bytes(gas_price),
        _int_to_bytes(gas_limit),
        to_bytes,
        _int_to_bytes(value),
        data,
        _int_to_bytes(v),
        _int_to_bytes(r),
        _int_to_bytes(s),
    ]
    return _rlp_encode(signed_items)


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _rpc(method: str, params: list):
    """Call a JSON-RPC method on the Sepolia endpoint."""
    r = httpx.post(
        SEPOLIA_RPC,
        json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        timeout=30,
    )
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"RPC error: {body['error']}")
    return body["result"]


def _pk_to_address(pk_hex: str) -> str:
    """Derive Ethereum address from a raw private key hex string."""
    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    pub = sk.get_verifying_key().to_string()  # 64 bytes (uncompressed sans prefix)
    return "0x" + _keccak256(pub)[-20:].hex()


# ---------------------------------------------------------------------------
# Public API — same signatures as the web3 version
# ---------------------------------------------------------------------------

def _cert_id_to_bytes32(certificate_id: str) -> bytes:
    """Convert UUID string → bytes32 via keccak256."""
    return _keccak256(certificate_id.encode())


def _hex_to_bytes32(hex_str: str) -> bytes:
    """Convert hex string (with or without 0x prefix) → bytes32, padded to 32 bytes."""
    clean = hex_str.replace("0x", "").replace("0X", "")
    padded = clean[:64].ljust(64, "0")
    return bytes.fromhex(padded)


def store_certificate(certificate_id: str, attestation_hash: str) -> str | None:
    """
    Props L2 extension — store certificate hash on Ethereum Sepolia testnet.

    Best-effort: never raises, returns None on any failure so the certificate is
    always returned to the user regardless of whether on-chain storage succeeded.
    """
    contract_address = os.environ.get("CONTRACT_ADDRESS", "").strip()
    private_key = os.environ.get("PRIVATE_KEY", "").strip()

    if not contract_address or not private_key:
        logger.info("[onchain] CONTRACT_ADDRESS or PRIVATE_KEY not set — skipping on-chain storage")
        return None

    pk = private_key.replace("0x", "").replace("0X", "")

    try:
        address = _pk_to_address(pk)
        nonce = int(_rpc("eth_getTransactionCount", [address, "latest"]), 16)
        gas_price = int(_rpc("eth_gasPrice", []), 16)

        cert_b32 = _cert_id_to_bytes32(certificate_id)
        hash_b32 = _hex_to_bytes32(attestation_hash)
        calldata = _abi_encode_store(cert_b32, hash_b32)

        raw = _sign_tx(
            nonce=nonce,
            gas_price=gas_price,
            gas_limit=80_000,
            to_hex=contract_address,
            value=0,
            data=calldata,
            chain_id=CHAIN_ID,
            pk_hex=pk,
        )

        tx_hash = _rpc("eth_sendRawTransaction", ["0x" + raw.hex()])

        logger.info(f"[onchain] Certificate {certificate_id[:8]}... stored: {tx_hash}")
        return tx_hash

    except Exception as e:
        logger.error(f"[onchain] Failed to store certificate on-chain: {e}")
        return None
