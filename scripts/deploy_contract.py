"""
Deploy PropsCertRegistry v2 (append-only).

Uses the same pure-Python Keccak/RLP/secp256k1 stack from app/onchain.py.
No web3.py or Foundry needed.

Usage:
  PRIVATE_KEY=0x... python scripts/deploy_contract.py                  # Base Sepolia (default)
  PRIVATE_KEY=0x... python scripts/deploy_contract.py --chain sepolia  # Ethereum Sepolia

Outputs the new contract address.
"""

import os
import sys
import time

# Add app/ to path so we can reuse onchain.py primitives
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from onchain import _keccak256, _rlp_encode, _int_to_bytes, _pk_to_address
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa import util as ecdsa_util
import httpx

# Chain configs
CHAINS = {
    "base_sepolia": {
        "rpc": "https://sepolia.base.org",
        "chain_id": 84532,
        "name": "Base Sepolia",
        "explorer": "https://sepolia.basescan.org",
    },
    "sepolia": {
        "rpc": "https://ethereum-sepolia-rpc.publicnode.com",
        "chain_id": 11155111,
        "name": "Ethereum Sepolia",
        "explorer": "https://sepolia.etherscan.io",
    },
}


def _rpc(method, params, rpc_url):
    """JSON-RPC call to any chain."""
    r = httpx.post(rpc_url, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1}, timeout=30)
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"RPC error: {body['error']}")
    return body["result"]

# Compiled bytecode of PropsCertRegistry v2 (with append-only check)
# Compiled with solc 0.8.34
BYTECODE = bytes.fromhex(
    "6080604052348015600e575f5ffd5b506102838061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80634000e4f61461003857806375e3661614610054575b5f5ffd5b610052600480360381019061004d919061017d565b610084565b005b61006e600480360381019061006991906101bb565b61012d565b60405161007b91906101f5565b60405180910390f35b5f5f1b5f5f8481526020019081526020015f2054146100da57816040517f16b35fe30000000000000000000000000000000000000000000000000000000081526004016100d191906101f5565b60405180910390fd5b805f5f8481526020019081526020015f2081905550817fbc242c34bb4427dfde027956987f5b0faccf0fac280052a35b95d58ee3187ef08242604051610121929190610226565b60405180910390a25050565b5f5f5f8381526020019081526020015f20549050919050565b5f5ffd5b5f819050919050565b61015c8161014a565b8114610166575f5ffd5b50565b5f8135905061017781610153565b92915050565b5f5f6040838503121561019357610192610146565b5b5f6101a085828601610169565b92505060206101b185828601610169565b9150509250929050565b5f602082840312156101d0576101cf610146565b5b5f6101dd84828501610169565b91505092915050565b6101ef8161014a565b82525050565b5f6020820190506102085f8301846101e6565b92915050565b5f819050919050565b6102208161020e565b82525050565b5f6040820190506102395f8301856101e6565b6102466020830184610217565b939250505056fea26469706673582212204865c99dcf2cbfc637732a858dfad414f5902f652c455b59e37db7034f1ffb4d64736f6c63430008220033"
)


def _sign_tx(*, nonce, gas_price, gas_limit, to_bytes, value, data, chain_id, pk_hex):
    """Build and sign an EIP-155 legacy transaction. Returns raw RLP hex."""
    pre_items = [
        _int_to_bytes(nonce),
        _int_to_bytes(gas_price),
        _int_to_bytes(gas_limit),
        to_bytes,  # empty bytes for contract creation
        _int_to_bytes(value),
        data,
        _int_to_bytes(chain_id),
        b"",
        b"",
    ]
    msg_hash = _keccak256(_rlp_encode(pre_items))

    sk = SigningKey.from_string(bytes.fromhex(pk_hex), curve=SECP256k1)
    sig = sk.sign_digest(msg_hash, sigencode=ecdsa_util.sigencode_string)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")

    order = SECP256k1.order
    if s > order // 2:
        s = order - s

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


def deploy(chain_key="base_sepolia"):
    chain = CHAINS[chain_key]
    rpc_url = chain["rpc"]
    chain_id = chain["chain_id"]
    chain_name = chain["name"]
    explorer = chain["explorer"]

    pk = os.environ.get("PRIVATE_KEY", "").strip().replace("0x", "")
    if not pk:
        print("ERROR: Set PRIVATE_KEY env var")
        sys.exit(1)

    address = _pk_to_address(pk)
    print(f"Chain:    {chain_name} ({chain_id})")
    print(f"RPC:      {rpc_url}")
    print(f"Deployer: {address}")

    # Check balance
    balance_hex = _rpc("eth_getBalance", [address, "latest"], rpc_url)
    balance_wei = int(balance_hex, 16)
    balance_eth = balance_wei / 1e18
    print(f"Balance:  {balance_eth:.6f} ETH")
    if balance_eth < 0.001:
        print("WARNING: Very low balance.")

    nonce = int(_rpc("eth_getTransactionCount", [address, "latest"], rpc_url), 16)
    gas_price = int(_rpc("eth_gasPrice", [], rpc_url), 16)
    print(f"Nonce: {nonce}, Gas price: {gas_price} wei ({gas_price / 1e9:.1f} gwei)")

    # Contract creation: to=empty, data=bytecode
    raw_tx = _sign_tx(
        nonce=nonce,
        gas_price=gas_price,
        gas_limit=500_000,
        to_bytes=b"",
        value=0,
        data=BYTECODE,
        chain_id=chain_id,
        pk_hex=pk,
    )

    print(f"Sending contract creation transaction...")
    tx_hash = _rpc("eth_sendRawTransaction", ["0x" + raw_tx.hex()], rpc_url)
    print(f"TX hash: {tx_hash}")
    print(f"{explorer}/tx/{tx_hash}")

    # Wait for receipt
    print("Waiting for confirmation...")
    for _ in range(60):
        time.sleep(3)
        try:
            receipt = _rpc("eth_getTransactionReceipt", [tx_hash], rpc_url)
            if receipt is not None:
                status = int(receipt["status"], 16)
                contract_addr = receipt["contractAddress"]
                gas_used = int(receipt["gasUsed"], 16)
                if status == 1:
                    print(f"\n{'='*60}")
                    print(f"CONTRACT DEPLOYED SUCCESSFULLY")
                    print(f"{'='*60}")
                    print(f"Address:  {contract_addr}")
                    print(f"TX:       {tx_hash}")
                    print(f"Gas used: {gas_used}")
                    print(f"Chain:    {chain_name} ({chain_id})")
                    print(f"Explorer: {explorer}/address/{contract_addr}")
                    print(f"{'='*60}")
                    print(f"\nUpdate docker-compose.yaml and .env:")
                    print(f"  CONTRACT_ADDRESS={contract_addr}")
                    return contract_addr
                else:
                    print(f"FAILED: Transaction reverted (status=0)")
                    sys.exit(1)
        except Exception:
            pass
        print(".", end="", flush=True)

    print(f"\nTimeout waiting for receipt. Check {explorer} manually.")
    return None


if __name__ == "__main__":
    chain = "base_sepolia"
    if "--chain" in sys.argv:
        idx = sys.argv.index("--chain")
        chain = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "base_sepolia"
    if chain not in CHAINS:
        print(f"Unknown chain '{chain}'. Valid: {', '.join(CHAINS.keys())}")
        sys.exit(1)
    deploy(chain)
