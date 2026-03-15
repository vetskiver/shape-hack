#!/usr/bin/env python3
import json, base64, cbor2
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

def load_cert(data):
    """Load a DER cert (bytes or hex-string)."""
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return x509.load_der_x509_certificate(data)

def verify_chain(leaf, chain_certs):
    """Simple chain-of-trust: verify each cert is signed by its issuer."""
    now = datetime.utcnow()
    chain = [leaf]
    while True:
        curr = chain[-1]
        # validity window
        if now < curr.not_valid_before or now > curr.not_valid_after:
            raise ValueError(f"Certificate expired or not yet valid: {curr.subject}")
        # self-signed? done
        if curr.issuer == curr.subject:
            break
        # find issuer in bundle
        for ca in chain_certs:
            if ca.subject == curr.issuer:
                ca.public_key().verify(
                    curr.signature,
                    curr.tbs_certificate_bytes,
                    ec.ECDSA(curr.signature_hash_algorithm)
                )
                chain.append(ca)
                break
        else:
            raise ValueError(f"Issuer not found for: {curr.subject}")
    print(f"✓ Certificate chain length {len(chain)} OK")

def verify_cose(protected_bytes, payload, sig, pubkey):
    """Verify the ECDSA-384 COSE_Sign1 signature."""
    # build Sig_structure per RFC8152 §4.4
    structure = ["Signature1", protected_bytes, b"", payload]
    to_be_signed = cbor2.dumps(structure)
    # split raw r||s (96 bytes)
    r, s = (int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big"))
    der_sig = encode_dss_signature(r, s)
    pubkey.verify(der_sig, to_be_signed, ec.ECDSA(hashes.SHA384()))
    print("✓ COSE signature OK")

def main(path):
    # 1) load JSON + base64→CBOR
    doc = json.load(open(path))["document"]
    raw = base64.b64decode(doc)
    # 2) decode COSE_Sign1
    ph, uh, payload, sig = cbor2.loads(raw)
    phb = ph if isinstance(ph, bytes) else bytes.fromhex(ph)
    # 3) extract cert + CA bundle from payload
    p = cbor2.loads(payload)
    leaf = load_cert(p["certificate"])
    cas  = [ load_cert(c) for c in p.get("cabundle", []) ]
    # 4) verify leaf→root
    verify_chain(leaf, cas)
    # 5) verify COSE signature
    verify_cose(phb, payload, sig, leaf.public_key())
    print("All checks passed!")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} attestation.json")
        sys.exit(1)
    main(sys.argv[1])
