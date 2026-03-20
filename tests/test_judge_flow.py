"""
Judge-path HTTP smoke test.

Exercises the narrow public/demo sequence with mocked external dependencies:
  /api/info -> /api/public-key -> POST /api/verify -> /api/certificate/{id} -> /api/verify/{id}

Run: pytest tests/test_judge_flow.py -v
"""

import json
import os
import sys
import types

from fastapi.testclient import TestClient

os.environ.setdefault("SKIP_OLLAMA_WAIT", "true")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import main  # noqa: E402

def test_judge_flow_smoke(monkeypatch):
    certificate_id = "judge-flow-cert-001"
    payload_hash = "abc123payloadhash"
    tx_hash = "0xjudgeflowtx"

    fake_oracle_result = {
        "credential": {
            "name": "Dr Demo",
            "license_number": "209311",
            "specialty": "Cardiology",
            "years_active": 17,
            "standing": "In good standing",
            "jurisdiction": "New York State",
        },
        "oracle_authenticated": True,
        "oracle_source": "www.op.nysed.gov",
        "oracle_tls_fingerprint": "TEST-FP",
        "data_hash": "oracle-data-hash",
        "oracle_type": "medical_board",
    }
    fake_extraction = {
        "extracted_facts": {
            "specialty": "Cardiology",
            "years_active": 17,
            "standing": "In good standing",
            "jurisdiction": "New York State",
        },
        "model_info": {
            "model_name": "llama3.2:1b",
            "model_digest": "sha256:judge-flow-model",
        },
        "extraction_method": "direct",
    }
    fake_redaction = {
        "disclosed": {
            "specialty": "Cardiology",
            "years_active": 17,
            "standing": "In good standing",
        },
        "all_fields": fake_oracle_result["credential"],
        "stripped_fields": ["jurisdiction", "license_number", "name"],
        "disclosed_fields": ["specialty", "standing", "years_active"],
    }
    fake_certificate = {
        "certificate_id": certificate_id,
        "credential": fake_redaction["disclosed"],
        "model_name": fake_extraction["model_info"]["model_name"],
        "model_digest": fake_extraction["model_info"]["model_digest"],
        "oracle_source": fake_oracle_result["oracle_source"],
        "oracle_tls_fingerprint": fake_oracle_result["oracle_tls_fingerprint"],
        "oracle_data_hash": fake_oracle_result["data_hash"],
        "raw_fields_stripped": fake_redaction["stripped_fields"],
        "disclosed_fields": fake_redaction["disclosed_fields"],
        "timestamp": "2026-03-20T22:00:00+00:00",
        "signing_key_public": "00" * 32,
        "signature": "11" * 64,
        "payload_hash": payload_hash,
        "tdx_quote": "22" * 700,
        "event_log": None,
        "enclave": "intel-tdx",
        "platform": "phala-cloud",
        "in_real_enclave": True,
    }

    monkeypatch.setattr(main, "fetch_credential", lambda credentials, oracle_target=None: fake_oracle_result)
    monkeypatch.setattr(main, "extract_credential_facts", lambda raw, oracle_type=None: fake_extraction)
    monkeypatch.setattr(main, "apply_redaction_filter", lambda credential, disclosed_fields, oracle_type=None: fake_redaction)
    monkeypatch.setattr(main, "generate_certificate", lambda redaction_result, oracle_result, model_info: dict(fake_certificate))
    monkeypatch.setattr(main, "verify_certificate", lambda cert: (True, "signature valid"))
    monkeypatch.setattr(
        main,
        "verify_tdx_quote",
        lambda cert: {
            "present": True,
            "report_data_matches": True,
            "verification_method": "structural",
            "details": "mock tdx verification",
            "measurements": {"mrtd": "demo-mrtd"},
            "intel_verified": False,
            "intel_details": (
                "Intel Trust Authority returned HTTP 401. "
                "No INTEL_TRUST_AUTHORITY_API_KEY was configured."
            ),
        },
    )
    fake_onchain = types.SimpleNamespace(
        CHAIN_EXPLORER="https://sepolia.basescan.org",
        store_certificate=lambda cert_id, att_hash: tx_hash,
        verify_certificate_onchain=lambda cert_id, att_hash: {
            "verified": True,
            "matches": True,
            "tx_hash": tx_hash,
        },
    )
    monkeypatch.setitem(sys.modules, "onchain", fake_onchain)

    with TestClient(main.app) as client:
        monkeypatch.setattr(main, "certificates", {})
        main._set_readiness(  # type: ignore[attr-defined]
            "ready_for_verify",
            verify_enabled=True,
            checks={
                "certificate_store": "ready",
                "oracle_target": "ready",
                "ollama": "ready",
                "model": "ready",
                "on_chain": "ready",
                "hardware_attestation": "ready",
            },
            blocking_issues=[],
            warnings=[],
        )

        info_response = client.get("/api/info")
        assert info_response.status_code == 200
        assert info_response.json()["verify_enabled"] is True

        public_key_response = client.get("/api/public-key")
        assert public_key_response.status_code == 200
        assert "BEGIN PUBLIC KEY" in public_key_response.text

        verify_response = client.post(
            "/api/verify",
            json={
                "credentials": {"license_number": "209311", "profession": "Physician (060)"},
                "disclosed_fields": ["specialty", "years_active", "standing"],
            },
        )
        assert verify_response.status_code == 200

        events = [
            json.loads(line)
            for line in verify_response.text.splitlines()
            if line.strip()
        ]
        assert [event["stage"] for event in events] == [
            "oracle",
            "oracle",
            "extraction",
            "extraction",
            "redaction",
            "redaction",
            "attestation",
            "attestation",
            "done",
        ]
        assert events[-1]["certificate"]["certificate_id"] == certificate_id
        assert events[-1]["certificate"]["model_digest"] == "sha256:judge-flow-model"

        certificate_response = client.get(f"/api/certificate/{certificate_id}")
        assert certificate_response.status_code == 200
        assert certificate_response.json()["basescan_url"].endswith(tx_hash)

        verifier_response = client.get(f"/api/verify/{certificate_id}")
        assert verifier_response.status_code == 200
        verifier_body = verifier_response.json()
        assert verifier_body["trust_level"] == "hardware"
        assert verifier_body["on_chain_verified"] is True
        assert verifier_body["on_chain_matches"] is True
        assert verifier_body["model_digest"] == "sha256:judge-flow-model"
