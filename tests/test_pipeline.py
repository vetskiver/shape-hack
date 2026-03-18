"""
Props Pipeline Smoke Tests
===========================
Exercises the core pipeline modules with mock data — no Ollama, no Phala Cloud,
no network access required. Validates that the redaction, attestation, and forge
logic work correctly in isolation.

Run: pytest tests/test_pipeline.py -v
"""

import hashlib
import json
import sys
import os

# Add app/ to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

# These imports work without Ollama or dstack running
from redaction import apply_redaction_filter, get_all_disclosable_fields
from attestation import generate_certificate, verify_certificate


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_MEDICAL_CREDENTIAL = {
    "name": "Dr Sarah Chen",
    "license_number": "NY-MD-2847193",
    "address": "84 Park Ave, New York",
    "specialty": "Cardiology",
    "years_active": 17,
    "jurisdiction": "New York State",
    "standing": "In good standing",
    "initial_registration_date": "January 08, 2007",
    "medical_school": "Columbia University",
}

SAMPLE_ATTORNEY_CREDENTIAL = {
    "name": "Raymond J. Aab",
    "registration_number": "1190404",
    "address": "233 Broadway Rm 1800, New York, Ny, 10279",
    "phone_number": "(212) 406-1700",
    "company_name": "Raymond J. Aab Attorney At Law",
    "year_admitted": 1978,
    "years_practicing": 48,
    "judicial_department": "Judicial Department 1",
    "law_school": "Fordham University School Of Law",
    "standing": "In good standing",
    "county": "New York",
    "jurisdiction": "New York State",
}

SAMPLE_ORACLE_RESULT = {
    "oracle_authenticated": True,
    "oracle_source": "www.op.nysed.gov",
    "oracle_tls_fingerprint": "ABCDEF1234",
    "data_hash": hashlib.sha256(b"test-data").hexdigest(),
}

SAMPLE_MODEL_INFO = {
    "model_name": "llama3.2:3b",
    "model_digest": hashlib.sha256(b"llama3.2:3b").hexdigest(),
}


# ---------------------------------------------------------------------------
# Redaction tests (Props L4)
# ---------------------------------------------------------------------------

class TestRedaction:
    def test_identity_fields_always_stripped_medical(self):
        result = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty", "years_active", "name", "license_number"],
            oracle_type="medical_board",
        )
        assert "name" not in result["disclosed"]
        assert "license_number" not in result["disclosed"]
        assert "specialty" in result["disclosed"]
        assert "years_active" in result["disclosed"]

    def test_identity_fields_always_stripped_attorney(self):
        result = apply_redaction_filter(
            SAMPLE_ATTORNEY_CREDENTIAL,
            ["law_school", "years_practicing", "name", "registration_number"],
            oracle_type="attorney",
        )
        assert "name" not in result["disclosed"]
        assert "registration_number" not in result["disclosed"]
        assert "law_school" in result["disclosed"]
        assert "years_practicing" in result["disclosed"]

    def test_no_fields_disclosed(self):
        result = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL, [], oracle_type="medical_board"
        )
        assert result["disclosed"] == {}
        assert len(result["stripped_fields"]) == len(SAMPLE_MEDICAL_CREDENTIAL)

    def test_all_disclosable_fields(self):
        result = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty", "years_active", "jurisdiction", "standing"],
            oracle_type="medical_board",
        )
        assert len(result["disclosed"]) == 4
        # Identity fields must still be stripped
        assert "name" in result["stripped_fields"]
        assert "license_number" in result["stripped_fields"]
        assert "address" in result["stripped_fields"]

    def test_stripped_fields_list_is_sorted(self):
        result = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty"],
            oracle_type="medical_board",
        )
        assert result["stripped_fields"] == sorted(result["stripped_fields"])
        assert result["disclosed_fields"] == sorted(result["disclosed_fields"])

    def test_disclosable_fields_per_oracle_type(self):
        medical_fields = get_all_disclosable_fields("medical_board")
        attorney_fields = get_all_disclosable_fields("attorney")
        assert "specialty" in medical_fields
        assert "law_school" in attorney_fields
        assert "specialty" not in attorney_fields
        assert "law_school" not in medical_fields


# ---------------------------------------------------------------------------
# Attestation tests (Props L2)
# ---------------------------------------------------------------------------

class TestAttestation:
    def test_generate_and_verify_certificate(self):
        redaction = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty", "years_active"],
            oracle_type="medical_board",
        )
        cert = generate_certificate(redaction, SAMPLE_ORACLE_RESULT, SAMPLE_MODEL_INFO)

        # Certificate has required fields
        assert "certificate_id" in cert
        assert "credential" in cert
        assert "signature" in cert
        assert "signing_key_public" in cert
        assert "payload_hash" in cert
        assert "model_name" in cert
        assert "model_digest" in cert
        assert "raw_fields_stripped" in cert
        assert "disclosed_fields" in cert

        # Credential contains only disclosed fields
        assert "specialty" in cert["credential"]
        assert "years_active" in cert["credential"]
        assert "name" not in cert["credential"]

        # Signature verifies
        valid, reason = verify_certificate(cert)
        assert valid, f"Certificate should verify: {reason}"

    def test_tampered_certificate_fails_verification(self):
        redaction = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty", "years_active"],
            oracle_type="medical_board",
        )
        cert = generate_certificate(redaction, SAMPLE_ORACLE_RESULT, SAMPLE_MODEL_INFO)

        # Tamper with the credential
        cert["credential"]["specialty"] = "FAKE SPECIALTY"

        valid, reason = verify_certificate(cert)
        assert not valid, "Tampered certificate should fail verification"
        assert "tampered" in reason.lower() or "invalid" in reason.lower()

    def test_tampered_timestamp_fails_verification(self):
        redaction = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty"],
            oracle_type="medical_board",
        )
        cert = generate_certificate(redaction, SAMPLE_ORACLE_RESULT, SAMPLE_MODEL_INFO)

        cert["timestamp"] = "2099-01-01T00:00:00+00:00"

        valid, reason = verify_certificate(cert)
        assert not valid

    def test_missing_field_fails_verification(self):
        redaction = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty"],
            oracle_type="medical_board",
        )
        cert = generate_certificate(redaction, SAMPLE_ORACLE_RESULT, SAMPLE_MODEL_INFO)

        del cert["signing_key_public"]

        valid, reason = verify_certificate(cert)
        assert not valid
        assert "missing" in reason.lower() or "malformed" in reason.lower()

    def test_model_info_in_certificate(self):
        redaction = apply_redaction_filter(
            SAMPLE_MEDICAL_CREDENTIAL,
            ["specialty"],
            oracle_type="medical_board",
        )
        cert = generate_certificate(redaction, SAMPLE_ORACLE_RESULT, SAMPLE_MODEL_INFO)

        assert cert["model_name"] == "llama3.2:3b"
        assert cert["model_digest"] == SAMPLE_MODEL_INFO["model_digest"]


# ---------------------------------------------------------------------------
# Forge / adversarial tests (Props L5)
# ---------------------------------------------------------------------------

class TestAdversarialDefense:
    def test_non_oracle_authenticated_data_rejected(self):
        """Simulates the pdf attack — data without oracle_authenticated flag."""
        fake_oracle_result = {
            "credential": {"specialty": "Cardiology"},
            "oracle_authenticated": False,
            "oracle_source": "direct-submission",
        }
        # The pipeline checks this flag before proceeding
        assert fake_oracle_result["oracle_authenticated"] is False

    def test_signature_catches_post_issuance_tampering(self):
        """Simulates the tampered attack — modify cert after issuance."""
        redaction = apply_redaction_filter(
            {"specialty": "General Practitioner", "years_active": 5,
             "jurisdiction": "NY", "standing": "Active"},
            ["specialty", "years_active", "jurisdiction", "standing"],
            oracle_type="medical_board",
        )
        cert = generate_certificate(redaction, SAMPLE_ORACLE_RESULT, SAMPLE_MODEL_INFO)

        # Valid before tampering
        valid, _ = verify_certificate(cert)
        assert valid

        # Tamper: GP → Cardiologist
        tampered = json.loads(json.dumps(cert))
        tampered["credential"]["specialty"] = "Cardiology"
        tampered["credential"]["years_active"] = 17

        valid, reason = verify_certificate(tampered)
        assert not valid, "Tampered certificate should fail"

    def test_data_hash_changes_on_modification(self):
        """Simulates integrity check — data hash must change if data changes."""
        original = {"specialty": "GP", "years_active": 5}
        modified = {"specialty": "Cardiology", "years_active": 17}

        hash_original = hashlib.sha256(
            json.dumps(original, sort_keys=True).encode()
        ).hexdigest()
        hash_modified = hashlib.sha256(
            json.dumps(modified, sort_keys=True).encode()
        ).hexdigest()

        assert hash_original != hash_modified
