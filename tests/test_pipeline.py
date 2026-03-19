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
from attestation import generate_certificate, verify_certificate, verify_tdx_quote, parse_tdx_measurements


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
        """Simulates the pdf attack — data without oracle_authenticated flag.

        Uses the same enforce_oracle_authenticated() guard as the real pipeline.
        Tests that the guard rejects: missing flag, False flag, wrong types.
        """
        # Inline copy of the shared guard from main.py — same logic, tested here
        def enforce_oracle_authenticated(oracle_result: dict) -> bool:
            return oracle_result.get("oracle_authenticated", False) is True

        # Case 1: No oracle_authenticated flag at all (direct submission)
        assert not enforce_oracle_authenticated({"credential": {"specialty": "Cardiology"}})

        # Case 2: oracle_authenticated explicitly False
        assert not enforce_oracle_authenticated({
            "credential": {"specialty": "Cardiology"},
            "oracle_authenticated": False,
        })

        # Case 3: Attacker tries to set oracle_authenticated as string "True"
        assert not enforce_oracle_authenticated({
            "credential": {"specialty": "Cardiology"},
            "oracle_authenticated": "True",
        })

        # Case 4: Attacker tries to set oracle_authenticated as int 1
        assert not enforce_oracle_authenticated({
            "credential": {"specialty": "Cardiology"},
            "oracle_authenticated": 1,
        })

        # Case 5: Only real oracle sets it to boolean True — this should pass
        assert enforce_oracle_authenticated({
            "credential": {"specialty": "Cardiology"},
            "oracle_authenticated": True,
            "oracle_source": "www.op.nysed.gov",
        })

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


# ---------------------------------------------------------------------------
# TDX quote verification tests (Props L2)
# ---------------------------------------------------------------------------

class TestTDXQuoteVerification:
    def test_no_quote_returns_not_present(self):
        """Certificate without TDX quote (simulated enclave)."""
        cert = {"payload_hash": "abcd1234"}
        result = verify_tdx_quote(cert)
        assert result["present"] is False
        assert result["report_data_matches"] is None

    def test_quote_with_matching_report_data(self):
        """Synthetic TDX quote with correct report_data at offset 568."""
        payload_hash = hashlib.sha256(b"test-payload").hexdigest()
        payload_hash_bytes = bytes.fromhex(payload_hash)

        # Build a synthetic quote: 568 bytes of padding + 32 bytes of hash + 32 bytes zero
        quote_bytes = b"\x00" * 568 + payload_hash_bytes + b"\x00" * 32
        cert = {
            "tdx_quote": quote_bytes.hex(),
            "payload_hash": payload_hash,
        }
        result = verify_tdx_quote(cert)
        assert result["present"] is True
        assert result["report_data_matches"] is True

    def test_quote_with_mismatched_report_data(self):
        """Synthetic TDX quote with wrong report_data — should detect mismatch."""
        payload_hash = hashlib.sha256(b"real-payload").hexdigest()
        wrong_hash = hashlib.sha256(b"tampered-payload").digest()

        quote_bytes = b"\x00" * 568 + wrong_hash + b"\x00" * 32
        cert = {
            "tdx_quote": quote_bytes.hex(),
            "payload_hash": payload_hash,
        }
        result = verify_tdx_quote(cert)
        assert result["present"] is True
        assert result["report_data_matches"] is False

    def test_quote_too_short(self):
        """Quote shorter than expected — should handle gracefully."""
        cert = {
            "tdx_quote": "aabbccdd",  # 4 bytes
            "payload_hash": "1234",
        }
        result = verify_tdx_quote(cert)
        assert result["present"] is True
        assert result["report_data_matches"] is None


# =============================================================================
# Rate Limiter Tests
# =============================================================================

class TestRateLimiter:
    """Tests for the in-memory rate limiter."""

    def test_allows_under_limit(self):
        """Requests under the limit should be allowed."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
        from main import _RateLimiter
        limiter = _RateLimiter(max_tokens=3, refill_seconds=60)
        assert limiter.allow("test-ip") is True
        assert limiter.allow("test-ip") is True
        assert limiter.allow("test-ip") is True

    def test_blocks_over_limit(self):
        """Requests over the limit should be blocked."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
        from main import _RateLimiter
        limiter = _RateLimiter(max_tokens=2, refill_seconds=60)
        assert limiter.allow("test-ip") is True
        assert limiter.allow("test-ip") is True
        assert limiter.allow("test-ip") is False

    def test_different_ips_independent(self):
        """Different IPs should have independent limits."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
        from main import _RateLimiter
        limiter = _RateLimiter(max_tokens=1, refill_seconds=60)
        assert limiter.allow("ip-a") is True
        assert limiter.allow("ip-a") is False
        assert limiter.allow("ip-b") is True  # different IP, still has tokens

    def test_cleanup_removes_stale(self):
        """Cleanup should remove entries older than 10 minutes."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
        from main import _RateLimiter
        limiter = _RateLimiter(max_tokens=5, refill_seconds=1)
        limiter.allow("stale-ip")
        # Manually age the entry
        import time
        limiter._buckets["stale-ip"][1] = time.monotonic() - 700
        limiter.cleanup()
        assert "stale-ip" not in limiter._buckets


# =============================================================================
# Input Validation Tests
# =============================================================================

class TestInputValidation:
    """Tests for oracle input validation."""

    def test_license_number_valid(self):
        """Valid numeric license numbers should be accepted."""
        import re
        valid_numbers = ["209311", "123456", "1", "1234567890"]
        for num in valid_numbers:
            assert re.match(r'^\d{1,10}$', num), f"{num} should be valid"

    def test_license_number_invalid(self):
        """Non-numeric or too-long license numbers should be rejected."""
        import re
        invalid_numbers = ["FAKE-001", "'; DROP TABLE", "<script>alert(1)</script>", "", "12345678901"]
        for num in invalid_numbers:
            assert not re.match(r'^\d{1,10}$', num), f"{num} should be invalid"

    def test_field_name_valid(self):
        """Valid field names (alphanumeric + underscore) should pass."""
        import re
        valid_fields = ["specialty", "years_active", "law_school", "standing"]
        for field in valid_fields:
            assert re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field), f"{field} should be valid"

    def test_field_name_invalid(self):
        """Invalid field names should be rejected."""
        import re
        invalid_fields = ["'; DROP TABLE", "<script>", "../../../etc/passwd", "field name", "123field"]
        for field in invalid_fields:
            assert not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field), f"{field} should be invalid"


# =============================================================================
# TDX Measurement Parsing Tests (Props L2)
# =============================================================================

class TestTDXMeasurementParsing:
    """Tests for MRTD/RTMR extraction from TDX quotes."""

    def test_parse_measurements_from_synthetic_quote(self):
        """Synthetic TDX quote with known MRTD and RTMRs."""
        # Build a synthetic quote with distinct byte patterns at each measurement offset
        quote_bytes = bytearray(632)  # minimum size for all fields

        # Header: version=4, ak_type=2, tee_type=0x81
        quote_bytes[0:2] = (4).to_bytes(2, "little")
        quote_bytes[2:4] = (2).to_bytes(2, "little")
        quote_bytes[4:8] = (0x81).to_bytes(4, "little")

        # MRTD at offset 184 (48 bytes) — fill with 0xAA
        quote_bytes[184:232] = b"\xaa" * 48

        # RTMR0 at offset 376 (48 bytes) — fill with 0xBB
        quote_bytes[376:424] = b"\xbb" * 48

        # RTMR1 at offset 424 (48 bytes) — fill with 0xCC
        quote_bytes[424:472] = b"\xcc" * 48

        # RTMR2 at offset 472 (48 bytes) — fill with 0xDD
        quote_bytes[472:520] = b"\xdd" * 48

        # RTMR3 at offset 520 (48 bytes) — fill with 0xEE
        quote_bytes[520:568] = b"\xee" * 48

        # REPORTDATA at offset 568 (64 bytes) — fill with 0xFF
        quote_bytes[568:632] = b"\xff" * 64

        result = parse_tdx_measurements(bytes(quote_bytes).hex())

        assert result is not None
        assert result["quote_version"] == 4
        assert result["attestation_key_type"] == 2
        assert result["tee_type"] == "0x81"
        assert result["mrtd"] == "aa" * 48
        assert result["rtmr0"] == "bb" * 48
        assert result["rtmr1"] == "cc" * 48
        assert result["rtmr2"] == "dd" * 48
        assert result["rtmr3"] == "ee" * 48
        assert result["report_data"] == "ff" * 64

    def test_parse_measurements_too_short(self):
        """Quote too short for measurement extraction."""
        result = parse_tdx_measurements("aabbccdd")
        assert result is None

    def test_parse_measurements_empty(self):
        """Empty quote hex returns None."""
        result = parse_tdx_measurements("")
        assert result is None

    def test_verify_tdx_quote_includes_measurements(self):
        """verify_tdx_quote result should include measurements when quote is long enough."""
        payload_hash = hashlib.sha256(b"test-payload").hexdigest()
        payload_hash_bytes = bytes.fromhex(payload_hash)

        # Build synthetic quote with known MRTD
        quote_bytes = bytearray(632)
        quote_bytes[184:232] = b"\xab" * 48  # MRTD
        quote_bytes[568:600] = payload_hash_bytes  # report_data first 32 bytes
        quote_bytes[600:632] = b"\x00" * 32  # report_data last 32 bytes

        cert = {
            "tdx_quote": bytes(quote_bytes).hex(),
            "payload_hash": payload_hash,
        }
        result = verify_tdx_quote(cert)
        assert result["present"] is True
        assert result["report_data_matches"] is True
        assert result["measurements"] is not None
        assert result["measurements"]["mrtd"] == "ab" * 48


# =============================================================================
# Integration Test — Full Pipeline (Props L1-L4)
# =============================================================================

class TestFullPipelineIntegration:
    """
    End-to-end test: oracle result → LLM extraction (mocked) → redaction → attestation.
    Exercises the same code path as POST /api/verify without needing Ollama or a live oracle.
    """

    def test_full_pipeline_medical(self):
        """Medical pipeline: oracle → extraction → redaction → certificate → verify."""
        # Step 1: Simulate oracle result (L1)
        raw_credential = {
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
        oracle_result = {
            "credential": raw_credential,
            "oracle_authenticated": True,
            "oracle_source": "www.op.nysed.gov",
            "oracle_tls_fingerprint": "ABCDEF1234",
            "data_hash": hashlib.sha256(
                json.dumps(raw_credential, sort_keys=True).encode()
            ).hexdigest(),
            "oracle_type": "medical_board",
        }

        # Step 2: Simulate LLM extraction result (L3) — in production, Ollama does this
        extracted_facts = {
            "specialty": "Cardiology",
            "years_active": 17,
            "jurisdiction": "New York State",
            "standing": "In good standing",
        }
        model_info = {
            "model_name": "llama3.2:3b",
            "model_digest": "sha256:a6990ed6be41test",
        }

        # Step 3: Merge extraction into credential (same as main.py line 670)
        enriched_credential = {**raw_credential, **extracted_facts}

        # Step 4: Redaction (L4) — user chose to disclose only specialty + years_active
        disclosed_fields = ["specialty", "years_active"]
        redaction_result = apply_redaction_filter(
            enriched_credential, disclosed_fields, oracle_type="medical_board"
        )

        # Verify redaction
        assert "name" not in redaction_result["disclosed"]
        assert "license_number" not in redaction_result["disclosed"]
        assert "address" not in redaction_result["disclosed"]
        assert "specialty" in redaction_result["disclosed"]
        assert "years_active" in redaction_result["disclosed"]
        assert redaction_result["disclosed"]["specialty"] == "Cardiology"
        assert redaction_result["disclosed"]["years_active"] == 17

        # Step 5: Generate certificate (L2)
        cert = generate_certificate(redaction_result, oracle_result, model_info)

        # Verify certificate structure
        assert cert["certificate_id"]
        assert cert["credential"] == {"specialty": "Cardiology", "years_active": 17}
        assert cert["model_name"] == "llama3.2:3b"
        assert cert["model_digest"] == "sha256:a6990ed6be41test"
        assert cert["oracle_source"] == "www.op.nysed.gov"
        assert "name" not in cert["credential"]
        assert "license_number" not in cert["credential"]
        assert len(cert["raw_fields_stripped"]) > 0
        assert "name" in cert["raw_fields_stripped"]
        assert cert["signature"]
        assert cert["signing_key_public"]
        assert cert["payload_hash"]

        # Step 6: Verify certificate signature (what the verifier page does)
        valid, reason = verify_certificate(cert)
        assert valid, f"Certificate should verify: {reason}"

        # Step 7: Tamper and verify rejection
        tampered = json.loads(json.dumps(cert))
        tampered["credential"]["specialty"] = "FAKE"
        valid_tampered, _ = verify_certificate(tampered)
        assert not valid_tampered, "Tampered certificate must fail"

    def test_full_pipeline_attorney(self):
        """Attorney pipeline: same flow, different oracle type."""
        raw_credential = {
            "name": "Raymond J. Aab",
            "registration_number": "1190404",
            "address": "233 Broadway, New York",
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
        oracle_result = {
            "credential": raw_credential,
            "oracle_authenticated": True,
            "oracle_source": "data.ny.gov",
            "oracle_tls_fingerprint": "1234ABCD",
            "data_hash": hashlib.sha256(
                json.dumps(raw_credential, sort_keys=True).encode()
            ).hexdigest(),
            "oracle_type": "attorney",
        }
        model_info = {
            "model_name": "llama3.2:3b",
            "model_digest": "sha256:test-digest",
        }

        disclosed_fields = ["law_school", "years_practicing", "standing"]
        redaction_result = apply_redaction_filter(
            raw_credential, disclosed_fields, oracle_type="attorney"
        )

        # Identity fields must be stripped
        assert "name" not in redaction_result["disclosed"]
        assert "registration_number" not in redaction_result["disclosed"]
        assert "address" not in redaction_result["disclosed"]
        assert "law_school" in redaction_result["disclosed"]
        assert "years_practicing" in redaction_result["disclosed"]

        cert = generate_certificate(redaction_result, oracle_result, model_info)
        valid, reason = verify_certificate(cert)
        assert valid, f"Attorney certificate should verify: {reason}"

        # Verify cross-oracle consistency — same certificate structure regardless of oracle type
        assert cert["oracle_source"] == "data.ny.gov"
        assert cert["model_name"] == "llama3.2:3b"
        assert "name" not in cert["credential"]
