"""
Props L4 — Data Redaction Layer (Props paper, section 2.4)
==========================================================
Implements the filter f(X) = X' from the Props paper.

The user selects which credential fields they consent to disclose.
This filter runs INSIDE the enclave — the TEE enforces redaction,
not the frontend. Only consented, non-identity fields ever exit.

Two-step redaction:
  Step 1 — mandatory strip: identity fields are ALWAYS removed regardless
            of user consent (name, license_number, address, date_of_birth, etc.)
  Step 2 — consent filter: only fields the user explicitly selected are included

The `raw_fields_stripped` list returned here drives the struck-through display
on Screen 2 of the frontend — it must come from the enclave, not be hardcoded.

S8 — Pluggable Oracle: field classification is oracle-type-aware.
Each oracle type has its own identity and disclosable field sets.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Field classification — per oracle type (S8: pluggable oracle)
# ---------------------------------------------------------------------------

# Medical board oracle (default)
_MEDICAL_IDENTITY_FIELDS: frozenset[str] = frozenset({
    "name",
    "license_number",
    "address",
    "date_of_birth",
    "medical_school",
    "degree_date",
    "initial_registration_date",
    "registered_through",
})

_MEDICAL_DISCLOSABLE_FIELDS: frozenset[str] = frozenset({
    "specialty",
    "years_active",
    "jurisdiction",
    "standing",
})

# Attorney oracle (S10 — real NY attorney registry via data.ny.gov)
_ATTORNEY_IDENTITY_FIELDS: frozenset[str] = frozenset({
    "name",
    "registration_number",
    "address",
    "phone_number",
    "company_name",
})

_ATTORNEY_DISCLOSABLE_FIELDS: frozenset[str] = frozenset({
    "year_admitted",
    "years_practicing",
    "judicial_department",
    "law_school",
    "standing",
    "county",
    "jurisdiction",
})

# Registry of field configs keyed by oracle_type
_FIELD_CONFIGS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "medical_board": (_MEDICAL_IDENTITY_FIELDS, _MEDICAL_DISCLOSABLE_FIELDS),
    "attorney": (_ATTORNEY_IDENTITY_FIELDS, _ATTORNEY_DISCLOSABLE_FIELDS),
}

# Backwards-compatible module-level constants (used by extractor.py, etc.)
IDENTITY_FIELDS = _MEDICAL_IDENTITY_FIELDS
DISCLOSABLE_FIELDS = _MEDICAL_DISCLOSABLE_FIELDS


def get_field_config(oracle_type: str = "medical_board") -> tuple[frozenset[str], frozenset[str]]:
    """Returns (identity_fields, disclosable_fields) for the given oracle type."""
    return _FIELD_CONFIGS.get(oracle_type, _FIELD_CONFIGS["medical_board"])


# ---------------------------------------------------------------------------
# Core filter
# ---------------------------------------------------------------------------

def apply_redaction_filter(
    raw_credential: dict,
    disclosed_fields: list[str],
    oracle_type: str = "medical_board",
) -> dict:
    """
    Props L4 — Applies filter f(X) = X' (section 2.4).

    Args:
        raw_credential:   The raw credential dict from the oracle (all fields).
        disclosed_fields: List of field names the user consented to disclose.
                          Only names from DISCLOSABLE_FIELDS are honoured —
                          requesting identity fields is silently ignored.
        oracle_type:      Which oracle produced the credential (S8: pluggable oracle).
                          Determines which fields are identity vs disclosable.

    Returns:
        {
          "disclosed":        { only the consented, non-identity fields },
          "all_fields":       [ all field names present in raw_credential ],
          "stripped_fields":  [ fields that were removed (identity + non-consented) ],
          "disclosed_fields": [ fields that exited the enclave ],
        }

    The caller passes this entire dict to the attestation layer so the
    certificate can include both what was disclosed and what was stripped.
    """
    identity_fields, disclosable_fields = get_field_config(oracle_type)

    # Normalise disclosed_fields — lowercase, strip whitespace
    consented: set[str] = {f.strip().lower() for f in disclosed_fields}

    # Intersect with allowed disclosable set — identity fields can never be consented to
    allowed_consented: set[str] = consented & disclosable_fields

    all_raw_fields = set(raw_credential.keys())

    # Fields that are being stripped (identity fields + non-consented disclosable fields)
    stripped: list[str] = sorted(
        f for f in all_raw_fields
        if f in identity_fields or f not in allowed_consented
    )

    # Build the disclosed output — only consented, non-identity fields
    disclosed: dict = {
        field: raw_credential[field]
        for field in allowed_consented
        if field in raw_credential
    }

    return {
        "disclosed": disclosed,
        "all_fields": sorted(all_raw_fields),
        "stripped_fields": stripped,
        "disclosed_fields": sorted(disclosed.keys()),
    }


def get_all_disclosable_fields(oracle_type: str = "medical_board") -> list[str]:
    """Returns the list of fields a user is allowed to toggle on Screen 1."""
    _, disclosable = get_field_config(oracle_type)
    return sorted(disclosable)


# ---------------------------------------------------------------------------
# Direct test: python app/redaction.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    sample_credential = {
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

    print("=== Test 1: user discloses specialty + years_active only ===")
    result = apply_redaction_filter(sample_credential, ["specialty", "years_active"])
    print(json.dumps(result, indent=2))

    print("\n=== Test 2: user discloses all four credential facts ===")
    result = apply_redaction_filter(
        sample_credential,
        ["specialty", "years_active", "jurisdiction", "standing"],
    )
    print(json.dumps(result, indent=2))

    print("\n=== Test 3: user tries to disclose identity field (should be ignored) ===")
    result = apply_redaction_filter(sample_credential, ["name", "specialty"])
    print(json.dumps(result, indent=2))
    assert "name" not in result["disclosed"], "FAIL: identity field leaked!"
    print("PASS: identity field correctly blocked")

    # S10 — Attorney oracle tests
    print("\n=== Test 4: attorney oracle — disclose law_school + years_practicing ===")
    attorney_credential = {
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
    result = apply_redaction_filter(
        attorney_credential, ["law_school", "years_practicing", "standing"], oracle_type="attorney"
    )
    print(json.dumps(result, indent=2))
    assert "name" not in result["disclosed"], "FAIL: name leaked!"
    assert "law_school" in result["disclosed"], "FAIL: law_school should be disclosed!"
    print("PASS: attorney redaction working correctly")
