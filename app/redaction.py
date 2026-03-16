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
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Field classification
# ---------------------------------------------------------------------------

# Identity fields — ALWAYS stripped. Never exit the enclave.
# Props section 2.4: the filter must remove personally identifiable information.
IDENTITY_FIELDS: frozenset[str] = frozenset({
    "name",
    "license_number",
    "address",
    "date_of_birth",
    "medical_school",
    "degree_date",
    "initial_registration_date",
    "registered_through",
})

# Credential facts — the only fields that CAN be disclosed (user controls which)
DISCLOSABLE_FIELDS: frozenset[str] = frozenset({
    "specialty",
    "years_active",
    "jurisdiction",
    "standing",
})


# ---------------------------------------------------------------------------
# Core filter
# ---------------------------------------------------------------------------

def apply_redaction_filter(
    raw_credential: dict,
    disclosed_fields: list[str],
) -> dict:
    """
    Props L4 — Applies filter f(X) = X' (section 2.4).

    Args:
        raw_credential:   The raw credential dict from the oracle (all fields).
        disclosed_fields: List of field names the user consented to disclose.
                          Only names from DISCLOSABLE_FIELDS are honoured —
                          requesting identity fields is silently ignored.

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
    # Normalise disclosed_fields — lowercase, strip whitespace
    consented: set[str] = {f.strip().lower() for f in disclosed_fields}

    # Intersect with allowed disclosable set — identity fields can never be consented to
    allowed_consented: set[str] = consented & DISCLOSABLE_FIELDS

    all_raw_fields = set(raw_credential.keys())

    # Fields that are being stripped (identity fields + non-consented disclosable fields)
    stripped: list[str] = sorted(
        f for f in all_raw_fields
        if f in IDENTITY_FIELDS or f not in allowed_consented
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


def get_all_disclosable_fields() -> list[str]:
    """Returns the list of fields a user is allowed to toggle on Screen 1."""
    return sorted(DISCLOSABLE_FIELDS)


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
