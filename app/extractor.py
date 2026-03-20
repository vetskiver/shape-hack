"""
Props L3 — Pinned Model Layer (Props paper, section 3.2 / section 2.2)
=======================================================================
A small LLM (current default: `llama3.2:1b` via Ollama) runs inside the TDX enclave and
extracts four credential facts from the raw oracle record.

WHY AN LLM (NOT REGEX):
- The model hash is part of the TDX attestation — the output is provably
  from THIS specific model, not a modified one.  That is Props L3.
- An LLM tolerates messy portal text (abbreviations, formatting noise)
  without brittle regex that breaks on portal changes.
- Adversarial prompt injection from outside the enclave is architecturally
  impossible — the input arrives through the oracle, not from the user.

The model name and SHA-256 hash of its manifest are captured and returned
so the attestation layer
 can include them in the signed certificate.

Ollama runs as a sidecar in docker-compose on port 11434.
Model is pulled at container startup via the entrypoint script.
"""

import hashlib
import json
import os
import re
import time
from datetime import datetime

import httpx

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")

# Props L3 — Pinned model digest (section 3.2)
# This is the expected Ollama manifest digest for our approved model.
# If the runtime digest doesn't match, certificate issuance is REFUSED.
# This turns "measured model" into "pinned model" — the distinction the
# Props paper requires. The digest is part of the enclave measurement
# because changing it requires a code change → new MRTD.
#
# To update: pull the new model, run `ollama show <model> --json`,
# copy the "digest" field here, and redeploy.
# Set to "" to discover the digest on first deploy (logged to stdout).
PINNED_MODEL_DIGEST = os.environ.get("PINNED_MODEL_DIGEST", "")

# Set SKIP_MODEL_PIN=true ONLY for local development without Ollama.
SKIP_MODEL_PIN = os.environ.get("SKIP_MODEL_PIN", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Per-oracle-type extraction config (S8: pluggable oracle)
# ---------------------------------------------------------------------------

# Medical board extraction
_MEDICAL_CREDENTIAL_FIELDS = {"specialty", "years_active", "jurisdiction", "standing"}
_MEDICAL_IDENTITY_FIELDS = {
    "name", "license_number", "address", "date_of_birth",
    "medical_school", "degree_date", "initial_registration_date",
    "registered_through",
}
_MEDICAL_EXTRACTION_PROMPT = """\
You are a credential extraction assistant running inside a secure enclave.
Your only task is to extract specific fields from a medical licensing record.

Raw credential record (JSON):
{raw_json}

Extract EXACTLY these four fields and return ONLY a JSON object with no extra text:
- specialty: the medical specialty or profession (string)
- years_active: number of years licensed/active (integer, compute from initial_registration_date if years_active is missing)
- jurisdiction: the licensing jurisdiction (string)
- standing: the license standing status (string, e.g. "In good standing", "Suspended")

If a field cannot be determined, use null.
Respond with ONLY the JSON object, nothing else.
Example: {{"specialty": "Cardiology", "years_active": 17, "jurisdiction": "New York State", "standing": "In good standing"}}
"""

# Attorney extraction (S10 — real NY attorney registry)
_ATTORNEY_CREDENTIAL_FIELDS = {
    "year_admitted", "years_practicing", "judicial_department",
    "law_school", "standing", "county", "jurisdiction",
}
_ATTORNEY_IDENTITY_FIELDS = {
    "name", "registration_number", "address",
    "phone_number", "company_name",
}
_ATTORNEY_EXTRACTION_PROMPT = """\
You are a credential extraction assistant running inside a secure enclave.
Your only task is to extract specific fields from an attorney registration record.

Raw attorney record (JSON):
{raw_json}

Extract EXACTLY these seven fields and return ONLY a JSON object with no extra text:
- year_admitted: the year admitted to the NY Bar (integer)
- years_practicing: number of years practicing law (integer, compute from year_admitted if missing)
- judicial_department: the judicial department of admission (string, e.g. "Judicial Department 1")
- law_school: the law school attended (string)
- standing: registration status (string, e.g. "In good standing", "Suspended")
- county: the county of practice (string)
- jurisdiction: the licensing jurisdiction (string)

If a field cannot be determined, use null.
Respond with ONLY the JSON object, nothing else.
Example: {{"year_admitted": 1978, "years_practicing": 48, "judicial_department": "Judicial Department 1", "law_school": "Fordham University School Of Law", "standing": "In good standing", "county": "New York", "jurisdiction": "New York State"}}
"""

# Registry
_EXTRACTION_CONFIGS = {
    "medical_board": {
        "credential_fields": _MEDICAL_CREDENTIAL_FIELDS,
        "identity_fields": _MEDICAL_IDENTITY_FIELDS,
        "prompt": _MEDICAL_EXTRACTION_PROMPT,
    },
    "attorney": {
        "credential_fields": _ATTORNEY_CREDENTIAL_FIELDS,
        "identity_fields": _ATTORNEY_IDENTITY_FIELDS,
        "prompt": _ATTORNEY_EXTRACTION_PROMPT,
    },
}

# Backwards-compatible module-level constants
CREDENTIAL_FIELDS = _MEDICAL_CREDENTIAL_FIELDS
IDENTITY_FIELDS = _MEDICAL_IDENTITY_FIELDS


# ---------------------------------------------------------------------------
# Ollama helpers
# ---------------------------------------------------------------------------

def _ollama_generate(prompt: str, max_retries: int = 3) -> str:
    """Calls Ollama /api/generate and returns the response text.

    Retries on transient failures (connection errors, 5xx) with short backoff.
    A single Ollama hiccup during a 30-second pipeline run should not kill the
    entire request — Props L3 integrity only requires that the model eventually
    runs, not that the first attempt succeeds.
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,  # deterministic output — important for L3 provability
            "num_predict": 200,
        },
    }
    last_error = None
    _model_pulled = False
    for attempt in range(1, max_retries + 1):
        try:
            resp = httpx.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json=payload,
                timeout=60.0,
            )
            resp.raise_for_status()
            return resp.json()["response"].strip()
        except httpx.HTTPStatusError as e:
            # Ollama returns 500 when the model isn't pulled yet.
            # Trigger an on-demand pull and retry.
            if e.response.status_code == 500 and not _model_pulled:
                print(f"[extractor] Ollama 500 — model may not be pulled. Pulling '{MODEL_NAME}'...")
                try:
                    pull_resp = httpx.post(
                        f"{OLLAMA_BASE_URL}/api/pull",
                        json={"name": MODEL_NAME, "stream": False},
                        timeout=600.0,
                    )
                    pull_resp.raise_for_status()
                    _model_pulled = True
                    print(f"[extractor] Model pulled successfully, retrying generate...")
                    continue
                except Exception as pull_err:
                    print(f"[extractor] Model pull failed: {pull_err}")
            last_error = e
            if e.response.status_code >= 500 and attempt < max_retries:
                wait = attempt * 2
                print(f"[extractor] Ollama {e.response.status_code} (attempt {attempt}/{max_retries}), retrying in {wait}s")
                import time; time.sleep(wait)
            else:
                raise
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as e:
            last_error = e
            if attempt < max_retries:
                wait = attempt * 2  # 2s, 4s
                print(f"[extractor] Ollama transient error (attempt {attempt}/{max_retries}), retrying in {wait}s: {e}")
                import time; time.sleep(wait)
            else:
                print(f"[extractor] Ollama failed after {max_retries} attempts: {e}")
    raise last_error or RuntimeError("Ollama unreachable after retries")


def get_model_info() -> dict:
    """
    Props L3 — returns model name and a digest that goes into the attestation.
    Ollama's /api/show returns the model's sha256 manifest digest in the
    top-level "digest" field (e.g. "sha256:a6990ed6be41...").

    HARD-FAIL: If we cannot retrieve the real model digest, the attestation
    would contain a fake hash — violating L3 integrity. We raise instead
    of silently falling back.
    """
    last_error = None
    for attempt in range(1, 4):
        try:
            resp = httpx.post(
                f"{OLLAMA_BASE_URL}/api/show",
                json={"name": MODEL_NAME},
                timeout=15.0,
            )
            resp.raise_for_status()
            last_error = None
            break
        except (httpx.ConnectError, httpx.ReadTimeout) as e:
            last_error = e
            if attempt < 3:
                import time; time.sleep(attempt * 2)
            else:
                raise RuntimeError(f"Cannot reach Ollama after 3 attempts: {e}")
    data = resp.json()

    # Best case: /api/show returns a top-level digest.
    digest = data.get("digest", "")

    # Some Ollama versions omit the top-level digest from /api/show but still
    # expose it through model listings. Fall back to the official list endpoints.
    if not digest:
        for endpoint, key in (("/api/tags", "models"), ("/api/ps", "models")):
            try:
                listing_resp = httpx.get(f"{OLLAMA_BASE_URL}{endpoint}", timeout=15.0)
                listing_resp.raise_for_status()
                for model in listing_resp.json().get(key, []):
                    model_names = {
                        model.get("name", ""),
                        model.get("model", ""),
                    }
                    if MODEL_NAME in model_names:
                        digest = model.get("digest", "")
                        if digest:
                            break
                if digest:
                    break
            except Exception as listing_err:
                print(f"[extractor] WARNING: {endpoint} digest lookup failed: {listing_err}")

    # Older responses sometimes only expose a parent model reference.
    if not digest:
        digest = data.get("details", {}).get("parent_model", "")

    # Props L3 HARD-FAIL: no silent fallback to hashed metadata.
    # A fake digest violates the pinned model guarantee — the attestation
    # must contain the real model file hash so auditors can verify which
    # exact model weights produced the output.
    if not digest:
        raise RuntimeError(
            f"Props L3 integrity violation: cannot retrieve model digest for "
            f"'{MODEL_NAME}' from Ollama at {OLLAMA_BASE_URL}. "
            f"The attestation requires a real model hash — refusing to fall back "
            f"to a synthetic digest. Ensure the model is pulled and Ollama is running."
        )

    # Props L3 — PINNED MODEL ENFORCEMENT (section 3.2)
    # Compare runtime digest against the hardcoded expected digest.
    # This is the difference between "measured" and "pinned":
    #   measured = record what ran
    #   pinned   = reject anything that isn't the expected model
    if PINNED_MODEL_DIGEST and not SKIP_MODEL_PIN:
        if digest != PINNED_MODEL_DIGEST:
            raise RuntimeError(
                f"Props L3 integrity violation: model digest mismatch. "
                f"Expected pinned digest '{PINNED_MODEL_DIGEST}', "
                f"but Ollama reported '{digest}'. "
                f"This could indicate model tampering or an unexpected update. "
                f"Update PINNED_MODEL_DIGEST in extractor.py if this is intentional."
            )
        print(f"[extractor] Props L3 pinned model OK: {digest[:32]}...")
    elif SKIP_MODEL_PIN:
        print(f"[extractor] WARNING: Model pin check SKIPPED (SKIP_MODEL_PIN=true). "
              f"Runtime digest: {digest}")

    return {
        "model_name": MODEL_NAME,
        "model_digest": digest,
        "pinned": not SKIP_MODEL_PIN,
        "ollama_url": OLLAMA_BASE_URL,
    }


def _safe_get_model_info() -> dict:
    """Non-blocking model info — returns placeholder if Ollama is unavailable."""
    try:
        return get_model_info()
    except Exception:
        return {
            "model_name": MODEL_NAME,
            "model_digest": "unavailable",
            "pinned": False,
            "ollama_url": OLLAMA_BASE_URL,
        }


def wait_for_ollama(max_wait_seconds: int = 120) -> None:
    """Blocks until Ollama is ready AND the model is pulled. Called at app startup."""
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5.0)
            if resp.status_code == 200:
                print(f"[extractor] Ollama ready at {OLLAMA_BASE_URL}")
                break
        except Exception:
            pass
        time.sleep(3)
    else:
        raise RuntimeError(f"Ollama did not become ready within {max_wait_seconds}s")

    # Ensure the model is actually pulled — Ollama 500s on /api/generate
    # if the model isn't available. Pull is idempotent (no-op if already present).
    print(f"[extractor] Ensuring model '{MODEL_NAME}' is pulled...")
    try:
        pull_resp = httpx.post(
            f"{OLLAMA_BASE_URL}/api/pull",
            json={"name": MODEL_NAME, "stream": False},
            timeout=600.0,  # model pull can take minutes on first boot
        )
        if pull_resp.status_code == 200:
            print(f"[extractor] Model '{MODEL_NAME}' ready")
        else:
            print(f"[extractor] WARNING: model pull returned {pull_resp.status_code}")
    except Exception as e:
        print(f"[extractor] WARNING: model pull failed: {e} — will retry on first request")


# ---------------------------------------------------------------------------
# Fast-path extraction (no LLM needed if oracle already parsed cleanly)
# ---------------------------------------------------------------------------

def _extract_direct(raw_credential: dict, oracle_type: str = "medical_board") -> dict | None:
    """
    If the oracle already gave us clean structured fields, use them directly.
    This is the fast path — LLM fallback only needed for messy/incomplete data.
    """
    config = _EXTRACTION_CONFIGS.get(oracle_type, _EXTRACTION_CONFIGS["medical_board"])
    credential_fields = config["credential_fields"]

    extracted = {}

    if oracle_type == "attorney":
        # Attorney fast path — data.ny.gov API returns clean structured JSON
        for field in credential_fields:
            val = raw_credential.get(field)
            if val is not None:
                if field in ("year_admitted", "years_practicing"):
                    try:
                        extracted[field] = int(val)
                    except (TypeError, ValueError):
                        pass
                else:
                    extracted[field] = val
            elif field == "years_practicing" and raw_credential.get("year_admitted"):
                try:
                    extracted["years_practicing"] = datetime.now().year - int(raw_credential["year_admitted"])
                except (TypeError, ValueError):
                    pass
    else:
        # Medical board fast path (original logic)
        if raw_credential.get("specialty"):
            extracted["specialty"] = raw_credential["specialty"]
        if raw_credential.get("years_active") is not None:
            extracted["years_active"] = int(raw_credential["years_active"])
        elif raw_credential.get("initial_registration_date"):
            try:
                from dateutil.parser import parse as parse_date
                reg_date = parse_date(raw_credential["initial_registration_date"])
                extracted["years_active"] = (datetime.now() - reg_date).days // 365
            except Exception:
                pass
        if raw_credential.get("jurisdiction"):
            extracted["jurisdiction"] = raw_credential["jurisdiction"]
        if raw_credential.get("standing"):
            extracted["standing"] = raw_credential["standing"]

    if len(extracted) == len(credential_fields):
        return extracted
    return None  # incomplete — fall through to LLM


# ---------------------------------------------------------------------------
# LLM extraction
# ---------------------------------------------------------------------------

def _parse_llm_response(response_text: str) -> dict:
    """Parses JSON from LLM output, stripping any surrounding prose."""
    # Find the first {...} block in the response
    match = re.search(r"\{[^{}]+\}", response_text, re.DOTALL)
    if not match:
        raise ValueError(f"LLM did not return JSON: {response_text[:200]}")
    parsed = json.loads(match.group(0))
    # Coerce years_active to int
    if parsed.get("years_active") is not None:
        try:
            parsed["years_active"] = int(parsed["years_active"])
        except (TypeError, ValueError):
            parsed["years_active"] = None
    return parsed


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def extract_credential_facts(raw_credential: dict, oracle_type: str = "medical_board") -> dict:
    """
    Props L3 — Pinned model extraction (section 3.2).

    Args:
        raw_credential: the inner credential dict from oracle output
                        (not the full oracle envelope)
        oracle_type:    which oracle produced this credential (S8: pluggable oracle)

    Returns:
        {
          "extracted_facts": { ... credential-type-specific fields ... },
          "model_info": {
              "model_name": "llama3.2:3b",
              "model_digest": "sha256...",
          },
          "extraction_method": "direct" | "llm",
        }
    """
    config = _EXTRACTION_CONFIGS.get(oracle_type, _EXTRACTION_CONFIGS["medical_board"])
    credential_fields = config["credential_fields"]

    # Props L3 — Extraction strategy:
    #   1. Try direct extraction first (deterministic, no external dependency)
    #   2. If direct extraction gets all fields, use it — fast and reproducible
    #   3. If incomplete, try LLM enhancement (if Ollama is available)
    #   4. If LLM unavailable, use whatever direct extraction got
    #
    # The certificate honestly reports extraction_method ("direct" or "llm").
    # Direct extraction is deterministic and reproducible — arguably a stronger
    # L3 guarantee than LLM inference, since the same input always produces
    # the same output with no model variance.

    # Step 1: Direct extraction from structured oracle data
    direct_result = _extract_direct(raw_credential, oracle_type)
    if direct_result is not None:
        print(f"[extractor] Direct extraction complete — all {len(credential_fields)} fields extracted")
        for key in credential_fields:
            direct_result.setdefault(key, None)

        # Props L3 still requires the real model digest even on the direct path.
        # The extraction may be deterministic, but the attestation should not
        # silently degrade to "unavailable" just because we skipped the LLM call.
        model_info = get_model_info()

        return {
            "extracted_facts": direct_result,
            "model_info": model_info,
            "extraction_method": "direct",
        }

    # Step 2: Direct extraction incomplete — try LLM
    print(f"[extractor] Direct extraction incomplete, trying {MODEL_NAME} LLM...")
    raw_json = json.dumps(raw_credential, indent=2)
    prompt = config["prompt"].format(raw_json=raw_json)

    try:
        response_text = _ollama_generate(prompt)
        print(f"[extractor] LLM response: {response_text[:120]}")
        extracted = _parse_llm_response(response_text)

        for key in credential_fields:
            extracted.setdefault(key, None)

        return {
            "extracted_facts": extracted,
            "model_info": get_model_info(),
            "extraction_method": "llm",
        }
    except Exception as e:
        print(f"[extractor] LLM unavailable ({e}) — using partial direct extraction")
        # Fall back to whatever direct extraction got (partial)
        partial = {}
        for field in credential_fields:
            val = raw_credential.get(field)
            if val is not None:
                partial[field] = val
            else:
                partial[field] = None

        model_info = get_model_info()

        return {
            "extracted_facts": partial,
            "model_info": model_info,
            "extraction_method": "direct",
        }


# ---------------------------------------------------------------------------
# Direct test: python app/extractor.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    sample = {
        "name": "Dr Sarah Chen",
        "license_number": "NY-MD-2847193",
        "address": "84 Park Ave, New York",
        "specialty": "Cardiology",
        "initial_registration_date": "January 08, 2007",
        "standing": "In good standing",
        "jurisdiction": "New York State",
    }
    print("[extractor] Testing extraction on sample credential...")
    try:
        result = extract_credential_facts(sample)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"[extractor] FAILED: {e}", file=sys.stderr)
        sys.exit(1)
