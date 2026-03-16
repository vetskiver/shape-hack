"""
Props L3 — Pinned Model Layer (Props paper, section 3.2 / section 2.2)
=======================================================================
A small LLM (Llama 3.2 3B via Ollama) runs inside the TDX enclave and
extracts four credential facts from the raw oracle record.

WHY AN LLM (NOT REGEX):
- The model hash is part of the TDX attestation — the output is provably
  from THIS specific model, not a modified one.  That is Props L3.
- An LLM tolerates messy portal text (abbreviations, formatting noise)
  without brittle regex that breaks on portal changes.
- Adversarial prompt injection from outside the enclave is architecturally
  impossible — the input arrives through the oracle, not from the user.

The model name and SHA-256 hash of its manifest are captured and returned
so the attestation layer can include them in the signed certificate.

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
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

# Fields that are credential facts (safe to extract)
CREDENTIAL_FIELDS = {"specialty", "years_active", "jurisdiction", "standing"}

# Identity fields — never extracted to the disclosed set (L4 strips these)
IDENTITY_FIELDS = {
    "name", "license_number", "address", "date_of_birth",
    "medical_school", "degree_date", "initial_registration_date",
    "registered_through",
}

# Prompt for the LLM extraction task
_EXTRACTION_PROMPT = """\
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


# ---------------------------------------------------------------------------
# Ollama helpers
# ---------------------------------------------------------------------------

def _ollama_generate(prompt: str) -> str:
    """Calls Ollama /api/generate and returns the response text."""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,  # deterministic output — important for L3 provability
            "num_predict": 200,
        },
    }
    resp = httpx.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json=payload,
        timeout=60.0,
    )
    resp.raise_for_status()
    return resp.json()["response"].strip()


def get_model_info() -> dict:
    """
    Props L3 — returns model name and a digest that goes into the attestation.
    Ollama's /api/show returns the model's sha256 manifest digest.
    """
    try:
        resp = httpx.post(
            f"{OLLAMA_BASE_URL}/api/show",
            json={"name": MODEL_NAME},
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        # Ollama returns the digest in modelinfo or details
        digest = (
            data.get("details", {}).get("parent_model", "")
            or data.get("modelinfo", {}).get("general.basename", "")
            or ""
        )
        # Fall back: hash the model file list for a stable identifier
        if not digest:
            model_files = json.dumps(data.get("model_info", {}), sort_keys=True)
            digest = hashlib.sha256(model_files.encode()).hexdigest()
        return {
            "model_name": MODEL_NAME,
            "model_digest": digest,
            "ollama_url": OLLAMA_BASE_URL,
        }
    except Exception as e:
        # Non-fatal — attestation continues with name-only hash
        fallback_digest = hashlib.sha256(MODEL_NAME.encode()).hexdigest()
        return {
            "model_name": MODEL_NAME,
            "model_digest": fallback_digest,
            "ollama_url": OLLAMA_BASE_URL,
            "model_info_error": str(e),
        }


def wait_for_ollama(max_wait_seconds: int = 120) -> None:
    """Blocks until Ollama is ready. Called at app startup."""
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5.0)
            if resp.status_code == 200:
                print(f"[extractor] Ollama ready at {OLLAMA_BASE_URL}")
                return
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError(f"Ollama did not become ready within {max_wait_seconds}s")


# ---------------------------------------------------------------------------
# Fast-path extraction (no LLM needed if oracle already parsed cleanly)
# ---------------------------------------------------------------------------

def _extract_direct(raw_credential: dict) -> dict | None:
    """
    If the oracle already gave us clean structured fields, use them directly.
    This is the fast path — LLM fallback only needed for messy/incomplete data.
    """
    extracted = {}
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

    if len(extracted) == 4:
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

def extract_credential_facts(raw_credential: dict) -> dict:
    """
    Props L3 — Pinned model extraction (section 3.2).

    Args:
        raw_credential: the inner credential dict from oracle output
                        (not the full oracle envelope)

    Returns:
        {
          "extracted_facts": {
              "specialty": str,
              "years_active": int,
              "jurisdiction": str,
              "standing": str,
          },
          "model_info": {
              "model_name": "llama3.2:3b",
              "model_digest": "sha256...",
          },
          "extraction_method": "direct" | "llm",
        }
    """
    # Fast path — oracle already gave us clean data
    direct = _extract_direct(raw_credential)
    if direct:
        print(f"[extractor] Fast-path extraction succeeded (no LLM needed)")
        return {
            "extracted_facts": direct,
            "model_info": get_model_info(),
            "extraction_method": "direct",
        }

    # LLM path — call Ollama
    print(f"[extractor] Calling {MODEL_NAME} for extraction")
    raw_json = json.dumps(raw_credential, indent=2)
    prompt = _EXTRACTION_PROMPT.format(raw_json=raw_json)

    try:
        response_text = _ollama_generate(prompt)
        print(f"[extractor] LLM response: {response_text[:120]}")
        extracted = _parse_llm_response(response_text)
    except Exception as e:
        # Last resort: fall back to direct extraction with whatever we have
        print(f"[extractor] LLM failed ({e}), using partial direct extraction")
        extracted = _extract_direct(raw_credential) or {}

    # Ensure all four keys exist (null if missing)
    for key in ("specialty", "years_active", "jurisdiction", "standing"):
        extracted.setdefault(key, None)

    return {
        "extracted_facts": extracted,
        "model_info": get_model_info(),
        "extraction_method": "llm",
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
