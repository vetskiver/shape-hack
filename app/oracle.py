"""
Props L1 — Oracle Layer (Props paper, section 3.1)
==================================================
Pluggable oracle system. ORACLE_TARGET env var selects the data source:
  medical_board  — Chromium scrapes NY State medical board (default)
  employment     — Mock HR portal returning employment credentials

Both oracle types produce the same envelope format (oracle_authenticated,
data_hash, etc.), so the downstream pipeline (L3 extraction, L4 redaction,
L2 attestation) works identically regardless of source. This is Props as
a protocol: same enclave, same attestation, different oracle.

WHY CHROMIUM INSIDE THE ENCLAVE (medical_board oracle):
- The TLS handshake happens inside the TEE, so the credential data is
  authenticated at the hardware level before it ever touches our code.
- TLS certificate fingerprint pinning is enforced inside the enclave —
  a fake registry cannot impersonate the real one.
- The data hash computed here is included in the TDX attestation quote,
  proving that THIS data (unmodified) is what the enclave processed.

Fetch mode:
  license_lookup — searches op.nysed.gov/verification-search by license number.
  HTML selectors verified against the live portal on 2026-03-16.

Configurable profession via ORACLE_PROFESSION env var (default: Physician).
Supports any NY State licensed profession: Physician, Dentist, Attorney, etc.

The oracle_authenticated flag and data_hash are consumed by the forge endpoint
(L5) to detect data that bypassed the oracle pipeline.
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import ssl
import socket
from datetime import datetime, timezone

# Playwright is only needed for the medical_board oracle (Chromium-in-TEE).
# Lazy-imported inside _fetch_credential_async to avoid import errors when
# running the employment oracle locally without Playwright installed.
# from playwright.async_api import async_playwright, Page

# ---------------------------------------------------------------------------
# Oracle Target Selection (S8 — Pluggable Oracle)
# Props L1 — section 3.1: same pipeline, different data source.
# medical_board = real Chromium scrape of NYSED registry (default)
# employment    = mock HR portal (demo: protocol works for any TLS source)
# ---------------------------------------------------------------------------
ORACLE_TARGET = os.environ.get("ORACLE_TARGET", "medical_board")

# ---------------------------------------------------------------------------
# TLS Fingerprint Pinning
# Props L1 — section 3.1: verify we are talking to the real NYSED registry.
# ---------------------------------------------------------------------------
# SHA-256 fingerprint of www.op.nysed.gov, verified 2026-03-16.
# Update when cert renews (annually):
#   openssl s_client -connect www.op.nysed.gov:443 -servername www.op.nysed.gov \
#     </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout
NYSED_TLS_FINGERPRINT = os.environ.get(
    "NYSED_TLS_FINGERPRINT",
    "0D53B7BB43B892DC70D34143113D16EC7A3628714D0104F193100A792BBC68D8",
)

NYSED_SEARCH_URL = "https://www.op.nysed.gov/verification-search"
NYSED_HOSTNAME = "www.op.nysed.gov"

# ---------------------------------------------------------------------------
# Configurable profession — ORACLE_PROFESSION env var
# Matches the exact text shown in the NYSED portal profession dropdown.
# ---------------------------------------------------------------------------
# Common values (use exact portal text including code):
#   Physician (060)          — medical doctors (MD/DO)
#   Dentist (050)            — dentists
#   Registered Nurse (049)   — RNs
#   Licensed Clinical Social Worker (029)
#   Physical Therapist (073)
#   Pharmacy (032)
#   Psychology (014)
# Default is Physician for the Dr Sarah Chen demo.
ORACLE_PROFESSION = os.environ.get("ORACLE_PROFESSION", "Physician (060)")

# Profession code extracted from the label, e.g. "060" from "Physician (060)"
_PROFESSION_CODE_RE = re.compile(r"\((\d+)\)")


def _get_profession_code(profession_label: str) -> str:
    m = _PROFESSION_CODE_RE.search(profession_label)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# TLS verification
# ---------------------------------------------------------------------------

def get_tls_fingerprint(hostname: str, port: int = 443) -> str:
    """Returns the live SHA-256 fingerprint of the server's TLS certificate."""
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
            return hashlib.sha256(cert_der).hexdigest().upper()


def verify_tls_fingerprint() -> tuple[bool, str]:
    """
    Props L1 — section 3.1: TLS fingerprint verification.
    Returns (True, fingerprint) on match, (False, live_fp) on mismatch.
    SKIP_TLS_VERIFY=true bypasses for local dev only.
    """
    if os.environ.get("SKIP_TLS_VERIFY", "false").lower() == "true":
        return True, "skipped"
    try:
        live = get_tls_fingerprint(NYSED_HOSTNAME)
        pinned = NYSED_TLS_FINGERPRINT.upper().replace(":", "").replace(" ", "")
        return live == pinned, live
    except Exception as e:
        return False, f"error:{e}"


# ---------------------------------------------------------------------------
# Credential decryption
# ---------------------------------------------------------------------------

def decrypt_credentials(encrypted_payload: str) -> dict:
    """
    Decrypts RSA-OAEP encrypted credentials from the user's browser.
    SKIP_ENCRYPTION=true accepts plain JSON for local dev.
    """
    if os.environ.get("SKIP_ENCRYPTION", "false").lower() == "true":
        return json.loads(encrypted_payload)

    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key_pem = os.environ.get("ENCLAVE_PRIVATE_KEY", "").encode()
        if not private_key_pem:
            raise ValueError("ENCLAVE_PRIVATE_KEY not set")

        private_key = load_pem_private_key(private_key_pem, password=None)
        plaintext = private_key.decrypt(
            base64.b64decode(encrypted_payload),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return json.loads(plaintext.decode())
    except Exception as e:
        raise ValueError(f"Credential decryption failed: {e}")


# ---------------------------------------------------------------------------
# Browser automation
# ---------------------------------------------------------------------------

async def _fetch_credential_async(license_number: str, profession: str) -> dict:
    """
    Props L1 — launches headless Chromium and navigates the NYSED portal.

    Form flow confirmed against live portal 2026-03-16:
    1. Select search type "License Number" from first dropdown
    2. Select profession (e.g. "Physician (060)") from second dropdown
    3. Fill #searchInput with 6-digit license number
    4. Click #goButton
    5. Click license number link in results → opens #licenseeDetailModal
    6. Scrape modal with exact id-based selectors
    """
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--single-process",
                "--incognito",
                "--disable-extensions",
            ],
        )
        page = await browser.new_page(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=os.environ.get("SKIP_TLS_VERIFY", "false").lower() == "true",
        )

        try:
            print(f"[oracle] Navigating to {NYSED_SEARCH_URL}")
            await page.goto(NYSED_SEARCH_URL, wait_until="networkidle", timeout=30000)

            # Step 1 — select "License Number" from search-by dropdown
            await page.locator('input[placeholder="Select option"]').nth(0).click()
            await page.wait_for_timeout(500)
            await page.get_by_text("License Number", exact=True).click()
            await page.wait_for_timeout(500)

            # Step 2 — select profession from second dropdown
            await page.locator('input[placeholder="Select option"]').click()
            await page.wait_for_timeout(300)
            # Type the profession name to filter the list
            profession_name = profession.split("(")[0].strip()
            await page.keyboard.type(profession_name)
            await page.wait_for_timeout(500)
            await page.get_by_text(profession, exact=True).click()
            await page.wait_for_timeout(500)

            # Step 3 — fill the six-digit license number
            await page.fill("#searchInput", license_number)
            await page.wait_for_timeout(300)

            # Step 4 — click GO
            await page.click("#goButton")
            await page.wait_for_load_state("networkidle", timeout=15000)
            await page.wait_for_timeout(1500)

            # Step 5 — click license number link to open detail modal
            await page.get_by_text(license_number).first.click()
            await page.wait_for_load_state("networkidle", timeout=15000)
            await page.wait_for_timeout(1500)

            # Step 6 — scrape the modal
            credential = await _scrape_modal(page, license_number, profession)

        finally:
            await browser.close()

    return credential


async def _scrape_modal(page, license_number: str, profession: str) -> dict:
    """
    Scrapes the #licenseeDetailModal that opens after clicking a result.

    Exact HTML structure verified 2026-03-16:
      <span id="name" class="person-name">DOGAN OZGEN MUHSIN</span>
      <dd id="address">      BROOKLYN NY
      <dd id="profession">   Medicine (060)
      <dd id="licenseNumber"> 209311
      <dd id="dateOfLicensure"> January 08, 1998
      <dd id="status">       Registered
      <dd id="registeredThroughDate"> January 31, 2027
      <dd id="schoolName">   TRAKYA UNIVERSITY MEDICAL FACULTY
      <dd id="degreeDate">   September 30, 1986
      <dd id="additionalQualifications"> None
    """
    raw = await page.evaluate("""() => {
        const modal = document.querySelector('#licenseeDetailModal');
        if (!modal) return {};

        const text = id => {
            const el = modal.querySelector('#' + id);
            return el ? el.textContent.trim() : null;
        };

        return {
            name:                    modal.querySelector('span#name.person-name')?.textContent.trim() || null,
            address:                 text('address'),
            profession:              text('profession'),
            license_number:          text('licenseNumber'),
            date_of_licensure:       text('dateOfLicensure'),
            status:                  text('status'),
            registered_through:      text('registeredThroughDate'),
            medical_school:          text('schoolName'),
            degree_date:             text('degreeDate'),
            additional_qualifications: text('additionalQualifications'),
        };
    }""")

    if not raw or not any(raw.values()):
        raise ValueError(
            "Modal scrape returned empty — license not found or portal changed structure. "
            f"License: {license_number}, Profession: {profession}"
        )

    credential = {}

    # Name — convert ALL CAPS to Title Case
    if raw.get("name"):
        credential["name"] = raw["name"].title()

    # Address
    if raw.get("address"):
        credential["address"] = raw["address"].strip()

    # Specialty — strip profession code "(060)" from label
    if raw.get("profession"):
        credential["specialty"] = re.sub(r"\s*\(\d+\)\s*$", "", raw["profession"]).strip()

    # License number
    if raw.get("license_number"):
        credential["license_number"] = raw["license_number"].strip()

    # Standing — normalise to "In good standing" for registered/active
    if raw.get("status"):
        status = raw["status"].strip()
        if status.lower() in ("registered", "active"):
            credential["standing"] = "In good standing"
        else:
            credential["standing"] = status  # e.g. "Suspended", "Revoked"

    # Registration dates
    if raw.get("registered_through"):
        credential["registered_through"] = raw["registered_through"].strip()

    if raw.get("date_of_licensure"):
        credential["initial_registration_date"] = raw["date_of_licensure"].strip()

    # Medical school (identity-adjacent — L4 will strip if user doesn't consent)
    if raw.get("medical_school") and raw["medical_school"] != "None":
        credential["medical_school"] = raw["medical_school"].strip()

    # Degree date
    if raw.get("degree_date"):
        credential["degree_date"] = raw["degree_date"].strip()

    # Additional qualifications
    if raw.get("additional_qualifications") and raw["additional_qualifications"] != "None":
        credential["additional_qualifications"] = raw["additional_qualifications"].strip()

    # Years active — computed from date of licensure
    if "initial_registration_date" in credential:
        try:
            from dateutil.parser import parse as parse_date
            reg_date = parse_date(credential["initial_registration_date"])
            credential["years_active"] = (datetime.now() - reg_date).days // 365
        except Exception:
            pass

    # Jurisdiction is always New York State for NYSED records
    credential["jurisdiction"] = "New York State"

    print(f"[oracle] Scraped {len(credential)} fields — name: {credential.get('name', 'MISSING')}")
    return credential


# ---------------------------------------------------------------------------
# Employment Oracle — Mock HR Portal (S8 — Pluggable Oracle)
# Props L1 — same oracle contract, different data source.
# In production this would scrape a real HR portal (Workday, ADP, etc.)
# using the same Chromium-in-TEE pattern. For the hackathon demo we return
# realistic mock data to show the pipeline is source-agnostic.
# ---------------------------------------------------------------------------

# Realistic employment records keyed by employee_id
_EMPLOYMENT_RECORDS: dict[str, dict] = {
    "EMP-7291": {
        "employee_name": "Marcus Webb",
        "employee_id": "EMP-7291",
        "ssn_last_four": "4821",
        "company": "Major Technology Company",
        "tier": "FAANG",
        "role": "Senior Software Engineer",
        "team": "Infrastructure",
        "department": "Platform Engineering",
        "years_tenure": 7,
        "employment_status": "Current employee",
        "start_date": "March 15, 2019",
        "office_location": "San Francisco, CA",
        "manager_name": "Jennifer Liu",
    },
    "EMP-3044": {
        "employee_name": "Priya Chakraborty",
        "employee_id": "EMP-3044",
        "ssn_last_four": "9137",
        "company": "Global Investment Bank",
        "tier": "Bulge Bracket",
        "role": "Vice President, Risk Analytics",
        "team": "Quantitative Risk",
        "department": "Risk Management",
        "years_tenure": 11,
        "employment_status": "Current employee",
        "start_date": "June 01, 2015",
        "office_location": "New York, NY",
        "manager_name": "David Rothstein",
    },
    "DEFAULT": {
        "employee_name": "Anonymous Employee",
        "employee_id": "EMP-0000",
        "ssn_last_four": "0000",
        "company": "Major Technology Company",
        "tier": "FAANG",
        "role": "Senior Software Engineer",
        "team": "Infrastructure",
        "department": "Platform Engineering",
        "years_tenure": 7,
        "employment_status": "Current employee",
        "start_date": "January 10, 2019",
        "office_location": "Seattle, WA",
        "manager_name": "Redacted Manager",
    },
}


def _fetch_employment_credential(credentials: dict) -> dict:
    """
    Props L1 — Mock employment oracle (section 3.1).
    Same oracle envelope contract as the medical board oracle.

    In production: Chromium authenticates against Workday/ADP HR portal,
    scrapes the authenticated employment record. Same TLS pinning, same
    data_hash, same oracle_authenticated flag.

    For hackathon: returns realistic mock data from _EMPLOYMENT_RECORDS.
    """
    employee_id = credentials.get("employee_id", "DEFAULT")
    record = _EMPLOYMENT_RECORDS.get(employee_id, _EMPLOYMENT_RECORDS["DEFAULT"]).copy()

    print(f"[oracle/employment] Fetching employment record for {employee_id}")

    # Props L1/L5 — data integrity hash (same as medical board oracle)
    raw_json = json.dumps(record, sort_keys=True)
    data_hash = hashlib.sha256(raw_json.encode()).hexdigest()

    return {
        "credential": record,
        "oracle_authenticated": True,
        "oracle_source": "hr-portal.internal.example.com",
        "oracle_tls_fingerprint": hashlib.sha256(b"mock-hr-portal-tls-cert").hexdigest().upper(),
        "data_hash": data_hash,
        "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
        "fetch_mode": "employee_lookup",
        "oracle_type": "employment",
    }


# ---------------------------------------------------------------------------
# Main entrypoint — medical board oracle
# ---------------------------------------------------------------------------

async def _oracle_main(credentials: dict) -> dict:
    """
    Props L1 — runs TLS pin check then fetches the credential.
    """
    license_number = credentials.get("license_number", "")
    if not license_number:
        raise ValueError("license_number is required")

    profession = credentials.get("profession", ORACLE_PROFESSION)

    # Props L1 — TLS fingerprint verification (section 3.1)
    fingerprint_ok, live_fingerprint = verify_tls_fingerprint()
    if not fingerprint_ok:
        raise ValueError(
            f"TLS fingerprint mismatch on {NYSED_HOSTNAME}. "
            f"Expected: {NYSED_TLS_FINGERPRINT}, Got: {live_fingerprint}. "
            f"This is not the authoritative NY State Medical Board registry."
        )
    print(f"[oracle] TLS fingerprint verified ({live_fingerprint[:16]}...)")

    raw_credential = await _fetch_credential_async(license_number, profession)

    if not raw_credential:
        raise ValueError("Oracle returned empty credential")

    # Props L1/L5 — data integrity hash (section 3.1 + 2.3)
    raw_json = json.dumps(raw_credential, sort_keys=True)
    data_hash = hashlib.sha256(raw_json.encode()).hexdigest()

    return {
        "credential": raw_credential,
        "oracle_authenticated": True,
        "oracle_source": NYSED_HOSTNAME,
        "oracle_tls_fingerprint": live_fingerprint,
        "data_hash": data_hash,
        "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
        "fetch_mode": "license_lookup",
        "profession": profession,
        "oracle_type": "medical_board",
    }


def fetch_credential(credentials_payload, oracle_target: str | None = None) -> dict:
    """
    Props L1 — Oracle layer (section 3.1). Public entrypoint.
    Dispatches to the correct oracle based on ORACLE_TARGET env var
    (or the oracle_target parameter override).

    Args:
        credentials_payload: dict with credentials or RSA-encrypted JSON string.
            medical_board: {license_number, profession (optional)}
            employment:    {employee_id (optional)}
        oracle_target: override for ORACLE_TARGET env var (for testing)

    Returns oracle envelope with: credential, oracle_authenticated, oracle_source,
        oracle_tls_fingerprint, data_hash, fetch_timestamp, oracle_type
    """
    if isinstance(credentials_payload, dict):
        credentials = credentials_payload
    else:
        credentials = decrypt_credentials(credentials_payload)

    target = (oracle_target or ORACLE_TARGET).strip().lower()

    if target == "employment":
        return _fetch_employment_credential(credentials)
    elif target == "medical_board":
        return asyncio.run(_oracle_main(credentials))
    else:
        raise ValueError(
            f"Unknown ORACLE_TARGET '{target}'. "
            f"Valid targets: medical_board, employment"
        )


# ---------------------------------------------------------------------------
# Direct test: python app/oracle.py
# Set ORACLE_TARGET=employment to test employment oracle.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    target = os.environ.get("ORACLE_TARGET", "medical_board")
    print(f"[oracle] Testing oracle: ORACLE_TARGET={target}")

    if target == "employment":
        employee_id = os.environ.get("TEST_EMPLOYEE_ID", "EMP-7291")
        print(f"[oracle] Employee ID: {employee_id}")
        try:
            result = fetch_credential({"employee_id": employee_id})
            print("[oracle] SUCCESS:")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"[oracle] FAILED: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        license_number = os.environ.get("TEST_LICENSE_NUMBER", "209311")
        profession = os.environ.get("ORACLE_PROFESSION", "Physician (060)")
        print(f"[oracle] license={license_number}, profession={profession}")
        try:
            result = fetch_credential({"license_number": license_number, "profession": profession})
            print("[oracle] SUCCESS:")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"[oracle] FAILED: {e}", file=sys.stderr)
            sys.exit(1)
