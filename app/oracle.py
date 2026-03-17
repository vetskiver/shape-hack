"""
Props L1 — Oracle Layer (Props paper, section 3.1)
==================================================
Chromium runs inside the Intel TDX enclave and authenticates against the
NY State Office of the Professions registry. The licensing board sees a
normal browser — it never knows Props touched their registry.

WHY CHROMIUM INSIDE THE ENCLAVE:
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

from playwright.async_api import async_playwright, Page

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
        page: Page = await browser.new_page(
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


async def _scrape_modal(page: Page, license_number: str, profession: str) -> dict:
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
# Main entrypoint
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
    }


def fetch_credential(credentials_payload) -> dict:
    """
    Props L1 — Oracle layer (section 3.1). Public entrypoint.

    Args:
        credentials_payload: dict with {license_number, profession (optional)}
                             or RSA-encrypted JSON string.

    Returns:
        {
          credential: {
            name, address, specialty, license_number, standing, years_active,
            jurisdiction, initial_registration_date, registered_through,
            medical_school, degree_date
          },
          oracle_authenticated: True,
          oracle_source: "www.op.nysed.gov",
          oracle_tls_fingerprint: "...",
          data_hash: "sha256...",
          fetch_timestamp: "iso8601",
          profession: "Physician (060)"
        }
    """
    if isinstance(credentials_payload, dict):
        credentials = credentials_payload
    else:
        credentials = decrypt_credentials(credentials_payload)

    return asyncio.run(_oracle_main(credentials))


# ---------------------------------------------------------------------------
# Direct test: python app/oracle.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    license_number = os.environ.get("TEST_LICENSE_NUMBER", "209311")
    profession = os.environ.get("ORACLE_PROFESSION", "Physician (060)")
    print(f"[oracle] Testing oracle: license={license_number}, profession={profession}")

    try:
        result = fetch_credential({"license_number": license_number, "profession": profession})
        print("[oracle] SUCCESS:")
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"[oracle] FAILED: {e}", file=sys.stderr)
        sys.exit(1)
