"""
Props L1 — Oracle Layer (Props paper, section 3.1)
==================================================
Pluggable oracle system. ORACLE_TARGET env var selects the data source:
  medical_board  — Chromium scrapes NY State medical board (default)
  attorney       — Real NY attorney registry via data.ny.gov Open Data API

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

WHY data.ny.gov API (attorney oracle):
- Same TLS pinning pattern — data.ny.gov fingerprint pinned inside enclave.
- NY Open Data Socrata API returns real attorney registration records.
- No scraping needed — structured JSON from an authoritative government source.
- Demonstrates that Props works with any TLS data source (web scrape OR API).

Fetch mode:
  license_lookup    — searches op.nysed.gov/verification-search by license number.
  attorney_lookup   — queries data.ny.gov/resource/eqw2-r5nb.json by registration number.
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
# running the attorney oracle locally without Playwright installed.
# from playwright.async_api import async_playwright, Page

# ---------------------------------------------------------------------------
# Oracle Target Selection (S8 — Pluggable Oracle)
# Props L1 — section 3.1: same pipeline, different data source.
# medical_board = real Chromium scrape of NYSED registry (default)
# attorney      = real NY attorney registry via data.ny.gov Socrata API
# ---------------------------------------------------------------------------
ORACLE_TARGET = os.environ.get("ORACLE_TARGET", "medical_board")

# ---------------------------------------------------------------------------
# TLS Fingerprint Pinning
# Props L1 — section 3.1: verify we are talking to the real NYSED registry.
# ---------------------------------------------------------------------------
# SHA-256 fingerprint of www.op.nysed.gov, verified 2026-03-16.
# HARDCODED in source code so it is part of the Docker image and therefore
# part of the TDX enclave measurement (MRTD). An operator cannot change the
# pinned registry without changing the code, which changes the measurement,
# which changes the enclave-derived signing key, which invalidates all
# previously issued certificates. This is the L1 trust anchor.
#
# To update when the cert renews (annually):
#   openssl s_client -connect www.op.nysed.gov:443 -servername www.op.nysed.gov \
#     </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout
# Then rebuild and redeploy the Docker image.
NYSED_TLS_FINGERPRINT = "0D53B7BB43B892DC70D34143113D16EC7A3628714D0104F193100A792BBC68D8"

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
# Production safety — SKIP_* flags must not be used inside a real TDX enclave
# ---------------------------------------------------------------------------

def _in_real_enclave() -> bool:
    """Detect if we are running inside a real Phala Cloud TDX enclave."""
    try:
        from dstack_sdk import DstackClient
        client = DstackClient()
        client.get_key("/props-oracle", "enclave-check")
        return True
    except Exception:
        return False

# Enforce at module load: if dstack is available (real enclave), SKIP flags are forbidden.
_IS_REAL_ENCLAVE = _in_real_enclave()

if _IS_REAL_ENCLAVE:
    _skip_tls = os.environ.get("SKIP_TLS_VERIFY", "false").lower() == "true"
    _skip_enc = os.environ.get("SKIP_ENCRYPTION", "false").lower() == "true"
    if _skip_tls or _skip_enc:
        _violations = []
        if _skip_tls:
            _violations.append("SKIP_TLS_VERIFY")
        if _skip_enc:
            _violations.append("SKIP_ENCRYPTION")
        raise RuntimeError(
            f"SECURITY VIOLATION: {', '.join(_violations)} set inside a real TDX enclave. "
            f"These flags bypass Props L1 security guarantees and MUST NOT be used "
            f"in production. Remove them from your environment and redeploy."
        )
    print("[oracle] Running inside real TDX enclave — all security checks enforced")
else:
    if os.environ.get("SKIP_TLS_VERIFY", "false").lower() == "true":
        print("[oracle] WARNING: SKIP_TLS_VERIFY=true — TLS pinning disabled (local dev only)")
    if os.environ.get("SKIP_ENCRYPTION", "false").lower() == "true":
        print("[oracle] WARNING: SKIP_ENCRYPTION=true — RSA decryption disabled (local dev only)")


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
# Attorney Oracle — NY Attorney Registry via data.ny.gov (S8/S10)
# Props L1 — same oracle contract, different REAL data source.
# Uses the NY Open Data Socrata API (data.ny.gov) to fetch real attorney
# registration records. TLS fingerprint of data.ny.gov is pinned inside
# the enclave — same security model as the medical board oracle.
# ---------------------------------------------------------------------------

NY_ATTORNEY_API = "https://data.ny.gov/resource/eqw2-r5nb.json"
NY_ATTORNEY_HOSTNAME = "data.ny.gov"

# SHA-256 TLS fingerprint of data.ny.gov — hardcoded in measured code.
# Same rationale as NYSED: part of the enclave measurement, not configurable.
# Update when cert renews — rebuild and redeploy:
#   openssl s_client -connect data.ny.gov:443 -servername data.ny.gov \
#     </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout
NY_ATTORNEY_TLS_FINGERPRINT = "49653D147D6180FDC9BEBF2A971930CFD5AAD671059781DA3F5494292434F8C9"


def _verify_attorney_tls() -> tuple[bool, str]:
    """
    Props L1 — TLS fingerprint verification for data.ny.gov.
    Same pattern as NYSED medical board pin check.
    """
    if os.environ.get("SKIP_TLS_VERIFY", "false").lower() == "true":
        return True, "skipped"
    pinned = NY_ATTORNEY_TLS_FINGERPRINT.upper().replace(":", "").replace(" ", "")
    if not pinned:
        # No fingerprint configured — reject (L1 requires TLS pinning)
        logger.warning("[attorney-oracle] No TLS fingerprint configured — rejecting")
        return False, "no-pin-configured"
    try:
        live = get_tls_fingerprint(NY_ATTORNEY_HOSTNAME)
        return live == pinned, live
    except Exception as e:
        return False, f"error:{e}"


def _fetch_attorney_credential(credentials: dict) -> dict:
    """
    Props L1 — Real attorney oracle (section 3.1).
    Fetches a real attorney registration record from the NY Open Data API
    (data.ny.gov Socrata endpoint). Same oracle envelope contract as
    the medical board oracle.

    Input: { registration_number: "1234567" }
    The API returns: name, company, address, year_admitted, law_school,
                     status, judicial_department, county, etc.
    """
    import httpx

    registration_number = credentials.get("registration_number", "").strip()
    if not registration_number:
        raise ValueError("registration_number is required for attorney oracle")

    # Props L1 — TLS fingerprint verification (section 3.1)
    fp_ok, live_fp = _verify_attorney_tls()
    if not fp_ok:
        raise ValueError(
            f"TLS fingerprint mismatch on {NY_ATTORNEY_HOSTNAME}. "
            f"Got: {live_fp}. This is not the authoritative NY attorney registry."
        )
    print(f"[oracle/attorney] TLS verified for {NY_ATTORNEY_HOSTNAME} ({live_fp[:16]}...)")

    # Query the Socrata API by registration number (with retry for transient failures)
    print(f"[oracle/attorney] Fetching attorney record: registration_number={registration_number}")
    last_error = None
    records = None
    for attempt in range(1, 4):
        try:
            resp = httpx.get(
                NY_ATTORNEY_API,
                params={"registration_number": registration_number},
                timeout=15.0,
            )
            resp.raise_for_status()
            records = resp.json()
            last_error = None
            break
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as e:
            last_error = e
            if attempt < 3:
                import time
                wait = attempt * 2
                print(f"[oracle/attorney] Transient error (attempt {attempt}/3), retrying in {wait}s: {e}")
                time.sleep(wait)
        except Exception as e:
            raise ValueError(f"Attorney API request failed: {e}")
    if records is None:
        raise ValueError(f"Attorney API unreachable after 3 attempts: {last_error}")

    if not records:
        raise ValueError(
            f"No attorney found with registration_number={registration_number}. "
            "Verify at https://data.ny.gov — the number must be a valid NY attorney registration."
        )

    raw = records[0]  # first (and should be only) match

    # Build clean credential record from API response
    credential = {}

    # Identity fields (will be stripped by L4 redaction)
    full_name_parts = [
        raw.get("first_name", ""),
        raw.get("middle_name", ""),
        raw.get("last_name", ""),
        raw.get("suffix", ""),
    ]
    full_name = " ".join(p.strip() for p in full_name_parts if p.strip())
    if full_name:
        credential["name"] = full_name.title()

    if raw.get("registration_number"):
        credential["registration_number"] = raw["registration_number"]

    # Address (identity)
    address_parts = [
        raw.get("street_1", ""),
        raw.get("street_2", ""),
        raw.get("city", ""),
        raw.get("state", ""),
        raw.get("zip", ""),
    ]
    address = ", ".join(p.strip() for p in address_parts if p.strip())
    if address:
        credential["address"] = address.title()

    if raw.get("phone_number"):
        credential["phone_number"] = raw["phone_number"]

    # Disclosable fields
    if raw.get("company_name"):
        credential["company_name"] = raw["company_name"].title()

    if raw.get("year_admitted"):
        credential["year_admitted"] = int(raw["year_admitted"])
        # Compute years_practicing
        credential["years_practicing"] = datetime.now().year - int(raw["year_admitted"])

    if raw.get("judicial_department_of_admission"):
        dept = raw["judicial_department_of_admission"]
        credential["judicial_department"] = f"Judicial Department {dept}"

    if raw.get("law_school"):
        credential["law_school"] = raw["law_school"].title()

    if raw.get("status"):
        status = raw["status"].strip()
        if status.lower() in ("currently registered",):
            credential["standing"] = "In good standing"
        else:
            credential["standing"] = status

    if raw.get("county"):
        credential["county"] = raw["county"]

    credential["jurisdiction"] = "New York State"

    print(f"[oracle/attorney] Scraped {len(credential)} fields — name: {credential.get('name', 'MISSING')}")

    # Props L1/L5 — data integrity hash (same as medical board oracle)
    raw_json = json.dumps(credential, sort_keys=True)
    data_hash = hashlib.sha256(raw_json.encode()).hexdigest()

    return {
        "credential": credential,
        "oracle_authenticated": True,
        "oracle_source": NY_ATTORNEY_HOSTNAME,
        "oracle_tls_fingerprint": live_fp if live_fp != "skipped" else "skipped",
        "data_hash": data_hash,
        "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
        "fetch_mode": "attorney_lookup",
        "oracle_type": "attorney",
    }


# ---------------------------------------------------------------------------
# Main entrypoint — medical board oracle
# ---------------------------------------------------------------------------

async def _oracle_main(credentials: dict, max_retries: int = 2) -> dict:
    """
    Props L1 — runs TLS pin check then fetches the credential.
    Retries the Chromium scrape on transient failures (timeouts, navigation errors).
    TLS verification is NOT retried — a fingerprint mismatch is a hard rejection.
    """
    license_number = credentials.get("license_number", "")
    if not license_number:
        raise ValueError("license_number is required")

    profession = credentials.get("profession", ORACLE_PROFESSION)

    # Props L1 — TLS fingerprint verification (section 3.1)
    # This is checked once — mismatch is a security rejection, not a transient error
    fingerprint_ok, live_fingerprint = verify_tls_fingerprint()
    if not fingerprint_ok:
        raise ValueError(
            f"TLS fingerprint mismatch on {NYSED_HOSTNAME}. "
            f"Expected: {NYSED_TLS_FINGERPRINT}, Got: {live_fingerprint}. "
            f"This is not the authoritative NY State Medical Board registry."
        )
    print(f"[oracle] TLS fingerprint verified ({live_fingerprint[:16]}...)")

    # Retry the Chromium scrape — the NYSED portal can be slow/flaky
    last_error = None
    raw_credential = None
    for attempt in range(1, max_retries + 1):
        try:
            raw_credential = await _fetch_credential_async(license_number, profession)
            if raw_credential:
                break
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                wait = attempt * 3  # 3s before retry
                print(f"[oracle] Chromium scrape failed (attempt {attempt}/{max_retries}), retrying in {wait}s: {e}")
                await asyncio.sleep(wait)
            else:
                print(f"[oracle] Chromium scrape failed after {max_retries} attempts: {e}")

    if not raw_credential:
        raise ValueError(
            f"Oracle returned empty credential after {max_retries} attempts"
            + (f": {last_error}" if last_error else "")
        )

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
            attorney:      {registration_number}
        oracle_target: override for ORACLE_TARGET env var (for testing)

    Returns oracle envelope with: credential, oracle_authenticated, oracle_source,
        oracle_tls_fingerprint, data_hash, fetch_timestamp, oracle_type
    """
    if isinstance(credentials_payload, dict):
        credentials = credentials_payload
    else:
        credentials = decrypt_credentials(credentials_payload)

    target = (oracle_target or ORACLE_TARGET).strip().lower()

    if target == "attorney":
        return _fetch_attorney_credential(credentials)
    elif target == "medical_board":
        return asyncio.run(_oracle_main(credentials))
    else:
        raise ValueError(
            f"Unknown ORACLE_TARGET '{target}'. "
            f"Valid targets: medical_board, attorney"
        )


# ---------------------------------------------------------------------------
# Direct test: python app/oracle.py
# Set ORACLE_TARGET=attorney to test attorney oracle.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    target = os.environ.get("ORACLE_TARGET", "medical_board")
    print(f"[oracle] Testing oracle: ORACLE_TARGET={target}")

    if target == "attorney":
        reg_number = os.environ.get("TEST_REGISTRATION_NUMBER", "1190404")
        print(f"[oracle] Registration number: {reg_number}")
        try:
            result = fetch_credential({"registration_number": reg_number})
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
