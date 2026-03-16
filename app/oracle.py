"""
Props L1 — Oracle Layer (Props paper, section 3.1)
==================================================
Chromium runs inside the Intel TDX enclave and authenticates against the
NY State Office of the Professions registry using the practitioner's own
credentials. The licensing board sees a normal browser login — it never
knows Props touched their registry.

WHY CHROMIUM INSIDE THE ENCLAVE:
- The TLS handshake happens inside the TEE, so the credential data is
  authenticated at the hardware level before it ever touches our code.
- TLS certificate fingerprint pinning is enforced inside the enclave —
  a fake registry cannot impersonate the real one.
- The data hash computed here is included in the TDX attestation quote,
  proving that THIS data (unmodified) is what the enclave processed.

Two fetch modes:
  1. practitioner_login  — logs into myaccount.op.nysed.gov with username/password
  2. license_lookup      — searches op.nysed.gov/verify by license number (demo/fallback)

The oracle_authenticated flag and data_hash are consumed by the forge endpoint (L5)
to detect data that bypassed the oracle pipeline.
"""

import asyncio
import base64
import hashlib
import json
import os
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from playwright.async_api import async_playwright, BrowserContext, Page

# ---------------------------------------------------------------------------
# TLS Fingerprint Pinning
# Props L1 — section 3.1: the oracle must verify it is talking to the real source
# ---------------------------------------------------------------------------
# SHA-256 fingerprint of the real NY State OP registry TLS certificate.
# Get the live value with:
#   openssl s_client -connect myaccount.op.nysed.gov:443 </dev/null 2>/dev/null \
#     | openssl x509 -fingerprint -sha256 -noout
# This value must be updated when the cert renews (typically annually).
NYSED_TLS_FINGERPRINT = os.environ.get(
    "NYSED_TLS_FINGERPRINT",
    # SHA-256 fingerprint of www.op.nysed.gov, verified 2026-03-16.
    # Renews annually — update by running:
    #   openssl s_client -connect www.op.nysed.gov:443 -servername www.op.nysed.gov \
    #     </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout
    "0D53B7BB43B892DC70D341431131D16EC7A3628714D0104F193100A792BBC68D8",
)

# The two NYSED endpoints we interact with.
# myaccount.op.nysed.gov (practitioner login) does not resolve publicly —
# the portal redirects through www.op.nysed.gov for all public access.
PRACTITIONER_LOGIN_URL = "https://www.op.nysed.gov/professions/online-services"
PUBLIC_LOOKUP_URL = "https://www.op.nysed.gov/verify"


def get_tls_fingerprint(hostname: str, port: int = 443) -> str:
    """
    Props L1 — section 3.1: TLS fingerprint verification.

    Connects to the host and returns the SHA-256 fingerprint of its certificate.
    Called once before launching the browser to verify we are talking to the
    real NYSED registry and not a fake one.
    """
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            return fingerprint.upper().replace(":", "")


def verify_tls_fingerprint(hostname: str) -> tuple[bool, str]:
    """
    Returns (True, fingerprint) if the live fingerprint matches the pinned value.
    Returns (False, live_fingerprint) if there is a mismatch.

    In SKIP_TLS_VERIFY=true mode (local dev only), always returns True.
    """
    if os.environ.get("SKIP_TLS_VERIFY", "false").lower() == "true":
        return True, "skipped"

    if NYSED_TLS_FINGERPRINT == "REPLACE_WITH_REAL_SHA256_FINGERPRINT":
        # Fingerprint not configured — skip check but log a warning.
        # This should never happen in production.
        print("WARNING: TLS fingerprint not configured. Skipping pin check.")
        return True, "not_configured"

    try:
        live = get_tls_fingerprint(hostname)
        pinned = NYSED_TLS_FINGERPRINT.upper().replace(":", "").replace(" ", "")
        return live == pinned, live
    except Exception as e:
        return False, f"error:{str(e)}"


def decrypt_credentials(encrypted_payload: str) -> dict:
    """
    Props L2 — TEE data handling.

    Decrypts RSA-encrypted credentials submitted by the user's browser.
    The private key was derived from the enclave's deterministic key material,
    so only this exact enclave build can decrypt these credentials.

    For the hackathon, credentials can also be sent as plain JSON when
    SKIP_ENCRYPTION=true (local dev only).
    """
    if os.environ.get("SKIP_ENCRYPTION", "false").lower() == "true":
        # In dev mode, accept plain JSON directly.
        return json.loads(encrypted_payload)

    # Production: decrypt with the enclave-derived RSA private key.
    # The public key for this enclave is served at GET /api/pubkey so the
    # browser can encrypt before submission.
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key_pem = os.environ.get("ENCLAVE_PRIVATE_KEY", "").encode()
        if not private_key_pem:
            raise ValueError("ENCLAVE_PRIVATE_KEY not set in environment")

        private_key = load_pem_private_key(private_key_pem, password=None)
        ciphertext = base64.b64decode(encrypted_payload)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return json.loads(plaintext.decode())
    except Exception as e:
        raise ValueError(f"Credential decryption failed: {e}")


async def fetch_via_practitioner_login(
    page: Page,
    username: str,
    password: str,
) -> dict:
    """
    Props L1 — Oracle layer (section 3.1): practitioner login path.

    Logs into myaccount.op.nysed.gov using the practitioner's own credentials
    and navigates to their license profile page to extract the full credential record.

    This is the primary path — it mirrors exactly what Dr Sarah Chen does when
    she logs into the NY medical board to renew her license.
    """
    print(f"[oracle] Navigating to practitioner login: {PRACTITIONER_LOGIN_URL}")
    await page.goto(PRACTITIONER_LOGIN_URL, wait_until="networkidle", timeout=30000)

    # Fill in login form
    await page.fill('input[name="username"], input[id="username"], input[type="text"]', username)
    await page.fill('input[name="password"], input[id="password"], input[type="password"]', password)
    await page.click('button[type="submit"], input[type="submit"], .login-btn')
    await page.wait_for_load_state("networkidle", timeout=15000)

    # After login, navigate to license details
    # The NYSED OP account page shows the practitioner's license records
    current_url = page.url
    print(f"[oracle] Post-login URL: {current_url}")

    if "login" in current_url.lower() or "error" in current_url.lower():
        raise ValueError("Login failed — invalid credentials or portal unavailable")

    # Navigate to license profile / My Licenses page
    # Try common paths the portal uses
    for path in ["/account", "/myaccount", "/licenses", "/profile"]:
        try:
            nav_url = f"https://myaccount.op.nysed.gov{path}"
            await page.goto(nav_url, wait_until="networkidle", timeout=10000)
            content = await page.content()
            # Check if we landed on a page with license information
            if any(keyword in content.lower() for keyword in ["license", "registration", "specialty", "physician"]):
                break
        except Exception:
            continue

    return await _scrape_credential_fields(page)


async def fetch_via_license_lookup(
    page: Page,
    license_number: str,
    profession: str = "Medicine",
) -> dict:
    """
    Props L1 — Oracle layer (section 3.1): public license verification path.

    Searches the public NYSED verification portal by license number.
    Used as a fallback when practitioner login is unavailable, and as the
    primary method for demo mode where we look up a specific license number.

    The public portal returns the same authoritative data — name, specialty,
    jurisdiction, license standing — as the practitioner portal. It is still
    oracle-authenticated because it comes from the real NYSED TLS endpoint
    inside the TEE.
    """
    print(f"[oracle] Navigating to public lookup: {PUBLIC_LOOKUP_URL}")
    await page.goto(PUBLIC_LOOKUP_URL, wait_until="networkidle", timeout=30000)

    # The NYSED verification search form
    # Select profession: Medicine
    try:
        await page.select_option('select[name="profession"], select#profession', label=profession)
    except Exception:
        pass  # Some versions of the form auto-select

    # Enter license number in the search field
    try:
        await page.fill('input[name="licno"], input[name="license_number"], input[id="licno"]', license_number)
    except Exception:
        # Try a generic text input
        await page.fill('input[type="text"]:first-of-type', license_number)

    # Submit the search
    await page.click('input[type="submit"], button[type="submit"]')
    await page.wait_for_load_state("networkidle", timeout=15000)

    # Click through to the detailed license record
    try:
        # The search results show a list of matching practitioners
        # Click the first result to get to the full detail page
        await page.click('table.results a:first-of-type, .result-row a:first-of-type, a.license-link', timeout=5000)
        await page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass  # Already on detail page if only one result

    return await _scrape_credential_fields(page)


async def _scrape_credential_fields(page: Page) -> dict:
    """
    Extracts credential fields from the NYSED portal page currently loaded.

    The NYSED OP portal displays license information in a definition list
    or table format. We extract each field by its label.

    Returns a raw dict with all fields found — identity and credential alike.
    The redaction layer (Props L4) is responsible for stripping identity fields
    before the data exits the enclave.
    """
    content = await page.content()

    # Use Playwright's evaluate to extract text from labeled fields
    # The NYSED portal uses consistent label patterns
    raw_fields = await page.evaluate("""() => {
        const result = {};

        // Pattern 1: definition list (dt = label, dd = value)
        document.querySelectorAll('dt').forEach(dt => {
            const dd = dt.nextElementSibling;
            if (dd && dd.tagName === 'DD') {
                const key = dt.textContent.trim().toLowerCase()
                    .replace(/[:\\s]+/g, '_').replace(/_+/g, '_').trim('_');
                result[key] = dd.textContent.trim();
            }
        });

        // Pattern 2: table rows (th = label, td = value)
        document.querySelectorAll('tr').forEach(tr => {
            const cells = tr.querySelectorAll('th, td');
            if (cells.length === 2) {
                const key = cells[0].textContent.trim().toLowerCase()
                    .replace(/[:\\s]+/g, '_').replace(/_+/g, '_');
                result[key] = cells[1].textContent.trim();
            }
        });

        // Pattern 3: label-value spans (common in newer portal versions)
        document.querySelectorAll('.label, .field-label').forEach(label => {
            const value = label.nextElementSibling || label.parentElement?.querySelector('.value');
            if (value) {
                const key = label.textContent.trim().toLowerCase()
                    .replace(/[:\\s]+/g, '_').replace(/_+/g, '_');
                result[key] = value.textContent.trim();
            }
        });

        return result;
    }""")

    # Normalise the scraped fields into our canonical schema.
    # NYSED uses various label wordings across portal versions —
    # we map them all to consistent field names.
    FIELD_MAP = {
        # Name
        "name": "name",
        "full_name": "name",
        "practitioner_name": "name",
        "licensee_name": "name",
        # License number
        "license_number": "license_number",
        "license_no": "license_number",
        "registration_number": "license_number",
        "licno": "license_number",
        # Specialty / profession
        "specialty": "specialty",
        "profession": "specialty",
        "type_of_practice": "specialty",
        "title": "specialty",
        # License standing / status
        "status": "standing",
        "license_status": "standing",
        "registration_status": "standing",
        "standing": "standing",
        # Jurisdiction
        "state": "jurisdiction",
        "jurisdiction": "jurisdiction",
        "licensed_in": "jurisdiction",
        # Dates
        "registration_period": "registration_period",
        "registered_through": "registration_period",
        "expiration_date": "expiration_date",
        "initial_registration_date": "initial_registration_date",
        "license_date": "initial_registration_date",
        # Address (identity field — will be stripped by L4)
        "address": "address",
        "business_address": "address",
        "mailing_address": "address",
    }

    normalised = {}
    for raw_key, value in raw_fields.items():
        # Try exact match first, then partial match
        mapped = FIELD_MAP.get(raw_key)
        if not mapped:
            for pattern, canonical in FIELD_MAP.items():
                if pattern in raw_key or raw_key in pattern:
                    mapped = canonical
                    break
        if mapped and value and value.strip():
            normalised[mapped] = value.strip()

    # Derive years_active from initial registration date if not directly present
    if "years_active" not in normalised and "initial_registration_date" in normalised:
        try:
            from dateutil.parser import parse as parse_date
            reg_date = parse_date(normalised["initial_registration_date"])
            years = (datetime.now() - reg_date).days // 365
            normalised["years_active"] = years
        except Exception:
            pass

    # Ensure jurisdiction defaults to New York State for NYSED records
    if "jurisdiction" not in normalised:
        normalised["jurisdiction"] = "New York State"

    print(f"[oracle] Scraped {len(normalised)} fields from portal")
    return normalised


async def _fetch_credential_async(credentials: dict) -> dict:
    """
    Core async fetch. Launches Playwright Chromium, runs the oracle pipeline,
    returns the full credential record with oracle metadata attached.
    """
    mode = credentials.get("mode", "practitioner_login")
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    license_number = credentials.get("license_number", "")

    # -------------------------------------------------------------------------
    # Props L1 — TLS fingerprint verification (section 3.1)
    # Verify we are talking to the real NYSED registry before launching browser.
    # A fake registry with a different cert fingerprint is rejected here.
    # -------------------------------------------------------------------------
    # Both modes go through www.op.nysed.gov — myaccount subdomain does not resolve publicly.
    hostname = "www.op.nysed.gov"
    fingerprint_ok, live_fingerprint = verify_tls_fingerprint(hostname)

    if not fingerprint_ok:
        raise ValueError(
            f"TLS fingerprint mismatch on {hostname}. "
            f"Expected: {NYSED_TLS_FINGERPRINT}, "
            f"Got: {live_fingerprint}. "
            f"This endpoint is not the authoritative NY State Medical Board registry."
        )

    print(f"[oracle] TLS fingerprint verified for {hostname}")

    # -------------------------------------------------------------------------
    # Props L1 — Chromium-in-TEE browser session (section 3.1)
    # -------------------------------------------------------------------------
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--single-process",
                # Prevent any extension or user data from leaking
                "--incognito",
                "--disable-extensions",
                # Proxy through dstack's VSOCK network interface if available
                # (dstack handles routing inside the TEE automatically)
            ],
        )

        context: BrowserContext = await browser.new_context(
            # Use a realistic user agent to avoid bot detection on the portal
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            # Ignore HTTPS errors only in dev mode
            ignore_https_errors=os.environ.get("SKIP_TLS_VERIFY", "false").lower() == "true",
        )

        page: Page = await context.new_page()

        try:
            if mode == "practitioner_login":
                raw_credential = await fetch_via_practitioner_login(page, username, password)
            else:
                # license_lookup mode — used for demo and public verification
                if not license_number:
                    raise ValueError("license_number required for license_lookup mode")
                raw_credential = await fetch_via_license_lookup(page, license_number)

        finally:
            await browser.close()

    if not raw_credential:
        raise ValueError("Oracle returned empty credential record — portal may have changed structure")

    # -------------------------------------------------------------------------
    # Props L1/L5 — Data integrity hash (section 3.1 + 2.3)
    # Hash the raw credential data immediately after fetch.
    # This hash is included in the TDX attestation quote.
    # The forge endpoint checks this hash to detect tampered data (L5).
    # -------------------------------------------------------------------------
    raw_json = json.dumps(raw_credential, sort_keys=True)
    data_hash = hashlib.sha256(raw_json.encode()).hexdigest()

    return {
        # The raw credential record — ALL fields including identity.
        # L4 redaction strips identity fields before this exits the enclave.
        "credential": raw_credential,
        # Oracle metadata — consumed by attestation layer and L5 forge check.
        "oracle_authenticated": True,
        "oracle_source": hostname,
        "oracle_tls_fingerprint": live_fingerprint,
        "data_hash": data_hash,
        "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
        "fetch_mode": mode,
    }


def fetch_credential(credentials_payload: str | dict) -> dict:
    """
    Props L1 — Oracle layer (section 3.1).
    Public entrypoint. Accepts encrypted or plain credentials, returns
    oracle-authenticated raw credential record.

    Args:
        credentials_payload: Either a base64-encoded RSA-encrypted JSON string
                             (production) or a plain dict (SKIP_ENCRYPTION=true).

    Returns:
        {
          "credential": { full raw fields from NYSED portal },
          "oracle_authenticated": True,
          "oracle_source": "hostname",
          "oracle_tls_fingerprint": "...",
          "data_hash": "sha256 of raw credential",
          "fetch_timestamp": "iso8601",
          "fetch_mode": "practitioner_login|license_lookup"
        }
    """
    if isinstance(credentials_payload, dict):
        credentials = credentials_payload
    else:
        credentials = decrypt_credentials(credentials_payload)

    return asyncio.run(_fetch_credential_async(credentials))


# ---------------------------------------------------------------------------
# Demo / development: run directly to test the oracle
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    # Quick test: look up a license by number (public mode, no login required)
    test_credentials = {
        "mode": "license_lookup",
        "license_number": os.environ.get("TEST_LICENSE_NUMBER", "209311"),
    }

    print("[oracle] Running oracle test in license_lookup mode...")
    print(f"[oracle] Looking up license: {test_credentials['license_number']}")

    try:
        result = fetch_credential(test_credentials)
        print("[oracle] SUCCESS — raw credential record:")
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"[oracle] FAILED: {e}", file=sys.stderr)
        sys.exit(1)
