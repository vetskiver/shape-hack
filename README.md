# Anonymous Expert Oracle

**"We built the first decentralised protocol for verified anonymous speech."**

Built for the Encode Club Shape Rotator Hackathon — TEE track.
Implements [Props: Verifiable ML Inference over Private Data](https://arxiv.org/pdf/2410.20522) (Juels & Koushanfar, 2024).

---

## Local Dev Setup

Everything you need to run and test the oracle on your laptop.

### Prerequisites

- Python 3.12 (the commands below use `python3.12` and `pip` pointing to 3.12)
- Node.js (needed for `playwright install`)
- macOS or Linux

### One-time setup

**1. Install Python dependencies**
```bash
pip install playwright python-dateutil cryptography fastapi uvicorn dstack-sdk
```

**2. Install Chromium (used by the oracle to scrape the medical board)**
```bash
playwright install chromium
```

**3. Fix SSL certificates (macOS only — do this once)**
```bash
/Applications/Python\ 3.12/Install\ Certificates.command
```

> If that path doesn't exist, find it with:
> `find /Applications -name "Install Certificates.command" 2>/dev/null`

---

## Testing the Oracle (S2)

The oracle fetches real credential data from the NY State medical board.

**Quick test with a known license number:**
```bash
SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true TEST_LICENSE_NUMBER=209311 python3.12 app/oracle.py
```

**Test with a different profession:**
```bash
SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true TEST_LICENSE_NUMBER=053787 ORACLE_PROFESSION="Dentist (050)" python3.12 app/oracle.py
```

**Find your own license number to test with:**
1. Go to https://www.op.nysed.gov/verification-search
2. Select **Licensee Name** → **Physician (060)**
3. Search any last name (e.g. `Chen`, `Smith`)
4. Copy a license number from the results
5. Run the command above with that number

**What good output looks like:**
```json
{
  "credential": {
    "name": "...",
    "specialty": "Medicine",
    "standing": "In good standing",
    "years_active": 17,
    "license_number": "...",
    "address": "...",
    "jurisdiction": "New York State"
  },
  "oracle_authenticated": true,
  "data_hash": "abc123..."
}
```

### Environment variables (local dev)

| Variable | What it does | Default |
|---|---|---|
| `SKIP_TLS_VERIFY=true` | Skips TLS fingerprint pin check | `false` |
| `SKIP_ENCRYPTION=true` | Accepts plain JSON instead of RSA-encrypted credentials | `false` |
| `TEST_LICENSE_NUMBER` | License number to look up | `209311` |
| `ORACLE_PROFESSION` | Profession dropdown value on NYSED portal | `Physician (060)` |

> **These flags are for local dev only.** Never set them in docker-compose.yaml for Phala Cloud deployment.

---

## Running the FastAPI server locally

```bash
SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true python3.12 app/main.py
```

Then visit http://localhost:8080/api/attestation — returns a mock attestation (real one only available inside Phala Cloud TEE).

---

## TLS Fingerprint (production)

The oracle pins the TLS certificate of the real NYSED registry.
To get the current fingerprint (do this before each deployment):

```bash
openssl s_client -connect www.op.nysed.gov:443 -servername www.op.nysed.gov \
  </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout
```

Set the output value as `NYSED_TLS_FINGERPRINT` in docker-compose.yaml.
Current pinned value (verified 2026-03-16): `0D:53:B7:BB:43:B8:92:DC:70:D3:41:43:11:3D:16:EC:7A:36:28:71:4D:01:04:F1:93:10:0A:79:2B:BC:68:D8`

---

## Sessions completed

| Session | What was built | Branch |
|---|---|---|
| S1 | FastAPI app + dstack TDX attestation endpoint | main |
| S2 | Oracle layer — Chromium scrapes NY medical board | main |
| S3 | LLM extraction + redaction filter | — |
| S4 | Attestation output + full API | — |
| S5 | Frontend connected to real backend | — |
| S6 | On-chain certificate registry (Base testnet) | — |
| S7 | Adversarial forge endpoint | — |

---

## Supported professions

Any NY State licensed profession works — just change `ORACLE_PROFESSION`:

```bash
ORACLE_PROFESSION="Physician (060)"                    # medical doctors
ORACLE_PROFESSION="Dentist (050)"                      # dentists
ORACLE_PROFESSION="Registered Nurse (RN)"              # nurses
ORACLE_PROFESSION="Psychology (014)"                   # psychologists
ORACLE_PROFESSION="Licensed Clinical Social Worker (029)"
ORACLE_PROFESSION="Physical Therapist (073)"
ORACLE_PROFESSION="Pharmacy (032)"
```

Full list at https://www.op.nysed.gov/verification-search — second dropdown.
