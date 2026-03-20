# Attestia

**"We built the first decentralised protocol for verified anonymous speech."**

Built for the Encode Club Shape Rotator Hackathon — TEE track.
Implements [Props: Verifiable ML Inference over Private Data](https://arxiv.org/pdf/2410.20522) (Juels & Koushanfar, 2024).

**Product name:** Attestia  
**Protocol / paper lineage:** Props

**Live deployment:** https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network

**Contract:** [`0x07a7c1efc53923b202191a888fad41e54cae7ca6`](https://sepolia.basescan.org/address/0x07a7c1efc53923b202191a888fad41e54cae7ca6) on Base Sepolia (chain 84532)

## Judge Access

Judges can use the live website directly here:

- **Attestia live app:** [https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network](https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network)

Suggested path through the app:

1. Open **Screen 01 — Expert portal**
2. Use the medical-board flow with license number `209311`
3. Generate a certificate and follow the verifier link
4. Check the hardware-backed trust result and on-chain verification
5. Optionally explore the adversarial-defense screen to see why forged paths fail

Notes:

- No login is required.
- The live Phala deployment is the canonical demo path.
- The verifier is public, so issued certificates can be shared and checked independently.

---

## What it does

A doctor, lawyer, or whistleblower submits their professional credentials. The Attestia pipeline inside an Intel TDX enclave authenticates against the authoritative licensing registry, extracts credential facts via LLM, strips identity fields, and produces a signed certificate stored permanently on Base (Coinbase L2). The expert attaches this certificate to anything they publish. Readers verify the credential without knowing who the expert is.

### Business model

B2B protocol licensing to media platforms, legal systems, and verification services. Per-query API pricing for third-party integrations. The on-chain registry is the durable primitive — the verification API is the monetisation layer.

---

## Architecture — Props paper layers

| Layer | What it does | Implementation |
|-------|-------------|----------------|
| **L1 Oracle** | Fetches data from authoritative TLS source inside TEE | Chromium scrapes NYSED registry (medical) or data.ny.gov Socrata API (attorney). TLS fingerprint pinned inside enclave. |
| **L2 TEE + Attestation** | Hardware-isolated computation with cryptographic proof | Phala Cloud Intel TDX enclave. Ed25519 signing with enclave-derived deterministic key. TDX quote includes payload hash. |
| **L3 Pinned Model** | Verifiable ML inference — model hash in attestation | `llama3.2:1b` via Ollama sidecar (current runtime default). Model digest from `/api/show` included in signed certificate. Hard-fails if LLM unavailable. |
| **L4 Data Redaction** | User-controlled filter f(X) = X' (section 2.4) | Toggle switches on frontend control server-side redaction. Identity fields always stripped. Certificate reflects what the enclave actually removed. |
| **L5 Adversarial Defense** | Architectural fraud rejection | `/api/forge` endpoint demonstrates three live attack rejections using real pipeline guard functions. |

### Oracle authentication model

The NYSED medical board portal is a **public license verification system** — anyone can look up a license number. The Props L1 oracle proves that the data came from the real, authoritative government registry (via TLS fingerprint pinning inside the enclave) and was not fabricated or modified. The architecture fully supports credentialed portal login (the Chromium-in-TEE pattern handles any web authentication flow), and would be used for data sources that require login credentials. The attorney oracle demonstrates a second pattern: structured API access to data.ny.gov with separate TLS pinning. The key property is **data provenance** — the oracle establishes that the credential facts originated from the authoritative source, were fetched inside the enclave, and were not tampered with.

---

## Local Dev Setup

Everything you need to run and test the oracle on your laptop.

### Prerequisites

- Python 3.11 (matches the Docker image used for Phala deployment)
- Node.js (needed for `playwright install`)
- macOS or Linux

### One-time setup

**1. Install Python dependencies**
```bash
python3.11 -m pip install -r requirements.txt
```

**2. Install Chromium (used by the oracle to scrape the medical board)**
```bash
playwright install chromium
```

**3. Fix SSL certificates (macOS only — do this once)**
```bash
/Applications/Python\ 3.11/Install\ Certificates.command
```

> If that path doesn't exist, find it with:
> `find /Applications -name "Install Certificates.command" 2>/dev/null`

---

## Testing the Oracle (S2)

The oracle fetches real credential data from the NY State medical board.

**Quick test with a known license number:**
```bash
SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true TEST_LICENSE_NUMBER=209311 python3.11 app/oracle.py
```

**Test with a different profession:**
```bash
SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true TEST_LICENSE_NUMBER=053787 ORACLE_PROFESSION="Dentist (050)" python3.11 app/oracle.py
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
SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true python3.11 app/main.py
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

## Deploying to Phala Cloud

### One-time setup

Install the Phala CLI:
```bash
npm install -g phala
phala login    # enter your API key from cloud.phala.com
```

### Build and push the Docker image

**Always build for `linux/amd64`** — Phala Cloud runs Intel TDX (x86_64). Building on Apple Silicon without this flag produces an `arm64`-only image that silently crashes on Phala.

```bash
# Replace TAG with the release tag you are about to deploy, for example `s31`
docker buildx build --platform linux/amd64 -t vetskiver/props-oracle:TAG --push .
```

Then update `docker-compose.yaml`:
```yaml
props-oracle:
  image: vetskiver/props-oracle:TAG   # ← update this line
```

### Deploy / update the running CVM

```bash
phala deploy -c docker-compose.yaml 6faa38933e632ca8dd2795fa68ad043c0bb6ad82
```

The CVM will reboot and pull the new image. It takes ~3-5 minutes for the image pull + container start. Poll until live:
```bash
curl https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/
# Expected: {"version": "X.X.X", "status": "running", ...}
```

### CVM details

| Field | Value |
|---|---|
| CVM ID | `6faa38933e632ca8dd2795fa68ad043c0bb6ad82` |
| App ID | `6faa38933e632ca8dd2795fa68ad043c0bb6ad82` |
| Public URL | `https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network` |
| Docker image | `vetskiver/props-oracle:s33` |

### Runtime envs currently used by the live CVM

The live Phala deployment enables these additional runtime controls beyond the base local compose:

- `PINNED_MODEL_DIGEST`
- `SKIP_MODEL_PIN`
- `SKIP_OLLAMA_WAIT`
- `STRICT_MODE`
- `REQUIRE_REAL_TEE`
- `REQUIRE_LLM_EXTRACTION`
- `REQUIRE_PINNED_MODEL`
- `REQUIRE_ONCHAIN`

These are sealed envs / allowed compose envs on Phala Cloud and are part of the live judging path.

### Optional Intel Trust Authority appraisal

The app already verifies TDX quotes structurally and can establish `trust_level=hardware`
without Intel Trust Authority. If you also want the verifier payload to show a successful
third-party Intel appraisal instead of a `401`/unconfigured message, set:

- `INTEL_TRUST_AUTHORITY_API_KEY`
- `INTEL_TRUST_AUTHORITY_URL` (optional override; defaults to Intel's appraisal endpoint)

Important implementation note:

- This must be an Intel Trust Authority **Attestation API key**, not an Admin API key.
- The key is created and retrieved from the Intel Trust Authority portal.
- If your tenant uses a non-default regional endpoint, set `INTEL_TRUST_AUTHORITY_URL`
  to the correct appraisal base URL for that tenant instead of the default US endpoint.
- After creating or rotating the key, redeploy the CVM with the new sealed env and allow
  a short propagation window before re-testing the verifier path.

Without the API key, `intel_details` will stay in the "unavailable / unauthorized" path,
but the core judging-critical guarantees still work: real TDX quote, hardware trust, and
live Base Sepolia storage.

### Checking logs when something breaks

```bash
# Serial console logs (VM boot + docker pull progress)
phala cvms serial-logs 6faa38933e632ca8dd2795fa68ad043c0bb6ad82 | tail -50

# CVM status
phala cvms get 6faa38933e632ca8dd2795fa68ad043c0bb6ad82
```

---

## Sessions completed

| Session | What was built | Status |
|---|---|---|
| S1 | FastAPI app + dstack TDX attestation endpoint | ✅ done |
| S2 | Oracle layer — Chromium scrapes NY medical board | ✅ done |
| S3 | LLM extraction (Ollama `llama3.2:1b` default) + redaction filter | ✅ done |
| S4 | Attestation output + full API + forge endpoint + Phala deploy | ✅ done |
| S5 | Frontend connected to real backend (5-screen SPA) | ✅ done |
| S6 | On-chain certificate registry (Base Sepolia) | ✅ done |
| S7 | Adversarial forge endpoint (real pipeline guards) | ✅ done |
| S8 | Pluggable oracle (medical_board + attorney) | ✅ done |
| S9 | Full integration + bug fixing | ✅ done |

### How to verify S4 is fully working

**1. Version check**
```bash
curl https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/
# Expected: service metadata with version `0.6.0` and `status` `ready_for_verify`
```

**2. TDX attestation (Props L2)**
```bash
curl https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/api/attestation
# Expected: {"quote": "<hex>", "event_log": [...], "enclave_info": {...}}
```

**3. Full pipeline — credentials in, certificate out (Props L1–L4)**
```bash
curl -X POST https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/api/verify \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": {"license_number": "209311", "profession": "Physician (060)"},
    "disclosed_fields": ["specialty", "years_active", "standing"]
  }'
# Expected: NDJSON progress events ending in a certificate JSON with credential,
# model_digest, raw_fields_stripped, signature, and on-chain metadata
```

**4. Fetch certificate by ID (Screen 2)**
```bash
curl https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/api/certificate/<id_from_step_3>
```

**5. Verify certificate signature (Screen 4)**
```bash
curl https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/api/verify/<id_from_step_3>
# Expected: {"valid": true, "credential": {...}}
```

**6. Adversarial rejections — all three attack types (Props L5)**
```bash
# Attack 1: forged PDF submitted directly (not oracle-authenticated)
curl -s -w "\nHTTP %{http_code}" -X POST .../api/forge -H "Content-Type: application/json" -d '{"type": "pdf"}'
# Expected: HTTP 403 + {"rejected": true, "props_layer": "L1", ...}

# Attack 2: fake registry (TLS fingerprint mismatch)
curl -s -w "\nHTTP %{http_code}" -X POST .../api/forge -H "Content-Type: application/json" -d '{"type": "fake_registry"}'
# Expected: HTTP 403 + {"rejected": true, "props_layer": "L1", ...}

# Attack 3: tampered data (hash mismatch inside enclave)
curl -s -w "\nHTTP %{http_code}" -X POST .../api/forge -H "Content-Type: application/json" -d '{"type": "tampered"}'
# Expected: HTTP 403 + {"rejected": true, "props_layer": "L2", ...}
```

All six checks passing = S4 complete.

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
