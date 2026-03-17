# TASKS.md — Anonymous Expert Oracle
## How to use this file

Every Claude session starts the same way:
1. Open a **new** Claude chat (claude.ai or VS Code Copilot Chat)
2. Paste the **entire contents of CLAUDE.md** as your first message
3. Then paste the **Session Prompt** from the relevant session below
4. Work until the goal is achieved and tested
5. **Do not move to the next session until the current goal works**

Never put two sessions in one chat. Fresh context = better code.

---

## Who owns what

| Builder | Role | Sessions |
|---------|------|----------|
| Both | Together | S1, S9 |
| Builder 1 | Data Scientist (Python, ML, backend) | S2, S3, S4, S7, S8 |
| Builder 2 | Software Engineer (frontend, APIs, smart contract) | S5, S6 |

---

## Session S1 — Phala Cloud Setup
**Owner:** Both builders together
**Day:** Day 1
**Goal:** Real TDX attestation quote returning from a real Phala Cloud instance

Before starting:
- Sign up at cloud.phala.com
- Get hackathon credits
- Install Phala CLI: `npm install -g phala`

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

We are starting Day 1 infrastructure setup. Phala Cloud account is ready with credits.

We need you to give us the exact files to:
1. Create a minimal Python FastAPI app
2. Add dstack-sdk to get a real TDX attestation quote
3. Deploy to Phala Cloud via docker-compose
4. Confirm the attestation socket works

Give us these exact files with complete working code:
- app/main.py (FastAPI with one endpoint GET /api/attestation that returns a real TDX quote)
- Dockerfile
- docker-compose.yaml (with /var/run/dstack.sock mounted)
- requirements.txt

Then tell us the exact commands to deploy to Phala Cloud.
```

**Done when:** `curl https://your-phala-url/api/attestation` returns a real TDX quote JSON. Not a mock. Not a simulator. A real quote.

---

## Session S2 — Oracle Layer
**Owner:** Builder 1
**Day:** Day 2
**Goal:** Chromium running inside the TEE authenticating against NY medical board and returning real credential JSON

Before starting: S1 must be complete and working.

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

S1 is complete. Phala Cloud is running and dstack attestation works.

I need to build the oracle layer — Props L1 from section 3.1 of the paper.

The oracle needs to:
1. Accept encrypted credentials from the user (username + password for NY State medical board)
2. Run Chromium inside the TEE (headless, using Playwright or Selenium)
3. Log into https://www.nysed.gov/op (NY State medical board portal)
4. Scrape the authenticated credential record
5. Return the raw credential JSON to the next layer

Reference: the props_training repo at github.com/danivilardell/props_training does this exact pattern for Whoop. Adapt that pattern.

Give me:
- app/oracle.py — complete working Python code
- Any additional requirements needed in requirements.txt
- Any changes needed to docker-compose.yaml to support Chromium inside the container
```

**Done when:** Running the oracle with real NY medical board credentials returns a JSON object with name, license number, specialty, years active, jurisdiction, and standing.

---

## Session S3 — LLM Extraction + Redaction Filter
**Owner:** Builder 1
**Day:** Day 3 (morning)
**Goal:** Ollama LLM extracts four fields from credential JSON, redaction filter strips identity fields

Before starting: S2 must be complete. You should have a raw credential JSON to test against.

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

S2 is complete. The oracle returns raw credential JSON like this:
{
  "name": "Dr Sarah Chen",
  "license_number": "NY-MD-2847193",
  "address": "84 Park Ave, New York",
  "date_of_birth": "1975-03-12",
  "specialty": "Cardiology",
  "years_active": 17,
  "jurisdiction": "New York State",
  "standing": "In good standing"
}

I need two things:

1. app/extractor.py — Props L3 (pinned model)
   - Ollama running with Llama 3.2 3B inside the container
   - LLM extracts the four credential facts only: specialty, years_active, jurisdiction, standing
   - Returns structured JSON
   - Model name and version must be captured for the attestation

2. app/redaction.py — Props L4 (filter f(X) = X')
   - Accepts the raw credential + a list of fields the user consents to disclose
   - Strips all identity fields (name, license_number, address, date_of_birth)
   - Returns only the consented fields
   - This is section 2.4 of the Props paper

Also give me the docker-compose.yaml changes needed to run Ollama inside the container.
```

**Done when:** Passing raw credential JSON + `disclosed_fields: ["specialty", "years_active"]` returns `{"specialty": "Cardiology", "years_active": 17}` with nothing else.

---

## Session S4 — Attestation Output + Full API
**Owner:** Builder 1
**Day:** Day 3 (afternoon)
**Goal:** Full Props pipeline wired together with all API endpoints working

Before starting: S2 and S3 must be complete and tested.

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

S2 and S3 are complete. Oracle, extractor, and redaction are all working.

Now I need to wire everything together into a complete API.

1. app/attestation.py — Props L2
   - Wraps dstack-sdk DstackClient
   - Takes the redacted credential + model hash + disclosed fields
   - Calls client.get_quote() with a hash of the certificate data
   - Returns a signed certificate JSON:
     {
       "certificate_id": "uuid",
       "credential": { disclosed fields only },
       "model_hash": "llama3.2:3b",
       "enclave_measurement": "...",
       "timestamp": "...",
       "signature": "...",
       "raw_fields_stripped": [ list of field names that were removed ]
     }
   Note: raw_fields_stripped is important for the frontend to show struck-through fields

2. Update app/main.py with these endpoints:
   POST /api/verify — accepts {credentials, disclosed_fields}, runs full pipeline, returns certificate
   GET /api/certificate/:id — returns certificate by ID (store in memory dict for now)
   GET /api/verify/:id — verifies certificate signature, returns {valid: bool, credential: {...}}
   POST /api/forge — accepts {type: "pdf"|"fake_registry"|"tampered"}, returns 403 with rejection reason

Give me complete working code for all files.
```

**Done when:** `POST /api/verify` with real credentials returns a signed certificate JSON with all fields populated including `raw_fields_stripped`.

---

## Session S5 — Frontend Application
**Owner:** Builder 2
**Day:** Day 3
**Goal:** Build a real frontend web application connected to the live backend

Before starting: S4 must be complete and all endpoints confirmed working.

**Context on props_demo.html:**
The file `frontend/props_demo.html` is a visual reference only. It shows step by step what the MVP is about and how L1 through L5 address all aspects of the Props paper. Use it to understand the design, the five screens, and the product story. Do not wire it up. Build a new application that actually works.

**Known backend details:**
- Backend URL: `https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network`
- `POST /api/verify` takes 30-60 seconds (Chromium scraping + LLM inference). Use fetch() with a 90 second timeout or no timeout at all. Show a loading state.
- Credentials are sent as plain JSON `{license_number, profession}` — encryption not yet wired
- Response includes `raw_fields_stripped[]` — use this array to drive the struck-through display on Screen 2
- CORS headers must be enabled on the backend — remind Builder 1 to add them to FastAPI

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

The backend is live at:
https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network

Confirmed endpoints:
POST /api/verify
  Request:  {license_number: "NY-MD-2847193", profession: "doctor", disclosed_fields: ["specialty", "years_active", "standing"]}
  Response: {certificate_id, credential, model_hash, enclave_measurement, timestamp, signature, raw_fields_stripped}
  Note: takes 30-60 seconds — use 90s timeout, show loading state

GET /api/certificate/:id
  Response: full certificate JSON

GET /api/verify/:id
  Response: {valid: bool, credential: {...}, on_chain_tx: "..."}

POST /api/forge
  Request:  {type: "pdf" | "fake_registry" | "tampered"}
  Response: HTTP 403 with {rejected, props_layer, reason, attack_type}

Reference: frontend/props_demo.html shows the visual design, the five screens, and how L1-L5 
map to each screen. Use it as a design guide and product reference. Do not modify it.
Build a new file: frontend/index.html

Build a single-page application with five views using vanilla JS and fetch(). 
No React, no build step, no npm. Must work when opened directly in a browser.

VIEW 1 — Credential submission (Props L1 + L4)
- Registry field locked to "NY State Medical Board"
- License number input field
- Profession input field  
- Four toggle switches: Specialty / Years active / Jurisdiction / License standing
- Toggles build the disclosed_fields array
- Submit button calls POST /api/verify
- Loading spinner with message "Fetching credentials from NY Medical Board..." 
  then "Running LLM extraction inside enclave..." — show this for the full 30-60s wait
- On success: navigate to View 2

VIEW 2 — Certificate output (Props L2 + L3 + L4)
- Fetch GET /api/certificate/:id on load
- Two clear sections:
  STRIPPED (from raw_fields_stripped array): name, license_number, address shown 
  with red strikethrough — these came from the backend, not hardcoded
  DISCLOSED (from credential object): specialty, years, standing shown in green
- Attestation block: enclave_measurement, model_hash, timestamp, signature
- On-chain tx link to Basescan if on_chain_tx is present
- "Copy verify link" button — copies the /verify/:id URL
- "Download certificate JSON" button

VIEW 3 — Published article (demo illustration only)
- Mock article page with Dr Sarah Chen's story about drug overprescription
- Byline shows Props verified badge: "Verified board-certified cardiologist · Props certified"
- "Verify credential →" link goes to View 4
- This view is hardcoded for demo purposes — it shows what real-world usage looks like

VIEW 4 — Public verifier (Props L2 + L3)
- Fetch GET /api/verify/:id on load
- Large green checkmark if valid, red X if not
- Three disclosed credential facts
- "Identity: not disclosed — cannot be recovered by anyone"
- Enclave measurement and model hash
- On-chain confirmation with Basescan link
- No login required — any reader can open this URL

VIEW 5 — Adversarial defense demo (Props L5)
- Three attack panels
- Each has a "Launch attack →" button
- Clicking calls POST /api/forge with the relevant type
- Shows the real HTTP 403 JSON response in a dark terminal-style box
- Shows which Props layer caught it (from props_layer field in response)
- All three must call the real API — no hardcoded responses

Dark theme matching props_demo.html visual style.
Give me the complete frontend/index.html file.
```

**Done when:** Opening index.html pointed at the Phala Cloud URL, going through all five views with a real license number, shows real backend data. The struck-through fields on View 2 come from `raw_fields_stripped` in the API response. View 5 shows real HTTP 403 responses from the live API.

---

## Session S6 — On-Chain Certificate Registry
**Owner:** Builder 2
**Day:** Day 4
**Goal:** Certificate hashes stored on Base testnet, verifier reads from chain

Before starting: S4 and S5 must be complete. You need a wallet with Base testnet ETH (get from Base faucet).

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

The full pipeline is working end to end. Certificates are being generated with real TDX attestation.

Now I need to add on-chain certificate storage. This makes it a protocol not a tool.

1. contracts/PropsCertRegistry.sol
   A simple Solidity smart contract for Base testnet:
   - store(bytes32 certificateId, bytes32 attestationHash) — stores certificate hash on-chain
   - verify(bytes32 certificateId) returns (bytes32) — returns stored hash for verification
   - emit CertificateStored event on store()
   Keep it minimal. No ownership, no access control needed for hackathon.

2. Deploy the contract to Base testnet
   Give me the exact commands using Hardhat or Foundry (whichever is simpler)

3. app/onchain.py
   Python code using web3.py to call store() when a certificate is generated
   Add this call to app/main.py in the POST /api/verify endpoint after certificate is created

4. Update Screen 4 in props_demo.html
   After signature verification, also check the on-chain registry
   Show: "Certificate confirmed on Base testnet [tx hash]" with a link to basescan

Give me all files with complete working code.
```

**Done when:** Generating a certificate triggers an on-chain transaction on Base testnet. The verifier page shows the Basescan link. The certificate exists permanently without our server.

---

## Session S7 — Adversarial Endpoint
**Owner:** Builder 1
**Day:** Day 4-5
**Goal:** `POST /api/forge` returning real structured 403 rejections for three attack types

Before starting: S4 must be complete.

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

The full pipeline is working. Now I need to build the adversarial defense demonstration — Props L5, section 2.3 of the paper.

Update app/main.py to make POST /api/forge actually simulate the three attack types and return real structured rejections:

Attack type "pdf":
- Simulate: user submits credential data directly without going through oracle
- Detect: check if data has oracle_authenticated flag set by the oracle layer
- Return 403: {"rejected": true, "props_layer": "L1", "reason": "Credential not oracle-authenticated. Data was not fetched from an authoritative TLS endpoint.", "attack_type": "direct_submission"}

Attack type "fake_registry":
- Simulate: oracle pointed at wrong endpoint
- Detect: check TLS certificate fingerprint against pinned NY medical board fingerprint
- Return 403: {"rejected": true, "props_layer": "L1", "reason": "TLS fingerprint mismatch. This endpoint is not the authoritative NY State Medical Board registry.", "attack_type": "fake_registry"}

Attack type "tampered":
- Simulate: data modified after oracle fetch
- Detect: recompute hash of credential data, compare against oracle-attested hash
- Return 403: {"rejected": true, "props_layer": "L2", "reason": "Data hash mismatch detected inside enclave. Credential was modified after oracle authentication.", "attack_type": "tampered_data"}

This endpoint is called LIVE during the demo from the browser. It must return real HTTP 403 responses with the structured JSON above. Not hardcoded HTML. Real JSON 403s.
```

**Done when:** Calling `POST /api/forge` with each of the three attack types returns a real HTTP 403 with the structured rejection JSON. Test with curl before the demo.

---

## Session S8 — Pluggable Oracle
**Owner:** Builder 1
**Day:** Day 5
**Goal:** ORACLE_TARGET config abstraction, same pipeline works for two data sources

Before starting: S2 must be complete.

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

The medical board oracle is fully working. Now I need to add a pluggable oracle abstraction so we can demonstrate that the same pipeline works for any TLS data source.

1. Refactor app/oracle.py
   Add ORACLE_TARGET environment variable support:
   - ORACLE_TARGET=medical_board → hits NY medical board (existing code)
   - ORACLE_TARGET=employment → hits mock employment portal (new)

2. Add mock employment oracle
   The employment oracle does not need to hit a real URL for the hackathon
   It should return realistic-looking employment data:
   {
     "employee_name": "[REDACTED]",
     "company": "Major Technology Company",
     "tier": "FAANG",
     "role": "Senior Software Engineer",
     "team": "Infrastructure",
     "years_tenure": 7,
     "employment_status": "Current employee"
   }
   Make the mock realistic. It should look like it came from an HR portal.

3. Update docker-compose.yaml
   Add ORACLE_TARGET environment variable

The demo moment: we change ORACLE_TARGET from medical_board to employment in docker-compose, redeploy, and the same pipeline produces a completely different certificate type. Same enclave. Same attestation. Same redaction filter. Different oracle.
```

**Done when:** Setting `ORACLE_TARGET=employment` in docker-compose and running the pipeline produces an employment credential certificate instead of a medical credential certificate.

---

## Session S9 — Full Integration + Bug Fixing
**Owner:** Both builders together
**Day:** Day 5
**Goal:** Complete end-to-end test on Phala Cloud, everything working together

Before starting: S1 through S8 should all be complete. Expect things to be broken. That is normal.

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

All components are built. We are doing a full integration test on the deployed Phala Cloud instance.

Here is the complete error log from our test:
[PASTE YOUR ACTUAL ERRORS HERE]

Here is our current file structure:
[PASTE OUTPUT OF: find . -name "*.py" -o -name "*.html" -o -name "*.yaml" | head -30]

Fix the errors one by one. Start with the most critical path:
credentials in → oracle fetches → LLM extracts → redaction applies → attestation signed → certificate on-chain → verifier confirms

Do not suggest rebuilding anything from scratch. Fix what is broken with minimal changes.
```

**Done when:** Going through the complete demo flow — Screens 1 → 2 → 3 → 4 → Screen 5 adversarial — works end to end on the deployed Phala Cloud instance with no mocked steps.

---

## Session S10 — Demo Prep
**Owner:** Both builders together
**Day:** Day 6
**Goal:** Smooth demo under 5 minutes, no new features

**Session Prompt:**
```
[PASTE CLAUDE.md HERE FIRST]

Everything is built and working. We are preparing for the demo tomorrow.

We need:
1. A demo script — the exact words to say for each screen, under 5 minutes total
2. A checklist of things to verify before going on stage
3. Two pitch slides content:
   - Slide 1: architecture diagram description (we will design it ourselves)
   - Slide 2: three use cases on the same pipeline

Also tell us: what questions will judges ask and what are the best answers?
```

**Done when:** You can run through the entire demo in under 5 minutes without looking at notes.

---

## File Structure Reference

When all sessions are complete your repo should look like this:

```
your-repo/
  CLAUDE.md                    ← system prompt for all Claude sessions
  TASKS.md                     ← this file
  app/
    main.py                    ← FastAPI app with all endpoints (S1, S4, S7)
    oracle.py                  ← Chromium credential fetching (S2, S8)
    extractor.py               ← LLM credential extraction (S3)
    redaction.py               ← filter f(X) = X' (S3)
    attestation.py             ← dstack-sdk wrapper (S4)
    onchain.py                 ← web3.py Base testnet calls (S6)
  contracts/
    PropsCertRegistry.sol      ← smart contract (S6)
  frontend/
    props_demo.html            ← all 5 screens, real API calls (S5, S6)
  Dockerfile                   ← (S1)
  docker-compose.yaml          ← (S1, S3, S8)
  requirements.txt             ← (S1, S2, S3, S6)
```

---

## Rules for Both Builders

1. **Always start with CLAUDE.md.** Every session. No exceptions.
2. **Test before moving on.** Do not stack unverified code on top of unverified code.
3. **One session = one goal.** Do not ask Claude to do two sessions worth of work in one chat.
4. **Tell Claude what works.** Before asking for the next thing, explain what is already working.
5. **If Claude goes wrong, start fresh.** New session with CLAUDE.md. Do not try to course-correct in a broken chat.
6. **Never mock in production.** If something does not work, fix it. Do not fake it in the frontend.
7. **Day 6 is demo prep only.** No new features on the last day. Period.

---

## Quick Reference — API Endpoints

| Endpoint | Session | Owner | Purpose |
|----------|---------|-------|---------|
| GET /api/attestation | S1 | B1 | Raw TDX attestation quote |
| POST /api/verify | S4 | B1 | Full pipeline — credentials in, certificate out |
| GET /api/certificate/:id | S4 | B1 | Fetch certificate by ID |
| GET /api/verify/:id | S4 | B1 | Verify certificate signature |
| POST /api/forge | S7 | B1 | Adversarial rejection demo |

---

## Quick Reference — Props Layers

| Layer | Session that builds it | How to verify it works |
|-------|----------------------|----------------------|
| L1 Oracle | S2 | Raw credential JSON returns from real NY medical board |
| L2 TEE + Attestation | S1, S4 | Real TDX quote returned with enclave measurement |
| L3 Pinned Model | S3 | Model hash captured and included in certificate JSON |
| L4 Data Redaction | S3 | raw_fields_stripped in response matches toggled-off fields |
| L5 Adversarial Defense | S7 | POST /api/forge returns real 403 for all three attack types |
