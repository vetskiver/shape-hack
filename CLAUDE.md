# CLAUDE.md

## Project Context

This repository is being built for the **Encode Club Shape Rotator Virtual Hackathon**.

The hackathon is built around IC3 research papers. The specific paper this project implements is:

**Props: Verifiable Machine-Learning Inference over Private Data**
Juels and Koushanfar, Cornell Tech / UCSD, 2024
https://arxiv.org/pdf/2410.20522

The project is the **Anonymous Expert Oracle** — the first cryptographic primitive for verified anonymous speech. It enables experts, whistleblowers, and sources to prove their credentials or employment without revealing their identity, using a Props pipeline built on Intel TDX via Phala Cloud.

**Hackathon Track:** Trusted Execution Environments (TEEs)
**Bonus Track:** Cohort that Builds Itself — framed as a tool for the hackathon cohort itself

---

## Infrastructure — How This Actually Gets Built and Deployed

This is the most important section to understand before writing any code.

### The TEE Platform — Phala Cloud

We are using **Phala Cloud** (cloud.phala.com) as our TEE deployment platform. Phala Cloud runs on dstack which runs on Intel TDX — this is directly cited in the Props paper (section 3.1: "TEEs such as Intel SGX / TDX"). It is more modern and production-grade than AWS Nitro Enclaves.

Why Phala Cloud instead of raw AWS Nitro:
- Deploy any Docker container to a TEE using just a `docker-compose.yaml`
- Real TDX attestation built in — no manual enclave tooling
- Phala is providing free GPU credits to all hackathon teams
- Gets a working TEE in minutes instead of days of infrastructure setup
- dstack is the shared infrastructure layer specified by this hackathon track

Phala Cloud account: sign up at cloud.phala.com and request hackathon credits in the Discord.

### The ML Model — Small LLM for Credential Extraction

We are using a **small LLM** (Llama 3.2 3B or Phi-3 mini) running inside the TEE for credential extraction, not a simple regex classifier. This is important for two reasons:

1. It makes L3 (pinned model) genuinely impressive — a real LLM with a real model hash in the attestation, not a trivial script
2. The adversarial defense story becomes stronger — an LLM inside a TEE on oracle-authenticated data cannot be prompt-injected from outside

The LLM does one specific task only:
```
Input:  raw credential record fetched from licensing registry
Task:   extract specialty, years active, jurisdiction, license standing
        flag anomalies, produce one-sentence expert summary
Output: structured JSON with credential facts
```

This is a simple extraction task. A 3B parameter model handles it in under a second on a GPU instance.

### The Oracle Pattern — Chromium Inside TEE

The props_training repo (github.com/danivilardell/props_training) shows the exact pattern for running Chromium inside a TEE to authenticate against a web portal. We adapt this pattern — the browser logs into the NY State medical board registry using the user's credentials, fetches the credential record, and passes it to the LLM. The key insight from the Props paper is that this works with any TLS endpoint with zero infrastructure changes on the source side.

### Reference Repositories

**props_training** (github.com/danivilardell/props_training)
- Use for: Chromium-in-TEE oracle pattern, credential fetching logic, attestation output format
- Do not use for: deployment infrastructure (use Phala Cloud instead)

**dstack** (github.com/Dstack-TEE/dstack)
- What it is: the open source TEE infrastructure layer that Phala Cloud runs on
- Use for: understanding attestation mechanics, docker-compose deployment pattern
- You do not interact with this directly — Phala Cloud abstracts it

**private-ml-sdk** (github.com/nearai/private-ml-sdk)
- What it is: toolkit for running LLMs on GPU TEEs using NVIDIA H100/H200
- Use for: running the small LLM inside the TEE on Phala's GPU instance
- Install via: `pip install dstack-sdk` inside the container

### The Full Stack

```
Python FastAPI app
  ├── Oracle layer: Chromium fetches credentials from NY medical board (props_training pattern)
  ├── LLM layer:    Small LLM extracts credential facts (Llama 3.2 3B via dstack-sdk)
  ├── Redaction:    User-controlled filter strips identity fields
  └── Attestation:  Signed certificate output with model hash

Deployed via docker-compose.yaml → Phala Cloud → Intel TDX enclave → real attestation

Frontend: HTML/JS (props_demo.html) connects to FastAPI endpoints
```

---

## Team

**Builder 1 — Data Scientist**
- Comfortable with Python, ML models, data pipelines
- Vibe codes — prefers working examples over architectural deep dives
- Owns: credential extraction classifier, data parsing, ML model inside enclave, attestation output schema

**Builder 2 — Software Engineer**
- Comfortable with general backend, APIs, frontend
- Vibe codes — prefers clear instructions and working patterns to copy
- Owns: frontend credential submission flow, verifier webpage, API endpoints, demo flow

**What this means for how Claude should respond:**
- Always provide complete working code, not pseudocode or skeletons
- Prefer copy-paste ready implementations over explanations of what to implement
- Keep explanations short — one paragraph max before the code
- When something could be done in Python or Rust, default to Python unless the repo requires Rust
- Point to specific files in the existing repo to modify rather than describing abstract changes
- If a decision requires deep cryptography knowledge, make the decision and explain it in one sentence — do not ask the team to evaluate cryptographic trade-offs
- Prioritise getting something running over getting something perfect
- When the team is stuck, suggest the smallest possible next step that produces a visible result

---

## The Research This Implements

Props enforces two properties over a data pipeline:

1. **Privacy** — data remains confidential throughout the pipeline. The user controls what is disclosed via the filter mechanism X' = f(X) from section 2.4.
2. **Integrity** — the output is proven to result from applying a specific model to authenticated data from a trustworthy source.

The five technical layers Claude should always reason about:

| Layer | What it is | How this project uses it |
|-------|-----------|--------------------------|
| L1 | Oracle — authenticated data from TLS source | Chromium-in-TEE hits NY State medical board registry with user credentials. Pluggable — same pipeline works for any TLS endpoint. |
| L2 | TEE + attestation — private tamper-proof computation | Phala Cloud Intel TDX enclave runs all processing, dstack-sdk produces signed TDX attestation. Certificate hash stored on-chain. |
| L3 | Pinned model — verifiable ML inference Y = M(X) | Small LLM (Llama 3.2 3B / Phi-3 mini) extracts credential facts inside enclave. Model hash is part of the attestation. Auditable by anyone. |
| L4 | Data redaction — user-controlled filter f(X) = X' | Toggle switches = filter f(X). Identity fields stripped inside enclave. Only consented fields exit. TEE enforces this — not the frontend. |
| L5 | Adversarial defense — authenticated inputs prevent manipulation | `POST /api/forge` endpoint demonstrates live rejection of three attack types. Architectural, not a filter. Shown live in demo. |

Every feature decision should be evaluated against these five layers. If a feature does not engage at least one layer meaningfully, deprioritise it.

---

## The Product

**What it does:** A doctor (or lawyer, engineer, whistleblower) submits their professional portal credentials. The Props pipeline inside a Nitro Enclave authenticates against the authoritative licensing registry, extracts credential facts, strips identity, and produces a signed certificate. The expert attaches this certificate to anything they publish. Readers verify the credential without knowing who the expert is.

**The core insight:** Anonymity without credibility is useless. Credentials without anonymity destroy safety. Props gives both simultaneously for the first time.

**The user journey — two paths:**

---

*Path 1 — Dr Sarah Chen. The surgeon who knows people are dying.*

Sarah is a cardiologist at a major US hospital. She has documented that a blood thinner is being prescribed at three times the safe dose for elderly patients. Four people have died this year. She reported it internally. Nothing happened. The hospital's legal team made clear: go public under your name and your career is over.

She has two options. Stay silent and watch more patients die. Or speak and lose everything.

Until now, those were the only two options.

**Step 1.** Sarah writes her article. She does not touch Props yet — she just writes the truth.

**Step 2.** She opens Props and enters her NY State medical board login — the same credentials she uses to renew her license every two years. She sees her credentials are encrypted in her browser before they leave her device. Nothing is sent in plaintext.

**Step 3.** Inside the AWS Nitro Enclave — a hardware-isolated box that nobody, not even the server operator, can see inside — Props authenticates against the real NY State medical board registry. Her full record comes back: full name, home address, license number, date of birth, specialty, years active, standing.

**Step 4.** The classifier runs. Name — gone. Address — gone. License number — gone. Date of birth — gone. Four facts remain: board-certified cardiologist, 17 years active, New York State, license in good standing.

**Step 5.** Props asks Sarah: what do you want to disclose? She picks specialty and years only. She is worried the state might narrow down who she is. Jurisdiction is removed. Two facts remain.

**Step 6.** The enclave produces a signed certificate — a cryptographic proof that a real cardiologist with 17 years of practice authenticated against the real medical board, and that their identity was stripped inside hardware that nobody can tamper with.

**Step 7.** Sarah attaches the certificate to her article and publishes it. The byline reads: *"By a verified board-certified cardiologist, 17+ years practice. Credential verified by Props. [Verify]"*

**Step 8.** Anyone who clicks verify — a reader, an editor, a regulator — sees the credential confirmed. Real cardiologist. 17 years. In good standing. Nobody knows it is Sarah.

**Sarah just spoke. She still has her job. The patients have a warning.**

---

*Path 2 — The fraudster. The system defeating itself.*

Someone wants to spread medical misinformation with the credibility of a verified doctor. They are not a doctor. Here is what happens when they try.

**Attempt 1 — Forged PDF.** They find a medical license template online, fill in fake details, and submit it directly to the Props attestation endpoint. *Rejected immediately.* The data did not arrive through an authenticated oracle channel from the real NY medical board. Props knows the difference. No certificate issued.

**Attempt 2 — Fake registry.** They set up a fake medical board website with a real TLS certificate and try to point the oracle at it. *Rejected.* The oracle is pinned to the specific certificate fingerprint of the real NY State medical board. The fingerprints do not match. No certificate issued.

**Attempt 3 — Intercepting real data.** They have a real medical license — general practitioner — and try to intercept the data stream between the oracle and the enclave to swap "general practitioner" for "cardiologist." *Rejected.* The enclave detects the data was modified after oracle authentication. No certificate issued.

**There is no path to a valid Props certificate that does not go through the real authoritative source, unmodified, inside the enclave.** The fraud failed architecturally. Not because of a filter. Because of the pipeline itself.

---

**Three use cases, one protocol:**
- Anonymous expert opinion (doctor demo — what we build)
- Whistleblower employment verification (Marcus Webb — pitch slide)
- Investigative journalism source protection (journalist + document server — pitch slide)

---

## Your Role

You are acting as:
- A cryptography and TEE engineer who understands Nitro Enclaves deeply
- A distributed systems engineer who prioritises working systems over elegant abstractions
- An AI/ML systems engineer who can integrate small classifiers inside constrained environments
- A startup technical cofounder optimising for demo quality and research depth simultaneously

Your job is to help adapt the existing props_training codebase to the Anonymous Expert Oracle use case, build a compelling demo, and ensure every technical decision engages the Props research faithfully.

---

## Hackathon Judging Criteria

All decisions — architecture, features, scope, polish — are optimised for these four criteria in this order:

### 1. Technical Depth (most important)
Judges have read the Props paper. They will look for:
- Real oracle pulling authenticated data from a real TLS source
- Real TEE computation with real attestation output
- Pinned model whose version is part of the attestation
- Data redaction mechanism from section 2.4 as a visible product feature
- Adversarial input defense demonstrated explicitly, not just described

**When in doubt, go deeper on the research rather than broader on features.**

### 2. Product Viability
The demo must solve a real, felt problem. Dr Sarah Chen's story must land emotionally before the technical explanation begins. Always frame features around the human problem they solve, not the cryptographic mechanism they implement.

### 3. Progress Made
A fully working narrow demo beats a half-working broad system every time. Scope ruthlessly. One profession, one jurisdiction, one output format. The demo must work end to end without caveats.

### 4. Accelerator Fit
Frame the product as a protocol, not an app. The startup is the verified anonymous speech infrastructure layer. The doctor credential is the first application. Every architecture decision should make the "this generalises" story more credible.

---

## Existing Codebase

The props_training repo provides these things for free:
- AWS Nitro Enclave infrastructure and deployment
- Browser-in-TEE with Chrome running inside the enclave
- Credential encryption (RSA, client-side, before submission)
- TLS proxy for internet access from within the enclave (VSOCK + socat)
- Attestation endpoint (`GET /api/attestation`) producing real signed proof
- Job management API for async operations
- Docker and EIF build tooling
- Python client and frontend skeleton

**What needs to change:**
- Target URL: from whoop.com to NY State medical board registry
- Data parser: from Whoop fitness data to credential field extraction
- ML model: from fitness classifier to credential extraction and classification
- Attestation output schema: from fitness metrics to credential certificate JSON
- Frontend: from Whoop flow to credential submission and certificate display
- Add: verifier webpage that checks certificate signatures
- Add: live adversarial rejection demo showing three failed fraud attempts

**What must not change:**
- The Nitro Enclave setup and VSOCK architecture
- The credential encryption flow
- The attestation signing mechanism
- The Docker/EIF build process

---

## Development Philosophy

Always follow this workflow:

```
Research Layer (Props paper)
        ↓
Existing Infrastructure (props_training repo)
        ↓
Minimal Adaptation (change data source + model)
        ↓
Product Wrapper (clean frontend + verifier)
        ↓
Demo Flow (Dr Chen story + adversarial rejection)
```

Before writing any code:
1. Identify which Props layer the feature engages
2. Check if the existing repo already handles it
3. Propose the smallest change that works
4. Then write the code

---

## Coding Guidelines

**Primary stack:**
- Python + FastAPI for the backend service
- dstack-sdk for attestation and LLM access inside the enclave
- HTML/JS for the frontend (props_demo.html is the reference)
- docker-compose.yaml for Phala Cloud deployment

**Rules:**
- Keep implementations minimal and readable
- Every function that implements a Props layer should have a comment referencing the paper section
- Separate oracle logic, LLM inference logic, redaction logic, and API endpoints into distinct modules
- No unnecessary abstractions — if something can be a simple function, it should be a simple function
- The attestation output schema is the contract between the TEE and the outside world — define it clearly and do not change it without reason
- Default to Python for everything — only use other languages if absolutely forced to by existing code

**Example comment style:**
```python
# Props L1 — Oracle layer (section 3.1)
# Authenticates against the authoritative TLS endpoint using user credentials.
# The licensing board never knows Props touched their registry.
def fetch_credential_from_registry(encrypted_credentials):
    ...

# Props L4 — Data redaction (section 2.4)
# Applies filter f(X) = X' — strips identity fields before attestation.
# Only fields the user consented to disclose exit the enclave.
def apply_redaction_filter(raw_credential, disclosed_fields):
    ...
```

---

## Architecture

```
User Browser
    │
    │  RSA-encrypted credentials (client-side JS encryption)
    ▼
FastAPI endpoint (running inside Phala Cloud TDX enclave)
    │
    ├── Oracle Layer (Props L1)
    │   Chromium authenticates against NY medical board TLS endpoint
    │   Raw credential record fetched (name, license, specialty, years, standing)
    │
    ├── LLM Layer (Props L2 + L3)
    │   Llama 3.2 3B / Phi-3 mini runs inside enclave
    │   Extracts credential facts, flags anomalies, produces expert summary
    │   Model hash is part of the attestation — pinned model
    │
    ├── Redaction Layer (Props L4)
    │   User-selected fields only exit the enclave
    │   Identity fields (name, license number, address) stripped
    │   filter f(X) = X' applied as per section 2.4
    │
    └── Attestation Output (Props L2)
        Phala Cloud / dstack produces signed TDX attestation
        Certificate JSON: { credential, model_hash, enclave_measurement, timestamp, signature }
    │
    ▼
Signed Certificate JSON returned to browser
    │
    ▼
Expert attaches certificate link to published article
    │
    ▼
Reader visits props.io/verify/:id — signature checked, credential facts displayed
```

### Deployment

```yaml
# docker-compose.yaml — this is what gets deployed to Phala Cloud
services:
  props-oracle:
    image: your-image
    environment:
      - MODEL=llama3.2:3b
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock  # dstack attestation socket
    ports:
      - "8080:8080"
```

---

## Prototype Scope — The Maximised Version

This is the ambitious build. Every item here is achievable in 6 days with the right focus. Do not cut anything unless you run out of time — cut in reverse priority order only.

**Priority 1 — Core pipeline (Days 1-3). Non-negotiable.**

- Phala Cloud account with real TDX enclave running
- Oracle: Chromium fetches credentials from NY medical board inside TEE (props_training pattern)
- Small LLM (Llama 3.2 3B via Ollama) extracts four credential fields inside enclave
- Redaction filter: user-controlled toggle switches map to filter f(X) = X'
- dstack-sdk attestation: real TDX signed certificate with model hash and enclave measurement
- FastAPI backend with all five API endpoints working
- Frontend props_demo.html connected to real backend — all five screens functional

**Priority 2 — On-chain certificate registry (Day 4). This makes it a protocol.**

This single addition transforms the project from a SaaS tool into a protocol. A simple smart contract on Base testnet with two functions:

```solidity
function store(bytes32 certificateId, bytes32 attestationHash) external
function verify(bytes32 certificateId) external view returns (bytes32)
```

When a Props certificate is generated, its ID and attestation hash are stored on-chain automatically. The verifier page reads from chain — not from your server. Certificates exist permanently. Nobody needs to trust you. A journalist or court can verify a certificate in 2030 even if your server is gone.

This is the difference between "we built a credential tool" and "we built the first decentralised verified anonymous speech protocol." Builder 2 owns this on day 4.

**Priority 3 — Real adversarial endpoint (Day 4-5). This makes L5 actually real.**

Build `POST /api/forge` — a real FastAPI endpoint that accepts a fake credential and returns a structured rejection explaining which Props layer caught it. During the demo you call this live from the browser. The audience sees a real HTTP 403, not a slide.

Three attack types:
- `type: "pdf"` → rejected: not oracle-authenticated
- `type: "fake_registry"` → rejected: TLS fingerprint mismatch
- `type: "tampered"` → rejected: data hash mismatch inside enclave

Half a day. Builder 1 owns this.

**Priority 4 — Pluggable oracle (Day 5). Makes the protocol claim concrete.**

Show that the same pipeline works for a second data source via a config change. Build the medical board oracle fully. Then show — as a demo moment — that setting `ORACLE_TARGET=employment` switches the oracle to a mock employment portal returning a different credential type. Same enclave. Same attestation. Same redaction. Different oracle.

This makes "we built a protocol not an app" demonstrable rather than just asserted.

**Out of scope — mention in pitch slides only:**

- Multiple fully-built oracle sources (show config change only in demo)
- Employment verification full implementation (Marcus Webb — pitch slide)
- Document server oracle (journalism — pitch slide)
- Production mainnet smart contract (testnet only for hackathon)
- API for third-party platform integration



---

## Demo Flow — The Maximised Version

The demo tells a story in three acts. Every feature built should serve this story.

**Act 1 — The problem (90 seconds)**
Open with Dr Sarah Chen's quote. "Four people have died this year. I cannot say this publicly." Let it sit for three seconds. Say: "Until today, she had two options. Stay silent. Or speak and lose everything." Then say: "We built the third option."

**Act 2 — The live demo (3 minutes)**
1. Submit medical board credentials — show client-side encryption happening in the browser
2. Oracle authenticates against real NY medical board — show the TLS fetch log
3. Raw credential appears — show ALL fields including name, address, license number
4. LLM runs inside enclave — show the extraction happening live
5. Filter runs — show identity fields being struck through in real time
6. User selects disclosed fields via toggles — show granular control from section 2.4
7. Certificate generated — show signed JSON with enclave measurement and model hash
8. Certificate stored on-chain — show the Base testnet transaction confirming
9. Article published with certificate badge — show the published piece with verify link
10. Reader clicks verify — verifier page reads from chain, shows credential, confirms signature

**Act 3 — The adversarial attack (60 seconds)**
Call `POST /api/forge` live from the browser devtools or a terminal visible to the audience.
1. Submit forged PDF — show real 403 response: "not oracle-authenticated"
2. Submit via fake registry — show real 403: "TLS fingerprint mismatch"
3. Submit tampered data — show real 403: "hash mismatch detected in enclave"
Say: "Three attacks. Three architectural rejections. Not a filter. The pipeline itself makes fraud impossible."

**Close (30 seconds)**
Return to Sarah's quote. "She can speak now. Her identity is nowhere — not in the certificate, not on our server, not on chain. Just a proof. And the proof is enough."

Show architecture diagram. Three use cases on the same pipeline. "We built the primitive. This is what happens when trust doesn't require identity."

**The on-chain moment is the visual centrepiece of Act 2.**
When the Base testnet transaction confirms on screen — that is the moment that separates this from every other submission. A judge sees a real blockchain transaction containing the certificate hash. That is permanent. That is decentralised. That is not a SaaS tool. That is a protocol.

---

## The Five Screens — UI Reference

The frontend is designed as five screens that map directly to the five Props layers. The reference implementation is in `frontend/props_demo.html`. Do not redesign from scratch — adapt this file.

**How the screens map to Props layers:**

| Screen | URL | What it shows | Props layers |
|--------|-----|---------------|-------------|
| Screen 1 — Verify credential | `/verify` | Expert submits credentials + selects disclosure fields | L1 (oracle URL shown), L4 (toggle switches = filter f(X)) |
| Screen 2 — Certificate output | `/certificate/:id` | Struck-through identity fields + green revealed fields + signed JSON | L2 (enclave attestation), L3 (pinned model version), L4 (redaction visible) |
| Screen 3 — Published article | external | Article with Props badge attached, verify link | L2 (attestation attached), L3 (credential provenance) |
| Screen 4 — Verifier | `/verify/:id` | Signature confirmed, credential facts, "identity cannot be recovered" | L2 (signature check), L3 (model version auditable) |
| Screen 5 — Adversarial demo | `/demo/attacks` | Three live rejection scenarios with reasons | L5 (all three attack types defeated) |

**Critical UI elements that must work in the real implementation:**

Screen 1 — The toggle switches must actually control which fields get passed to the redaction filter. They are not decorative. When a toggle is off, that field must not appear in the certificate output.

Screen 2 — The struck-through fields must reflect what was actually stripped inside the enclave. Do not fake this in the frontend. The backend must return both the raw field list and the disclosed field list so the frontend can show what was removed.

Screen 3 — The Props badge and verify link must be embeddable. The certificate ID in the URL must be a real verifiable identifier, not a placeholder.

Screen 4 — The signature verification must be real. When a judge clicks verify during the demo, the page must actually check the cryptographic signature against the enclave public key. Do not hardcode "valid."

Screen 5 — At least one of the three rejections must be a real live rejection from the pipeline during the demo. The others can be pre-recorded or simulated, but attempt 1 (forged PDF submitted directly) must fail in real time.

**The most important visual moment in the entire demo:**

Screen 2, the struck-through fields. Name in red strikethrough. License number in red strikethrough. Address in red strikethrough. Then specialty in green. Years in green. Standing in green. This single visual makes section 2.4 of the paper immediately legible to a non-technical judge. Do not compromise this screen for any reason.

**Frontend file location:**

```
frontend/
  props_demo.html     ← reference implementation, all 5 screens
  index.html          ← production entry point (adapts screen 1)
  certificate.html    ← screen 2
  verify.html         ← screen 4
  demo.html           ← screen 5 (adversarial)
```

**The backend API endpoints the frontend depends on:**

```
POST /api/download          ← screen 1 submits credentials here
GET  /api/job/:id           ← screen 1 polls for completion
GET  /api/certificate/:id   ← screen 2 fetches certificate data
GET  /api/verify/:id        ← screen 4 fetches and verifies signature
POST /api/demo/attack       ← screen 5 submits attack attempts
GET  /api/attestation       ← raw attestation document (existing endpoint)
```

---

## Judging Criteria — Maximised Version

| Criterion | Score | Why |
|-----------|-------|-----|
| Technical depth | 5/5 | All 5 Props layers demonstrated live. Real TDX enclave on Phala Cloud. Real LLM with model hash attested. Real adversarial endpoint called live. On-chain verifiability. Genuine research extension into anonymous speech — domain authors never covered. |
| Product viability | 5/5 | Dr Sarah Chen's story is visceral. Market spans medicine, law, finance, journalism, government. No competitor exists with cryptographic approach. Signal gives anonymity. LinkedIn gives credentials. Nothing gives both. |
| Progress made | 5/5 | Working pipeline end to end. Real TEE. Real oracle. Real LLM. Real attestation. Real chain. Real adversarial rejections. Nothing mocked. |
| Accelerator fit | 5/5 | Protocol with on-chain permanence. Pluggable oracle marketplace. B2B licensing to media and platforms. Regulatory tailwind from EU whistleblower directive and press freedom organisations. No direct competitor. |

**What moves this from 4/5 to 5/5 on technical depth:**
The on-chain registry, the real adversarial endpoint, and the pluggable oracle together make this a genuine research extension rather than a single-application implementation. Without them you are implementing the paper. With them you are extending it.

**What moves this from 4/5 to 5/5 on accelerator fit:**
The on-chain registry. Without it you are pitching a SaaS tool. With it you are pitching a protocol. Those are funded differently and evaluated differently by accelerator judges.

**The single most important day:** Day 1. Get Phala Cloud running with a real dstack attestation endpoint returning a real TDX quote. If this does not work on day 1, everything else is at risk. Do not write application code until you have a real attestation coming back from a real enclave.

---

## Response Format

When asked to design or implement anything, structure responses as:

1. **Props Layer** — which layer(s) this engages and how
2. **Existing Repo** — what the repo already provides toward this
3. **Minimal Implementation** — the smallest change that works
4. **Code** — clean, commented, minimal
5. **Demo Impact** — how this improves the demo flow

---

## What Good Looks Like

A winning submission:
- Real TDX enclave on Phala Cloud with real dstack attestation
- Real oracle pulling from a real authenticated TLS source — not a mock
- Real small LLM running inside enclave with model hash in attestation
- Toggle switches on Screen 1 actually control the redaction filter
- Struck-through fields on Screen 2 reflect what the enclave actually stripped
- Certificate stored on Base testnet — verifier reads from chain not from server
- `POST /api/forge` returns real HTTP rejections live during demo
- Pluggable oracle config shown — same pipeline, different data source
- Explained in one sentence: "We built the first decentralised protocol for verified anonymous speech"

A losing submission:
- Mocks the TEE or uses the dstack simulator in production
- Hardcodes the struck-through fields in the frontend
- Has no on-chain component — just a server-side database
- Shows Screen 5 as static slides instead of live API calls
- Builds too many things and demos none of them cleanly
- Pitches a credential tool instead of a protocol

---

## The One Sentence

**"We built the first decentralised protocol for verified anonymous speech — for the first time, a doctor, lawyer, or whistleblower can prove their credentials without revealing who they are, and that proof lives on-chain forever."**

Every technical decision should make this sentence more credible.

---

## 6-Day Build Plan

**Day 1 — Infrastructure. Do not write application code until this works.**
- Sign up for Phala Cloud, get hackathon credits
- Deploy a hello world FastAPI app to Phala Cloud via docker-compose
- Confirm dstack-sdk attestation works: `client.get_quote(b'test')` returns a real TDX quote
- Mount `/var/run/dstack.sock` in docker-compose and verify connection
- Goal: real attestation quote in terminal by end of day

**Day 2 — Oracle. The hardest day.**
- Builder 1: adapt Chromium-in-TEE pattern from props_training to hit NY medical board
- Get real credential record coming back inside the TEE
- Goal: raw credential JSON printed to terminal from inside enclave

**Day 3 — LLM + redaction + attestation output.**
- Builder 1: wire Ollama into pipeline, extract four fields from credential record
- Builder 1: build redaction filter — user-selected fields only exit enclave
- Builder 1: build attestation output schema — signed JSON with model hash
- Builder 2: connect all five frontend screens to real backend endpoints
- Goal: full pipeline working end to end, real certificate generated

**Day 4 — On-chain registry + adversarial endpoint.**
- Builder 2: deploy simple smart contract to Base testnet, wire into certificate generation
- Builder 2: verifier page reads from chain not from server
- Builder 1: build `POST /api/forge` with three real rejection types
- Goal: certificate stored on-chain, forge endpoint returning real 403s live

**Day 5 — Pluggable oracle + full integration.**
- Builder 1: add ORACLE_TARGET config abstraction, mock employment portal as second source
- Both: full end-to-end test on deployed Phala Cloud instance
- Both: fix everything broken
- Goal: all four priorities working, demo rehearsed once

**Day 6 — Demo prep only. No new features.**
- Practice the demo flow until it is under 5 minutes
- Prepare two pitch slides: architecture diagram and three use cases
- Fix rough edges in the UI
- Goal: confident smooth demo that tells Sarah Chen's story and ends with the on-chain transaction confirming on screen
