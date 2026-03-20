# Hackathon Scorecard

This scorecard evaluates the current repo as a hackathon submission, not as a pitch deck. It is intentionally critical and based on the implementation that exists in the tree today.

The paper is useful because it clarifies the intended bar:

- secure data sourcing from an authentic deep-web source
- a pinned model/environment for inference
- privacy-preserving control over what data is released
- constrained adversarial inputs through authenticated provenance

The repo clearly targets those pillars, but it does not fully realize the paper’s strongest version of them. In particular, it demonstrates a practical TEE-backed pipeline and signed outputs, but not a formal proof that `Y = M(X)` for an exact model/environment specification, and it does not offer the paper’s more general filter story beyond field-based redaction.

## 1) Technical Depth

**Score: 8/10**

**Strengths**

- The system is not a thin wrapper around a single model call. It has a real multi-stage pipeline: oracle fetch, extraction, redaction, attestation, and optional on-chain storage in [`app/main.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/main.py), [`app/oracle.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/oracle.py), [`app/extractor.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/extractor.py), [`app/redaction.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/redaction.py), and [`app/onchain.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/onchain.py).
- The trust story is unusually deep for a hackathon repo: TDX enclave integration, enclave-derived keys, TLS pinning, model digest pinning, and certificate verification are all represented in code and not just in prose.
- The paper’s core “props” building blocks are visibly present: a secure data source, a pinned model, and user-controlled redaction.
- There is real adversarial framing in the product surface. The `forge` endpoint and the L1-L5 structure show the team has thought about attack rejection, not just happy-path extraction.
- The on-chain layer is implemented without relying on heavyweight web3 tooling, which is a strong engineering signal: raw JSON-RPC, Keccak, RLP, and secp256k1 signing are all present in [`app/onchain.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/onchain.py).

**Weaknesses**

- Some of the “research depth” still reads as over-asserted compared with what is actually proven in the repo. The paper’s pinned-model concept is broader than “log a model digest,” but the repo mostly demonstrates measured-and-pinned model usage rather than a composable proof over an exact `(E, M)` specification.
- The README and comments strongly imply a production-grade pinned-model story, but the compose default still points at `llama3.2:1b` while the docs talk about `llama3.2:3b`, which weakens trust in the measurement narrative.
- The local-dev path includes several escape hatches (`SKIP_TLS_VERIFY`, `SKIP_ENCRYPTION`, `SKIP_MODEL_PIN`), which is practical, but it also means the security claims are easy to bypass in the very environment judges may test first.
- The test suite is narrow. [`tests/test_pipeline.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/tests/test_pipeline.py) covers redaction, certificate signing, and forge rejection, but it does not exercise the full FastAPI path, Playwright scraping, or a real on-chain round trip.
- The codebase is impressive, but some of the depth is concentrated in infrastructure-heavy mechanisms that are hard for a judge to independently validate during a short demo session.

## 2) Product Viability

**Score: 5.5/10**

**Strengths**

- The value proposition is clear: anonymous speech with verifiable credentials. That is legible, differentiated, and easy to explain at a high level.
- The target users are plausible and interesting: doctors, lawyers, journalists, and whistleblowers. That gives the project stronger narrative weight than a generic “AI proof” demo.
- The repo already includes a public deployment URL, a contract address, and a frontend, which means the product is at least shaped like something that can be shown outside the terminal.

**Weaknesses**

- The product still looks more like a protocol demo than a product people could adopt tomorrow. There is no obvious customer workflow, onboarding path, or pricing integration beyond a stated B2B idea in the README.
- The user journey is operationally heavy: credential entry, enclave processing, model dependency, certificate issuance, and chain verification are all part of the flow. The paper’s promise is stronger than the current product shape; the repo has not yet turned that promise into a low-friction workflow.
- The current system depends on multiple brittle external pieces at once: Phala Cloud, Ollama, Playwright, government registry availability, and Base Sepolia. That makes reliability and support burden a real concern.
- The medical-board demo is strong as a proof of concept, but it is a narrow wedge. The broader “anonymous expert oracle” market is compelling, yet the repo does not yet show a clear path from niche proof to repeatable product use.

## 3) Progress Made

**Score: 8.5/10**

**Strengths**

- This is a substantial build, not a concept mock. The repo contains a working FastAPI service, a static frontend, a live deployment path, an oracle layer, an extraction layer, an attestation layer, a contract, a verification SDK, and smoke tests.
- The README’s session table shows the project has moved through multiple integration milestones, and the codebase reflects that history rather than a single unfinished spike.
- The presence of a deployed URL and a contract address indicates the team has already crossed the hardest “nothing runs” stage.
- The frontend is not a throwaway placeholder. [`frontend/index.html`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/frontend/index.html) is a custom SPA with multiple screens, stateful UI, and explicit L1-L5 framing.

**Weaknesses**

- The repo still shows signs of integration drift. The README, compose defaults, and code comments do not always agree on model size, which is exactly the kind of inconsistency that hurts demo confidence.
- The current test coverage is mostly module-level smoke checking rather than end-to-end validation of the actual deployed path.
- There is a large difference between “implemented in code” and “proven stable in production.” The repo is clearly beyond prototype stage, but not yet at “boringly reliable” stage.

## 4) Accelerator Fit

**Score: 7.5/10**

**Strengths**

- The project fits a TEE and cryptography-heavy accelerator very well. It is explicitly anchored in Props research, Intel TDX, enclave attestation, and verifiable inference.
- The technical story is research-forward without being purely academic. There is enough product framing to make it relevant to a hackathon judge or accelerator mentor.
- The repo shows good ecosystem awareness: a frontend, an SDK, deployment scripts, and a contract make the project easier to package for a cohort or demo circuit.

**Weaknesses**

- The accelerator fit is strongest for a research-to-demo program, not yet for a growth-stage product accelerator. The repo does not yet show a repeatable acquisition channel or a narrow paid use case with evidence.
- The story is very infrastructure-specific. If an accelerator values distribution or customer pull over cryptographic sophistication, the current repo will need a clearer product thesis.
- The codebase still needs cleanup around operational correctness before it becomes an easy accelerator showcase. Right now, the technical ambition is higher than the product polish.

## Bottom Line

This is a strong hackathon submission with real technical substance. The biggest upside is depth: the repo does real work across oracle authentication, attestation, redaction, and on-chain verification. The paper makes it clear that this kind of pipeline is the right shape, and the repo captures that shape credibly.

The biggest risk is credibility: a judge will notice the implementation drift, the narrow test coverage, and the fact that the repo demonstrates the paper’s architecture more than its strongest formal guarantee. It is more convincing as a research prototype than as a polished customer-facing product.

If the goal is to win a TEE-focused hackathon, this is in good shape. If the goal is to convince an accelerator that this is already a viable business, the repo still needs sharper reliability, cleaner evidence, and a more concrete buyer story.
