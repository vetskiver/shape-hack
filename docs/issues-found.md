# Issues Found

This is an assessment-only pass. The items below are the highest-signal risks I found for a hackathon demo, ranked by how likely they are to confuse judges or break the live path.

## 1. Runtime guidance is out of sync with the container image

The README tells contributors to use Python 3.12 for local work, but the Docker image is built from `python:3.11-slim`.

Evidence:

- `README.md:44-65` says the prerequisites and install commands are for Python 3.12.
- `Dockerfile:1` pins the container to Python 3.11.

Why it matters:

This is a classic onboarding trap. A team member can follow the README, hit dependency or path differences, and lose time debugging an environment mismatch instead of the product.

## 2. The model story is drifting between docs and runtime defaults

The project narrative says the L3 model is Llama 3.2 3B, but the runtime defaults point to `llama3.2:1b` in both the compose file and the extractor module.

Evidence:

- `README.md:208-218` describes the S3 layer as “Llama 3.2 3B”.
- `docker-compose.yaml:31-33` defaults `OLLAMA_MODEL` to `llama3.2:1b`.
- `app/extractor.py:36-52` also defaults `MODEL_NAME` to `llama3.2:1b` and only accepts a pinned digest when configured.

Why it matters:

For this project, the model choice is part of the trust story, not a cosmetic detail. If the demo narrative, compose defaults, and actual attestation payload do not match, judges will spot the inconsistency immediately.

## 3. Deployment configuration is internally inconsistent

The current compose file points at image tag `s23`, while the README says the current image is `s4.1`.

Evidence:

- `docker-compose.yaml:12-14` uses `vetskiver/props-oracle:s23`.
- `README.md:185-193` says the current Docker image is `vetskiver/props-oracle:s4.1`.

Why it matters:

This makes the “what exactly is deployed?” question harder than it should be. It increases the chance that a deploy or rollback uses the wrong artifact, which is especially risky right before a demo.

## 4. Test coverage is still mostly smoke-level

The only test file explicitly states that it avoids Ollama, Phala Cloud, and network access. That is useful for unit checks, but it leaves the main end-to-end path untested.

Evidence:

- `tests/test_pipeline.py:1-8` says the tests use mock data and require no Ollama, no Phala Cloud, and no network.
- The repo has no obvious route-level or browser-driven integration test suite for `/api/verify`, `/api/forge`, or the frontend flow.

Why it matters:

The most important regressions here are integration regressions: API contract drift, certificate persistence issues, oracle failures, and deployment path breakage. Smoke tests help, but they do not prove the demo path.

## 5. The demo can quietly degrade to “works, but not really”

Two parts of the stack can fall back in ways that preserve a working-looking demo while weakening the product story.

Evidence:

- `frontend/index.html:7-9` imports Google Fonts from a remote CDN.
- `app/main.py:974-994` treats missing `CONTRACT_ADDRESS` or `PRIVATE_KEY` as a warning and skips on-chain storage.
- `scripts/deploy_contract.py:117-120` exits only when `PRIVATE_KEY` is absent during deployment, but the app itself can still run without on-chain permanence.

Why it matters:

If the network is flaky or the secrets are missing, the UI can still load and the backend can still issue certificates, but the result is a weaker demo: no custom typography, and potentially no on-chain permanence. That is avoidable fragility for a hackathon where the live experience matters.
