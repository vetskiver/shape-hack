# AGENTS.md

## Mission

Prepare this repo for a research-to-product hackathon. Optimize for:

- technical depth
- product viability
- progress made
- accelerator fit

## Repo Operating Context

### Current demo path

Do not break the existing demo flow:

1. FastAPI app serves the frontend from `/` and APIs from `/api/*`
2. `POST /api/verify` runs the oracle -> extraction -> redaction -> attestation pipeline
3. Certificates can be fetched and verified by ID
4. The deployed demo path is Phala Cloud + Ollama sidecar + Base Sepolia registry

### Run commands

Use the narrowest command that matches the task:

- Local API: `python app/main.py`
- Local API with relaxed local-dev flags: `SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true python app/main.py`
- Oracle-only run: `python app/oracle.py`
- Oracle local-dev run: `SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true TEST_LICENSE_NUMBER=209311 python app/oracle.py`
- Tests: `pytest tests/test_pipeline.py -v`
- Container stack: `docker compose up`

### Important env vars

Commonly relevant variables in this repo:

- `PORT`
- `ORACLE_TARGET`
- `ORACLE_PROFESSION`
- `TEST_LICENSE_NUMBER`
- `TEST_REGISTRATION_NUMBER`
- `SKIP_TLS_VERIFY`
- `SKIP_ENCRYPTION`
- `SKIP_OLLAMA_WAIT`
- `OLLAMA_URL`
- `OLLAMA_MODEL`
- `PINNED_MODEL_DIGEST`
- `CERT_STORE_DIR`
- `CORS_ORIGINS`
- `RATE_LIMIT_VERIFY`
- `RATE_LIMIT_VERIFY_REFILL`
- `RATE_LIMIT_FORGE`
- `RATE_LIMIT_FORGE_REFILL`
- `CHAIN_RPC_URL`
- `CHAIN_ID`
- `CHAIN_NAME`
- `CHAIN_EXPLORER`
- `CONTRACT_ADDRESS`
- `PRIVATE_KEY`
- `ENCLAVE_PRIVATE_KEY`
- `INTEL_TRUST_AUTHORITY_API_KEY`
- `INTEL_TRUST_AUTHORITY_URL`

### Deployment path

Current deployment path is Phala Cloud:

1. Build Docker image for `linux/amd64`
2. Push image tag
3. Update `docker-compose.yaml` image reference if needed
4. Deploy with `phala deploy -c docker-compose.yaml <cvm-id>`
5. Validate the live service root and core API endpoints

## Rules

- Prefer small, reversible changes.
- Do not break the current demo path.
- Be explicit about what is implemented vs mocked vs planned.
- For exploration tasks, write findings to `docs/*.md`.
- For evaluation tasks, do not change code unless explicitly asked.
- Before making code changes, identify run commands, tests, env vars, and deployment path.
- After making changes, validate the narrowest relevant scope and report exactly what was checked.

## Working Style

- Favor changes that strengthen the Props research story across L1-L5 rather than broad feature sprawl.
- Prefer production-shaped interfaces even when internals are mocked, but label mocks clearly.
- Preserve the current FastAPI + static frontend + Phala deployment shape unless there is a strong reason to change it.
- If a task is exploratory, add or update a focused doc instead of burying findings in chat.
- If a task is evaluative, produce findings first and separate them from recommendations.

## Standard Outputs

Keep these docs current when the task calls for them:

- `docs/repo-map.md`
- `docs/issues-found.md`
- `docs/hackathon-scorecard.md`
- `docs/deploy-plan.md`
- `docs/fix-priorities.md`
- `docs/demo-pack.md`

## Reporting Expectations

When you finish a task, report:

- what changed
- whether the change is implemented, mocked, or planned
- what commands or checks were run
- what was not validated
- any demo-path risk introduced or avoided

## Known Repo Notes

- README local-dev examples use Python 3.12, while the Docker image currently uses Python 3.11.
- `docker-compose.yaml` currently defaults `OLLAMA_MODEL` to `llama3.2:1b`, so verify model-related claims before editing demo or pitch materials.
- The current deployed path references Phala Cloud and Base Sepolia; avoid accidental changes to chain, CVM, or image assumptions without documenting them.
