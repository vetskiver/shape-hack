# Repository Map

## What This Repo Is

This is a Python-first Props prototype for the “Anonymous Expert Oracle” demo. The codebase wires together:

- an authenticated oracle that fetches licensing data from a real TLS source
- a pinned-model extraction step using Ollama
- an enclave-side redaction filter
- TDX-style attestation and certificate signing
- optional on-chain certificate storage on Base Sepolia
- a static frontend served directly by FastAPI

The repo is intentionally lightweight. There is no JS build system, no web framework beyond FastAPI, and no separate backend service split.

## Top-Level Structure

- `app/` - main service and pipeline modules
- `frontend/` - single-file SPA served at `/`
- `contracts/` - Solidity registry contract
- `sdk/` - Python verification SDK
- `scripts/` - deployment and verification helpers
- `tests/` - smoke tests for pipeline logic
- `examples/` - sample verifier client and oracle config
- `Dockerfile` - container image for the app
- `docker-compose.yaml` - local/Phala runtime with Ollama sidecar
- `phala.toml` - Phala deployment metadata

## Core Architecture

### `app/main.py`

This is the service entrypoint and orchestration layer. It:

- starts FastAPI
- serves the static frontend
- exposes the `/api/*` routes
- decrypts browser-submitted credentials when needed
- stores certificates on disk
- applies request validation and rate limiting
- wires together oracle -> extraction -> redaction -> attestation -> on-chain storage

Key API routes in this file:

- `GET /`
- `GET /health`
- `GET /api/info`
- `GET /api/tls-status`
- `GET /api/developer`
- `GET /api/oracles`
- `GET /api/public-key`
- `GET /api/attestation`
- `GET /api/tdx-key`
- `POST /api/verify`
- `GET /api/certificate/{certificate_id}`
- `GET /api/verify/{certificate_id}`
- `POST /api/forge`

### `app/oracle.py`

Implements the L1 oracle layer. It supports two data sources:

- `medical_board` - Chromium/Playwright scrape of the NYSED verification portal
- `attorney` - structured NY attorney registry data via data.ny.gov

The oracle code also handles TLS fingerprint pinning, local-dev bypass flags, and the authenticated-data envelope consumed downstream.

### `app/extractor.py`

Implements the L3 pinned-model step.

- defaults to Ollama at `OLLAMA_URL`
- defaults to `OLLAMA_MODEL`
- hard-fails if the expected model digest cannot be read
- can fall back to direct extraction for some structured cases

### `app/redaction.py`

Implements the L4 consent filter.

- always strips identity fields
- only discloses fields selected by the user
- uses oracle-type-specific field sets

### `app/attestation.py`

Implements the L2 signing and attestation layer.

- derives an Ed25519 signing key from dstack when running in a real enclave
- emits a TDX quote when available
- embeds the payload hash into the attestation structure
- verifies both signatures and quote structure for returned certificates

### `app/onchain.py`

Implements optional on-chain permanence.

- stores and verifies certificate hashes via raw JSON-RPC
- defaults to Base Sepolia
- avoids web3.py and Foundry dependencies

### `frontend/index.html`

A single static HTML app that the API serves directly. It contains the product UI, layer status visuals, and the demo flow. There is no frontend build step in the repo.

### `sdk/props_verify`

The Python verifier SDK for external consumers. This is the portable client-facing surface for checking certificates from another app or script.

## Entry Points

Primary runtime entry points:

- `python app/main.py`
- `python app/oracle.py`
- `pytest tests/test_pipeline.py -v`
- `docker compose up`
- `phala deploy -c docker-compose.yaml <cvm-id>`

Useful helper entry points:

- `python scripts/deploy_contract.py`
- `python scripts/verify_attestation.py`
- `python examples/verify_certificate.py`

## Runtime Data Flow

For `POST /api/verify`:

1. The request enters FastAPI with either plaintext `credentials` for local dev or `encrypted_credentials` for browser-to-enclave flow.
2. `app/main.py` validates the request and decrypts if needed.
3. `app/oracle.py` fetches source data from the configured oracle.
4. `app/extractor.py` derives the disclosable credential facts.
5. `app/redaction.py` strips identity fields and applies the consent filter.
6. `app/attestation.py` signs the payload and attaches any TDX quote data.
7. `app/main.py` persists the certificate JSON.
8. `app/onchain.py` best-effort stores the payload hash on-chain.
9. The API streams progress events and then returns the certificate.

For `GET /api/verify/{certificate_id}`:

1. Load the certificate from the local certificate store.
2. Verify the Ed25519 signature.
3. Check the TDX quote if present.
4. Verify on-chain presence against the registry contract.
5. Return trust metadata plus the disclosed credential facts.

## Important Environment Variables

Core app:

- `PORT`
- `CERT_STORE_DIR`
- `CORS_ORIGINS`
- `RATE_LIMIT_VERIFY`
- `RATE_LIMIT_VERIFY_REFILL`
- `RATE_LIMIT_FORGE`
- `RATE_LIMIT_FORGE_REFILL`
- `SKIP_OLLAMA_WAIT`

Oracle and extraction:

- `ORACLE_TARGET`
- `ORACLE_PROFESSION`
- `TEST_LICENSE_NUMBER`
- `TEST_REGISTRATION_NUMBER`
- `SKIP_TLS_VERIFY`
- `SKIP_ENCRYPTION`
- `OLLAMA_URL`
- `OLLAMA_MODEL`
- `PINNED_MODEL_DIGEST`
- `SKIP_MODEL_PIN`
- `ENCLAVE_PRIVATE_KEY`

On-chain:

- `CHAIN_RPC_URL`
- `CHAIN_ID`
- `CHAIN_NAME`
- `CHAIN_EXPLORER`
- `CONTRACT_ADDRESS`
- `PRIVATE_KEY`

## Local Run Path

The narrowest useful local commands are:

- `python app/main.py` for the API and frontend
- `SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true python app/main.py` for relaxed local-dev mode
- `python app/oracle.py` for the oracle module by itself
- `SKIP_TLS_VERIFY=true SKIP_ENCRYPTION=true TEST_LICENSE_NUMBER=209311 python app/oracle.py` for local oracle testing
- `pytest tests/test_pipeline.py -v` for module-level smoke tests

The repo’s tests are intentionally lightweight and do not require Ollama, Phala Cloud, or network access.

## Deployment Path

Current deployment path is Phala Cloud:

1. Build the image for `linux/amd64`.
2. Push the tag to the registry.
3. Update `docker-compose.yaml` if the image tag changed.
4. Deploy with `phala deploy -c docker-compose.yaml 6faa38933e632ca8dd2795fa68ad043c0bb6ad82`.
5. Validate the live root URL and the core API endpoints.

The runtime also depends on:

- the `/var/run/dstack.sock` mount for enclave features
- an Ollama sidecar
- a valid `CONTRACT_ADDRESS` and `PRIVATE_KEY` for on-chain storage

## Practical Notes

- The FastAPI app has a local certificate store, but if disk persistence fails it can fall back to memory-only mode.
- The oracle and attestation layers are designed to keep working outside a real enclave, but the trust level is lower there.
- The repo intentionally treats local-dev bypass flags as unsafe in production.
