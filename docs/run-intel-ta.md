# Intel Trust Authority Completion

## What changed

- Updated [AGENTS.md](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/AGENTS.md) to include:
  - `INTEL_TRUST_AUTHORITY_API_KEY`
  - `INTEL_TRUST_AUTHORITY_URL`
- Updated [README.md](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/README.md) to make the Intel Trust Authority path explicit:
  - the app needs an **Attestation API key**
  - an Admin API key is not the right credential
  - the URL may need to be overridden for non-default regional tenants
  - the CVM must be redeployed after sealing the key

## Implemented vs blocked

- Implemented: repo/runtime support for Intel Trust Authority request auth and URL override is already present in `app/attestation.py`.
- Implemented: Phala compose/env path already exposes `INTEL_TRUST_AUTHORITY_API_KEY` and `INTEL_TRUST_AUTHORITY_URL`.
- Blocked: this environment does not have a real Intel Trust Authority **Attestation API key**, so the live verifier still returns `401 Unauthorized`.

## Exact validation performed

- Read the current Intel Trust Authority integration in:
  - [app/attestation.py](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/attestation.py)
  - [docker-compose.yaml](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/docker-compose.yaml)
  - [README.md](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/README.md)
- Checked agent/runtime context in [AGENTS.md](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/AGENTS.md)
- Verified the live failure mode is still the missing-key path:
  - `tdx_intel_verified: false`
  - `intel_details` includes `HTTP 401` and `No INTEL_TRUST_AUTHORITY_API_KEY was configured`
- Checked Intel Trust Authority official docs for:
  - Attestation vs Admin API keys
  - appraisal API usage

## Exact remaining blocker

The hard blocker is external, not in-repo:

1. Create or retrieve a real Intel Trust Authority **Attestation API key** from the Intel Trust Authority portal.
2. If needed, confirm the correct tenant/regional appraisal base URL.
3. Seal `INTEL_TRUST_AUTHORITY_API_KEY` into the Phala deployment env.
4. Redeploy the CVM and re-check `/api/verify/{id}` for `tdx_intel_verified: true`.

Without that external secret/account step, this path cannot be completed from this environment.
