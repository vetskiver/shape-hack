# Execution Board

This board reflects the next highest-leverage implementation tasks after the first readiness-focused pass. These tasks are intentionally small, product-facing, and aimed at making the live website and deploy path more truthful and reliable.

## Frontend

### Top task

Make the website honor the backend's actual readiness contract, not just backend reachability.

### Why this is first

The current frontend can still enable submit when the backend is reachable but not actually ready to verify. That creates a judge-facing mismatch between what the UI promises and what the API can really do.

### Required outcome

- Screen 1 must read `verify_enabled`, `status`, `blocking_issues`, and `warnings` from `GET /api/info`
- Submit must stay blocked when the backend reports `verify_enabled=false`
- The readiness panel must explain the real backend state instead of only transport state
- The fix must preserve the existing live flow and local-dev plaintext fallback

### Validation target

Validate only the Screen 1 readiness and submit-enable flow against the website/app behavior.

## Backend

### Top task

Extend backend readiness so the "ready" path requires real on-chain prerequisites for production-style runs, and fail early when on-chain persistence is not actually available.

### Why this is first

Right now the product can still issue certificates while on-chain storage is skipped, which weakens the trust story and makes the live demo look stronger than the actual runtime guarantees.

### Required outcome

- Readiness must include an explicit on-chain check
- Production-style readiness must not report `ready_for_verify` when required on-chain config is absent
- `POST /api/verify` must fail early with a clear readiness reason if on-chain is required but unavailable
- Keep local-dev escape hatches explicit and avoid unrelated refactors

### Validation target

Validate only the readiness and verify-gating API path, including the on-chain readiness condition.

## Infra / Deploy

### Top task

Align deploy truth across Docker/config/docs so the live path has one canonical runtime story.

### Why this is first

The repo still has visible drift around Python version, model target, and deploy references. That is a reliability risk and a judging credibility risk even when the code itself works.

### Required outcome

- Pick one canonical Python version and make local/deploy guidance match it
- Pick one canonical model target and make docs/config match it
- Make the deploy reference consistent enough that a release can be built and deployed without guesswork
- Keep the existing Phala + Docker architecture intact

### Validation target

Validate only the narrow deploy/config path: config consistency, parseability, and any directly affected build/deploy commands.
