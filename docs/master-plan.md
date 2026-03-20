# Master Plan

This plan intentionally chooses the smallest set of changes most likely to improve demo reliability, technical depth credibility, product viability, and accelerator fit without breaking the current demo path.

## 1. Top 3 Judging Risks

### 1) Trust-story drift between pitch, code, and runtime

The repo tells a strong Props story, but judges will notice inconsistencies quickly:

- README says Python 3.12 while Docker uses Python 3.11
- README frames the model as Llama 3.2 3B while runtime defaults point to `llama3.2:1b`
- README and `docker-compose.yaml` disagree on the current image tag

This is the fastest way to lose credibility in a technically sophisticated demo.

### 2) The live path can fail only when a judge clicks the main flow

The current system can appear “up” while still not being truly ready to verify credentials. If Ollama, the pinned model, oracle path, or cert store are not ready, the failure happens at the worst possible moment: during the live demo.

### 3) The project is more convincing as research infrastructure than as a product

The technical depth is real, but the repo still reads more like a protocol demo than a reliable product. If the UI or runtime feels brittle, judges may conclude that the concept is impressive but not yet viable.

## 2. Top 3 Technical Risks

### 1) No narrow integration test for the real API contract

The repo has smoke tests, but not a targeted test covering the actual demo sequence:

- `GET /api/info`
- `POST /api/verify`
- `GET /api/certificate/{id}`
- `GET /api/verify/{id}`

That leaves the highest-value path vulnerable to silent regressions.

### 2) Deployment/runtime configuration drift

Model, Python version, and image-tag drift increase the chance of “works locally, breaks in deploy” failures. This is a technical risk, not just a documentation risk, because deployment correctness depends on these values being coherent.

### 3) Demo-critical dependencies can degrade silently

The app can still run while:

- on-chain writes are skipped
- external frontend assets fail
- startup dependencies are only partially healthy

That creates a system that looks live but is weaker than the claimed trust model.

## 3. Top 3 Demo Risks

### 1) Readiness is unclear to the presenter and the frontend

If the backend is warming up or degraded, the UI does not yet make that state explicit enough. That can turn a recoverable startup delay into a visible demo failure.

### 2) The verify flow depends on too many live moving parts at once

The demo path depends on Phala, Ollama, Playwright, the upstream registry, and optional on-chain storage. Without guardrails, one transient dependency issue can sink the full presentation.

### 3) There is no clearly separated fallback artifact for judging

The live path should remain primary, but the repo needs a clearly labeled backup path so a slow scrape or temporary startup problem does not erase the research story.

## 4. Single Highest-Leverage Fix in Frontend

Add explicit pre-submit readiness and degraded-state UX to the main verify flow.

Why this is the best frontend fix:

- It directly improves judge-facing reliability
- It makes the system feel product-shaped, not just technically clever
- It complements backend readiness work without requiring a redesign

Minimum useful change:

- show backend readiness before the submit action is enabled
- explain `warming_up`, `degraded`, and `ready`
- preserve user inputs across retryable failures

## 5. Single Highest-Leverage Fix in Backend

Implement a real readiness model for the verification pipeline.

Why this is the best backend fix:

- It prevents the worst failure mode: “server is up, verify still fails”
- It materially improves demo reliability and product viability
- It creates the foundation for frontend UX and deploy validation

Minimum useful change:

- detect readiness for Ollama, pinned model availability, oracle prerequisites, and certificate storage
- expose a machine-readable readiness state via `/api/info` or a dedicated endpoint
- distinguish `warming_up`, `degraded`, and `ready_for_verify`

## 6. Single Highest-Leverage Fix in Deploy/Infra

Align deployment truth into one canonical, verified configuration path.

Why this is the best deploy/infra fix:

- It is small and reversible
- It removes the most obvious credibility failures
- It improves both live operations and accelerator readiness

Minimum useful change:

- choose one canonical Python version
- choose one canonical model target
- choose one canonical current image tag / deploy reference
- make README, `docker-compose.yaml`, and runtime defaults agree

## 7. Recommended Execution Order for the Next 3 Implementation Tasks

### Task 1: Backend readiness and startup gating

Do this first because it gives the biggest immediate reliability gain and creates a clean contract for the frontend and deploy checks.

Target outcome:

- the app can declare whether it is actually ready to verify
- startup problems become visible before the demo click

### Task 2: Frontend readiness UX and retry-safe verify flow

Do this second because it turns backend readiness into a judge-visible product improvement with minimal scope.

Target outcome:

- submit is blocked until the system is ready
- degraded states are explained clearly
- retries do not force re-entry of the full form

### Task 3: Narrow API smoke test plus config alignment

Do this third as a reliability lock-in pass:

- add one integration-style API smoke test for the main flow
- align Python/model/image-tag truth across code and docs as part of the same stabilization sweep

This third task is intentionally a combined hardening pass, not a new feature wave.

## Bottom-Line Recommendation

If only three implementation tasks are completed next, they should be:

1. backend readiness and startup gating
2. frontend readiness UX and retry-safe submission
3. narrow API smoke coverage plus deployment/config alignment

That is the smallest sequence most likely to make the demo feel reliable, make the technical claims feel believable, and make the project look closer to an accelerator-ready product rather than just an impressive research prototype.
