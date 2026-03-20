# Fix Priorities

Top five highest-leverage fixes for demo reliability and hackathon judging outcomes, ranked by impact and effort.

## 1. Make startup and readiness explicit for the live pipeline

Impact: Very high
Effort: Medium

Why this matters:

- The current demo depends on several moving parts at boot: the enclave key path, Ollama availability, model pull, oracle reachability, and cert-store initialization.
- Right now the app can start in a partially healthy state and only fail when a judge clicks the main flow, which is the worst possible failure mode for a live demo.
- A clear readiness model would let the frontend and operators know when the system is actually ready to verify credentials, not just when the process is running.

What to fix:

- Add a true readiness signal that distinguishes `running`, `warming_up`, `degraded`, and `ready_for_verify`.
- Surface the model/oracle state in `/api/info` and/or a dedicated readiness endpoint.
- Make the frontend block the primary submit path until the backend reports readiness.

Dependencies / risks:

- Depends on the backend accurately detecting Ollama, the pinned model, and the enclave state.
- Risk: overblocking local dev if readiness is too strict. Keep a local-dev override, but make production strict.

## 2. Pin and align deployment/runtime config across README, compose, and image

Impact: Very high
Effort: Low to medium

Why this matters:

- The repo currently has visible drift: README says Python 3.12 while the Docker image uses 3.11, and the compose file defaults `OLLAMA_MODEL` to `llama3.2:1b` while the product narrative calls out a 3B model.
- Judges do not care which version is “technically fine”; they care whether the demo is consistent, repeatable, and believable.
- Deployment drift is one of the most common reasons a demo works on one machine and fails in front of the room.

What to fix:

- Make the deploy story self-consistent: Python version, model name, image tag, and current CVM/app IDs should all agree.
- Move any environment-sensitive deployment constants into one documented source of truth.
- Add a short “production vs local-dev” matrix so nobody confuses mocks, fallbacks, and live paths.

Dependencies / risks:

- Depends on the team deciding which model/version is the canonical demo target.
- Risk: changing the deploy story without verifying Phala compatibility could introduce new breakage, so keep the current path intact while aligning docs and config.

## 3. Add a narrow end-to-end smoke test for the actual API contract

Impact: High
Effort: Medium

Why this matters:

- Current tests are mostly module-level smoke tests; they do not prove that the HTTP surface, streaming verify flow, or certificate fetch/verify endpoints still work together.
- The judging demo is an integration story, so the highest-value test is the one that exercises the same route sequence a judge will use.
- Even a small API-level test catches regressions in request validation, streaming status events, certificate persistence, and verify-by-id behavior.

What to fix:

- Add one API smoke test that covers `/api/info`, `/api/public-key`, `/api/verify`, `/api/certificate/{id}`, and `/api/verify/{id}` with mocked external dependencies.
- Add a separate health/readiness check that the deployment can use before announcing the service live.
- Keep the test narrow and deterministic; do not try to fully reproduce Phala in CI.

Dependencies / risks:

- Depends on being able to stub the oracle and model layers cleanly.
- Risk: if the test is too broad or too flaky, it will stop being run. Keep it single-path and opinionated.

## 4. Harden the frontend against partial failure and long-running requests

Impact: High
Effort: Medium

Why this matters:

- The UI is the judge-facing surface, so even a recoverable backend issue can look like a failed product if the frontend does not explain what is happening.
- The verify flow is slow by design and currently depends on live network calls plus streaming progress; that is exactly where users perceive “broken” when the UX is not explicit.
- A polished frontend that survives slow starts, retries, and partial outages materially improves perceived reliability and demo confidence.

What to fix:

- Show explicit backend/model/oracle status before submission.
- Add a retry path for transient verify failures and a clear recovery button when the backend is warming up.
- Preserve the user’s input and selected disclosure fields across errors so the demo can be restarted quickly.

Dependencies / risks:

- Depends on a reliable readiness signal from the backend.
- Risk: too many UI states can make the flow feel busy; keep the interaction simple and focused on the one happy path.

## 5. Provide a judge-safe fallback artifact for the live narrative

Impact: Medium to high
Effort: Low to medium

Why this matters:

- The live pipeline is the best story, but it is also the most fragile part of the demo because it depends on external network and browser automation.
- For judging, the ideal setup is “live if possible, cached proof if needed.” That prevents a transient registry, model, or browser issue from collapsing the entire presentation.
- A fallback artifact lets the team still demonstrate the research value even if the full scrape cannot complete during the slot.

What to fix:

- Pre-generate a canonical demo certificate and verifier view that can be loaded instantly if the live scrape is slow or unavailable.
- Keep the fallback clearly labeled as cached/demo data, not live oracle output.
- Ensure the main flow still defaults to the live pipeline whenever it is healthy.

Dependencies / risks:

- Depends on keeping the fallback clearly separated from real production flow so it does not blur the trust story.
- Risk: if the fallback is too prominent, judges may think the product is mostly mocked. Label it explicitly and use it only as a backup.

## Recommended order

1. Readiness and startup gating.
2. Deployment/runtime config alignment.
3. API smoke test coverage.
4. Frontend failure handling.
5. Judge-safe fallback artifact.

## Notes

- The highest-value fixes are the ones that make the live demo predictable under pressure, not the ones that add the most features.
- Anything that reduces “it worked yesterday” risk should be prioritized over new product scope.
- Keep the live path intact and reversible; the goal is confidence, not architectural churn.
