# Frontend Task Completion

Implemented the top frontend task from `docs/execution-board.md`.

## Files changed

- `frontend/index.html`

## What changed

- Screen 1 now reads the backend readiness contract from `GET /api/info`, not just backend reachability.
- Submit stays blocked when the backend reports `verify_enabled=false`.
- The readiness panel now explains backend-reported `status`, `blocking_issues`, and `warnings`.
- The existing live flow and local-dev plaintext fallback remain intact.
- Added a small defensive guard in `submitVerify()` so a manual trigger still respects backend readiness.

## Validation performed

- Confirmed the new frontend logic is present in `frontend/index.html`:
  - `getBackendReadinessSummary()`
  - `verify_enabled`
  - `blocking_issues`
  - `formatBackendReadinessDetail()`
  - `Verification unavailable`
- Started the local app with the worktree Python 3.11 environment and validated the real website behavior in a browser:
  - usable local instance on `http://127.0.0.1:8080` with `verify_enabled=true`
  - blocked local instance on `http://127.0.0.1:8081` with `verify_enabled=false` caused by `ORACLE_TARGET=bad_target`
- Queried both local `/api/info` endpoints and confirmed the backend readiness contract differed as expected.
- Used Playwright CLI against the actual Screen 1 UI and confirmed:
  - on `http://127.0.0.1:8081/#verify`, the page showed `Backend is not ready to verify` and the submit button was disabled as `Verification unavailable`
  - on `http://127.0.0.1:8080/#verify`, the page showed `Ready to verify` and the submit button was enabled as `Generate anonymous certificate →`
- Queried the live deployed API at `/api/info` and confirmed it currently does **not** expose the new readiness contract yet, which validates the need for the frontend compatibility fallback path.

## Remaining blocker

- No blocking issue remains for the narrow Screen 1 validation path.
- The only minor runtime issue observed during browser validation was a `404` for `favicon.ico`, which did not affect the readiness or submit flow.
