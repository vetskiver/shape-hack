# Score Improvements Run

## Scope

Implemented, not mocked:

1. a narrow HTTP smoke test for the judge path
2. small Intel Trust Authority messaging/config coherence improvements already present in the repo
3. a minimal README drift cleanup so the repo matches the current live `s31` story

## Files Changed

- `/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/tests/test_judge_flow.py`
- `/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/README.md`

## What Changed

### 1. Judge-path smoke test

Added `tests/test_judge_flow.py`, a single FastAPI/TestClient smoke test that covers the exact judge-facing route sequence with mocked external dependencies:

- `GET /api/info`
- `GET /api/public-key`
- `POST /api/verify`
- `GET /api/certificate/{id}`
- `GET /api/verify/{id}`

The test intentionally mocks oracle, extraction, attestation, and on-chain writes so it validates the HTTP contract and NDJSON flow without depending on live Phala, Ollama, or Base Sepolia.

### 2. Intel Trust Authority path

No additional app-code change was necessary in this pass. The repo already has:

- `INTEL_TRUST_AUTHORITY_API_KEY` support in `app/attestation.py`
- `INTEL_TRUST_AUTHORITY_URL` support in `app/attestation.py`
- compose-level env plumbing in `docker-compose.yaml`
- README guidance explaining that hardware trust still works without Intel TA, but successful third-party appraisal requires a real API key

The remaining blocker is external: a real Intel Trust Authority API key is still required to remove the current `401`.

### 3. Doc/runtime drift cleanup

Updated `README.md` so the most judge-visible deployment story matches the current live state:

- S6 now correctly says `Base Sepolia`
- S8 now correctly says `medical_board + attorney`
- the live verify example now describes the actual NDJSON streaming contract
- the version check now matches the current `0.6.0` / `ready_for_verify` style output instead of the old `0.4.0` wording

## Validation Performed

Exact checks run:

- `python3 -m py_compile app/attestation.py app/extractor.py app/main.py tests/test_judge_flow.py`
- direct execution of the new smoke test via Python:
  - imported `tests/test_judge_flow.py`
  - executed `test_judge_flow_smoke(pytest.MonkeyPatch())`
  - observed `judge-flow-test-passed`
- inspected the updated `README.md` sections for the corrected live deploy/runtime wording

## Remaining Blocker

- Intel Trust Authority third-party appraisal still requires a real `INTEL_TRUST_AUTHORITY_API_KEY`.
- Without that external key, the verifier will continue to report the explicit unauthorized path even though the core judging-critical trust path remains live:
  - real TDX
  - `trust_level=hardware`
  - on-chain verification
  - real `model_digest`

## Demo-Path Risk

Avoided:

- no architecture change
- no live-path behavior change
- no new runtime dependency for the app itself

Introduced:

- none known in the demo path; the new test is isolated to the test suite
