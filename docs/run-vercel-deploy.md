# Vercel Deploy Attempt

## What Changed

- Added a root launcher at [`index.html`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/index.html) so the repo has a judge-facing entrypoint at `/`.
- Added a root Vercel config at [`vercel.json`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/vercel.json) to proxy `/api/*` to the live Phala backend.
- Added a root build script in [`package.json`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/package.json) so Vercel has a concrete static output directory.
- Updated the root build so `/` serves the real app HTML directly from `frontend/index.html` instead of a redirect shell.

## Validation Performed

- `command -v vercel` returned no CLI in PATH, so I used the skill fallback script.
- `python3 -m json.tool vercel.json`
- `python3 -m json.tool package.json`
- `npm run build`
- `bash /Users/alirezaghasemi/.codex/skills/vercel-deploy/scripts/deploy.sh .`
- `bash /Users/alirezaghasemi/.codex/skills/vercel-deploy/scripts/deploy.sh <tmpdir>` against a one-file static control site
- `npx vercel deploy dist -y`

## Deploy Results

- Attempt 1 preview URL: `https://skill-deploy-flh8co1tmy-codex-agent-deploys.vercel.app`
- Attempt 1 claim URL: `https://vercel.com/claim-deployment?code=e233c8ce-6938-4500-9c2e-45759f647459`
- Attempt 2 preview URL: `https://skill-deploy-0iozzb0j6n-codex-agent-deploys.vercel.app`
- Attempt 2 claim URL: `https://vercel.com/claim-deployment?code=9915d8dd-17b6-43ad-a013-0860d16342cc`
- Attempt 3 preview URL: `https://skill-deploy-w6p01tbdz2-codex-agent-deploys.vercel.app`
- Attempt 3 claim URL: `https://vercel.com/claim-deployment?code=be5ede1a-534d-411b-bcec-7ea87ade5e44`
- Control preview URL: `https://skill-deploy-8zext8g75w-codex-agent-deploys.vercel.app`
- Control claim URL: `https://vercel.com/claim-deployment?code=820be3d3-4061-4623-b83a-442f7a1d1ddc`

## Remaining Blocker

- The Vercel deploy service still reported `Deployment ready (returned 404)!` on the preview root even after the repo had a valid root app at `/`.
- A one-file static control site reproduced the same `404` result through the same fallback path.
- The direct Vercel CLI path is reachable from this environment, but it stops at device login because there are no Vercel credentials configured.
- That makes the current blocker external to the app code: either the fallback deploy service path is the source of the `404`, or a real authenticated Vercel CLI deploy is required to complete this reliably.
- No Phala demo-path behavior was changed.

## Notes

- I kept the existing Phala-backed frontend and APIs intact.
- The live demo path remains on Phala Cloud + Ollama + Base Sepolia.
