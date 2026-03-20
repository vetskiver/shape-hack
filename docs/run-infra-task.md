# Infra Task Completion

- Implemented: aligned the repo's deploy truth to one canonical runtime story without changing the Phala/Docker architecture.
- Files changed:
  - `README.md`
  - `docker-compose.yaml`
  - `app/extractor.py`
  - `docs/run-infra-task.md`
- What changed:
  - Updated local/dev guidance in `README.md` to use Python 3.11, which matches `Dockerfile`.
  - Updated model references in `README.md`, `docker-compose.yaml`, and `app/extractor.py` to reflect the current runtime default `llama3.2:1b`.
  - Updated the README deploy reference so the current compose target image is `vetskiver/props-oracle:s23`.
  - Kept the existing Phala + Docker Compose topology unchanged.
- Validation performed:
  - Ran `python3` with `yaml.safe_load(...)` against `docker-compose.yaml` and confirmed the compose target image is `vetskiver/props-oracle:s23` and the `OLLAMA_MODEL=${OLLAMA_MODEL:-llama3.2:1b}` env entry is present.
  - Ran `rg -n "Python 3.11|python3.11|llama3.2:1b|s23|3.12|s4.1|Llama 3.2 3B" README.md docker-compose.yaml app/extractor.py` to confirm the edited files now agree on the canonical Python version, model target, and image reference.
  - Reviewed the exact diff with `git diff -- README.md docker-compose.yaml app/extractor.py`.
  - Revalidated with `docker compose config` and confirmed Docker resolves:
    - `props-oracle.image: vetskiver/props-oracle:s23`
    - `props-oracle.platform: linux/amd64`
    - `props-oracle.environment.OLLAMA_MODEL: llama3.2:1b`
    - `ollama.platform: linux/amd64`
  - Revalidated the local build path with `docker buildx build --platform linux/amd64 -t props-oracle:infra-validate --load .`, which completed successfully.
  - Validated the live Phala deployment path directly:
    - `curl -i -sS https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/api/attestation`
      returned `status: real_tdx_quote` with a real quote and Phala TDX event log.
    - `curl -i -sS https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/api/public-key`
      returned the live RSA public key used for browser-side credential encryption.
    - Sent a real encrypted `POST /api/verify` request using the live public key from a Python 3.11 client.
      The streamed result returned:
      - `"on_chain": true`
      - `"assurance_results": {"real_tee": true, "model_pinned": true, "onchain_stored": true, ...}`
      - a certificate with `"in_real_enclave": true`
      - a Base Sepolia tx hash and Basescan URL
    - Fetched `GET /api/verify/{certificate_id}` for the issued live certificate and confirmed:
      - `"trust_level": "hardware"`
      - `"tdx_quote_present": true`
      - `"on_chain_verified": true`
      - `"on_chain_matches": true`
- Remaining blocker:
  - `docker compose config` warns that `PRIVATE_KEY` is unset in this worktree, so the rendered config still represents an on-chain-disabled local run unless secrets are supplied at deploy time.
  - `phala` CLI is not installed in this worktree, so I could not inspect or update the live CVM configuration directly from here.
  - This means the shortest real path for the current worktree is still operational rather than code-level: build and push the new image, then deploy it to the existing Phala CVM with `PRIVATE_KEY` present in Phala secrets/env so the write path stays on-chain-enabled.
  - The live deployment already proves that real on-chain writes plus `trust_level=hardware` are achievable with the current architecture; the unresolved step is promoting the latest worktree image/config onto that same secret-backed Phala path.
