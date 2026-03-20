# Deploy Plan

## Recommendation

The fastest credible deployment path is to keep the existing Phala Cloud + Docker Compose topology and do a straight image-roll deployment to the already-defined CVM. Do not introduce new infrastructure, new orchestration, or a different cloud target. The repo already has the pieces needed for a production-shaped demo:

- Docker image for the FastAPI app and Playwright Chromium runtime
- `docker-compose.yaml` with the Ollama sidecar and Dstack socket mount
- `phala.toml` pointing at that compose file
- documented Phala deploy command and live CVM URL in `README.md`

This is the right path because it preserves the current demo while keeping the deployment story aligned with the TEE claim.

## Fastest Credible Path

1. Build the image for `linux/amd64` only.
2. Push the image to the existing registry namespace used by the repo.
3. Update the `props-oracle` image tag in `docker-compose.yaml`.
4. Deploy the compose stack to the existing Phala CVM with `phala deploy`.
5. Validate the live root path, attestation endpoint, and verify flow.

## Required Commands

### 1) Authenticate and confirm the Phala target

```bash
phala login
phala deploy -c docker-compose.yaml 6faa38933e632ca8dd2795fa68ad043c0bb6ad82
```

### 2) Build the runtime image

```bash
docker buildx build --platform linux/amd64 -t vetskiver/props-oracle:<tag> --push .
```

Use a short release tag that matches the session or deployment date.

### 3) Update the compose image tag

Update `docker-compose.yaml` so `props-oracle.image` points at the pushed tag.

### 4) Deploy to the existing CVM

```bash
phala deploy -c docker-compose.yaml 6faa38933e632ca8dd2795fa68ad043c0bb6ad82
```

### 5) Wait for the service to come back

```bash
curl https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/
```

## Validation Steps

Check these in order:

1. Root health/version response comes back from the public Phala URL.
2. `GET /api/attestation` returns a non-mocked attestation payload.
3. `POST /api/verify` returns a certificate JSON object for a known test license.
4. `GET /api/certificate/{id}` returns the stored certificate.
5. `GET /api/verify/{id}` verifies the signature and on-chain lookup path.
6. If the on-chain path is configured, the certificate response includes a Base Sepolia explorer link.

Recommended smoke test payload from the README:

```bash
curl -X POST https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network/api/verify \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": {"license_number": "209311", "profession": "Physician (060)"},
    "disclosed_fields": ["specialty", "years_active", "standing"]
  }'
```

## Blockers

These are the main things that can stop a deployment from being credible or operational:

- Wrong architecture: building a non-`amd64` image will not match the Phala TDX runtime.
- Missing or stale image tag: the compose file must reference the pushed image, not a local build assumption.
- Registry push failure: deployment depends on the image being publicly reachable by Phala.
- Ollama mismatch: the app expects the sidecar to be available and the model to be pullable at startup.
- TLS pin drift: the oracle hardcodes the NYSED fingerprint in source, so the live registry cert rotation requires a code change and redeploy.
- On-chain config missing: certificate storage is skipped if `CONTRACT_ADDRESS` or `PRIVATE_KEY` is absent.
- Local-dev flags leaking into production: `SKIP_TLS_VERIFY`, `SKIP_ENCRYPTION`, and `SKIP_OLLAMA_WAIT` must not be used inside a real enclave.

## Missing Config

The repo implies the following config must exist somewhere outside source control for the deployment to be complete:

- Docker Hub credentials or equivalent registry access for `vetskiver/props-oracle:<tag>`
- Phala CLI login/API access
- A working `PRIVATE_KEY` for the on-chain registry path if on-chain writes are meant to be live
- `CONTRACT_ADDRESS` for the deployed Base Sepolia registry
- A known-good `OLLAMA_MODEL` that matches the pinned model digest story
- If custom deployment origins are needed, `CORS_ORIGINS`

The following are intentionally not runtime secrets and should live in code or compose defaults:

- `NYSED_TLS_FINGERPRINT` is hardcoded in `app/oracle.py`
- default chain metadata lives in `app/onchain.py`
- default app port is `8080`

## Production-Real vs Local-Dev Only

### Production-real

- Phala Cloud deploy target
- Docker Compose topology
- `amd64` container build
- TDX enclave-backed runtime behavior
- TLS fingerprint pinning for the oracle
- Ollama sidecar as the model runtime
- Certificate persistence on the mounted volume
- Optional Base Sepolia on-chain storage

### Local-dev only

- `SKIP_TLS_VERIFY=true`
- `SKIP_ENCRYPTION=true`
- `SKIP_OLLAMA_WAIT=true`
- `SKIP_MODEL_PIN=true`
- Running the oracle directly with `python app/oracle.py`
- Running the app locally with a mock or relaxed attestation path

## Practical Notes

- The repo already documents the live CVM ID and URL, so the deployment path is an update, not a fresh environment bootstrap.
- `phala.toml` simply points at `docker-compose.yaml`, so the compose file is the deployment source of truth.
- The current `docker-compose.yaml` already wires the Ollama sidecar, Dstack socket, and certificate volume, so the deployment work is mostly image/tag hygiene and secret/config hygiene.
- If a deployment starts failing, inspect Phala serial logs first, then confirm the image tag, then confirm the model/secret env vars.

## Short Verdict

This project is deployable today without architectural changes. The credible path is already present; the main risk is operational drift between the compose file, the image tag, and the TEE-specific runtime assumptions.
