# Current Judging Status

This is the current read on the repo and live deployment as of the latest verified `s31` rollout on Phala Cloud. It reflects the live state we confirmed in this thread: `ready_for_verify`, on-chain storage working, `trust_level=hardware`, and a real `model_digest` present in issued certificates.

## 1. Technical Depth

**Standing: 8.8/10**

**Strongest evidence**
- The stack is not a toy wrapper. It has a real oracle -> extraction -> redaction -> attestation -> on-chain flow in [`app/main.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/main.py), [`app/oracle.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/oracle.py), [`app/extractor.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/redaction.py), and [`app/onchain.py`](/Users/alirezaghasemi/.codex/worktrees/6f84/shape-hack/app/onchain.py).
- Live certificates now contain the real model hash, not a placeholder. On `s31`, `GET /api/verify/{id}` returned `model_digest=baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878`.
- The attestation story is materially strong: real Phala TDX enclave, enclave-derived signing, TDX quote, and on-chain registry verification are all live.
- The runtime readiness contract is explicit and machine-readable, which raises the sophistication of the live system instead of just the docs.

**Biggest remaining weakness**
- The project is still slightly ahead of its own formal proof story. It demonstrates a very strong trust pipeline, but not a fully formal, externally verifiable proof of the paper’s strongest `Y = M(X)` framing.
- Intel Trust Authority verification still returns `401` without an API key, so the third-party appraisal path remains incomplete.
- The codebase is deep, but some of that depth is infrastructure-heavy and hard to verify quickly in a judge’s limited time.

## 2. Product Viability

**Standing: 7.4/10**

**Strongest evidence**
- The product has a clear customer-shaped narrative: anonymous expert credentials with verifiable trust, aimed at doctors, lawyers, journalists, and whistleblowers.
- The live site is polished enough to show a real flow, not just a terminal demo.
- On-chain permanence and hardware-backed trust make the product story more credible than a standard “AI verification” app.

**Biggest remaining weakness**
- It still reads more like a protocol showcase than a repeatable product people could adopt tomorrow.
- The workflow depends on multiple live systems at once: Phala, Ollama, government registry access, and Base Sepolia.
- The product thesis is strong, but the onboarding, pricing, and buyer path are still mostly narrative rather than operationally proven.

## 3. Progress Made

**Standing: 9.2/10**

**Strongest evidence**
- The repo now has a live deployed path and the current `s31` deployment is confirmed healthy.
- We validated a full live verify run that produced a real certificate, wrote on-chain, and returned `trust_level=hardware`.
- The frontend, backend readiness contract, Docker, and compose configuration have all been tightened enough that the demo now behaves like a real product instead of a loose prototype.
- The recent fixes removed the most dangerous demo failure modes: readiness ambiguity, missing on-chain truth, and missing model digest metadata.

**Biggest remaining weakness**
- The repo still has some historical drift in docs and operational notes, so a judge or teammate can still be confused if they read the wrong file first.
- There is still no narrow end-to-end regression test that covers the exact live demo sequence from `/api/info` through `POST /api/verify` and verifier lookup.

## 4. Accelerator Fit

**Standing: 8.0/10**

**Strongest evidence**
- This is an excellent fit for a research-to-product accelerator focused on TEE, verification, and cryptographic infrastructure.
- The Props-paper framing is not cosmetic. The repo actually maps to L1-L5 style trust infrastructure, and the live deployment proves the concept works under real conditions.
- The project now has enough product shape to be pitchable, while still retaining real technical depth.

**Biggest remaining weakness**
- It is still strongest as a hackathon and research-to-product story, not yet as a clearly repeatable growth-stage product.
- The buyer/channel story is still thinner than the technical story.
- Accelerator judges who care about traction may still see “impressive infrastructure” before they see “clear business.”

## Overall Outlook

Right now this is a strong judging candidate, especially for a TEE or cryptography-heavy track. The biggest positive change is that the repo is no longer just conceptually impressive: the live `s31` deployment proves the trust chain end-to-end with on-chain storage, hardware trust, and a real model digest in the certificate.

My blunt read is:
- For a hackathon judge, this is now in the “serious contender” zone.
- For an accelerator, it is credible enough to take seriously, but still not fully polished as a business.
- The main remaining risk is not whether it works. It does.
- The remaining risk is whether the team can make the story feel operationally inevitable rather than just technically exceptional.

## Top 3 Things Most Likely To Improve Scores Further

1. Add one narrow end-to-end API smoke test for the judge path.
2. Resolve the Intel Trust Authority `401` with a real API key so the third-party appraisal path is also live.
3. Clean up the remaining doc/runtime drift so the repo reads as one coherent deployment story.

## Current Summary

The repo is now past the “impressive demo, shaky live path” phase. With `s31`, it has real hardware-backed trust, real on-chain persistence, and a real model digest in the certificate. That is enough to score well on technical depth and progress, and it materially improves product credibility. The remaining gap is polish, repeatability, and a cleaner buyer story rather than core capability.
