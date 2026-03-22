# Attestia Pitch Deck

Use this file as a direct prompt/input for Claude to build a polished Canva deck.

Goal:
- Create a concise, high-conviction hackathon / accelerator pitch deck
- Emphasize technical trust, live status, and research-to-product credibility
- Keep the deck visually clean, modern, and serious
- Avoid generic startup cliches or crowded slides

Design direction:
- Dark, premium, technical aesthetic
- Clean typography, high contrast, restrained accent color
- Minimal text per slide
- Visual hierarchy should be obvious instantly
- Prioritize clarity over decoration
- This should feel like a frontier infrastructure product, not a classroom presentation

Brand:
- Product name: Attestia
- Tagline: Verified anonymous expertise
- Protocol lineage: Powered by Props

Core facts to preserve:
- Live deployment runs on Phala Cloud
- Enclave type is Intel TDX
- On-chain verification is on Base Sepolia
- Contract address: 0x07a7c1efc53923b202191a888fad41e54cae7ca6
- Default live model: llama3.2:1b
- Attestia is the product; Props is the research / protocol lineage

Deck length:
- 7 slides total

---

## Slide 1 - Title

Title:
Attestia

Subtitle:
Verified anonymous expertise

Supporting line:
Portable proof for anonymous experts, backed by Intel TDX and on-chain verification

Footer:
Powered by Props

Intent:
- Immediate brand clarity
- Serious, technical, modern first impression

Visual suggestion:
- One dominant title
- Sparse layout
- Dark background with subtle depth or gradient

---

## Slide 2 - Problem

Title:
Anonymous expertise is hard to trust

Body:
- Anonymous speech is often ignored because readers cannot tell whether the speaker is real
- In high-stakes settings, revealing identity can be dangerous or impossible
- Today the choice is usually blind trust or total skepticism

Closing line:
The internet lacks a credible middle ground between anonymity and verifiability

Use cases:
- doctors
- lawyers
- journalists
- whistleblowers
- expert commentators

Intent:
- Frame the pain sharply and credibly
- Make the problem feel urgent and real

---

## Slide 3 - Solution

Title:
Attestia makes expertise portable without exposing identity

Body:
- Verify credentials against real authoritative registries
- Process the proof inside a Phala Cloud Intel TDX enclave
- Strip identity fields before issuance
- Issue a signed certificate that anyone can verify publicly
- Store proof on Base Sepolia for durable verification

Closing line:
Readers and platforms get proof of expertise without learning who the source is

Intent:
- Show the product as the missing middle ground
- Keep it product-shaped, not just protocol-shaped

---

## Slide 4 - How It Works

Title:
Five-layer trust pipeline

Body:
- L1 Oracle: fetch credential data from authoritative sources like NYSED and data.ny.gov
- L2 TEE + Attestation: run sensitive computation inside Intel TDX on Phala and bind output to enclave proof
- L3 Pinned Model: extract credential facts with a live model and include the model digest in the certificate
- L4 Redaction: release only user-consented fields and always strip identity fields
- L5 Adversarial Defense: forged, fake, and tampered paths fail architecturally

Closing line:
Trust comes from authenticated source data, enclave execution, signed output, and optional on-chain permanence

Intent:
- Show real technical depth
- Make the research lineage legible to judges in one slide

Visual suggestion:
- Clean 5-step horizontal or vertical flow
- Each layer should have one short phrase, not a paragraph

---

## Slide 5 - What Is Live Right Now

Title:
This is a live system, not a mocked demo

Body:
- Live deployment on Phala Cloud
- Hardware-backed trust result: trust_level = hardware
- Real Intel TDX quote embedded in issued certificates
- On-chain storage live on Base Sepolia
- Public verifier page live
- Model digest present in issued certificates
- Adversarial defense screen demonstrates rejected forged paths

Supporting proof:
- Contract: 0x07a7c1efc53923b202191a888fad41e54cae7ca6
- Model: llama3.2:1b

Intent:
- Remove any doubt that this is only a concept
- Make the implementation depth feel concrete

---

## Slide 6 - Why This Team / Why Now

Title:
Research-to-product is the point

Body:
- Attestia started from the Props paper and was translated into a working product architecture
- We built the oracle, extraction, redaction, attestation, and on-chain layers as one coherent trust chain
- We hardened the live path with readiness checks, clearer UX, deploy alignment, and repeated live validation
- This is not just a frontend demo; it is a live trust system with public verification

Closing line:
We are strongest at turning deep technical infrastructure into something usable and credible

Intent:
- Position the team as serious builders
- Reinforce that the project already crossed from research concept into live product

---

## Slide 7 - Vision / Why Accelerator

Title:
Why Attestia belongs in the accelerator

Body:
- The core technology is already live and defensible
- The next step is turning verified anonymous expertise into real trust infrastructure for platforms and institutions
- The accelerator is the right environment to sharpen product strategy, adoption path, and technical roadmap

Closing line:
Attestia can become the protocol-backed credibility layer for anonymous expert speech online

Final footer:
Live demo: https://6faa38933e632ca8dd2795fa68ad043c0bb6ad82-8080.dstack-pha-prod5.phala.network

Intent:
- End on ambition, not just implementation
- Make the project feel like an investable / acceleratable direction

---

## Build Notes For Claude / Canva

Please build this as:
- 7 slides
- dark, premium, technical design
- minimal copy per slide
- strong typography and spacing
- no generic SaaS illustrations
- no card-heavy dashboard look
- no playful startup visuals
- no excessive gradients or clutter

Priority order:
1. Clear story
2. Strong visual hierarchy
3. Technical credibility
4. Product seriousness

If a slide feels crowded:
- reduce text
- preserve the headline
- preserve the final closing line
- simplify body bullets rather than shrinking font too much
