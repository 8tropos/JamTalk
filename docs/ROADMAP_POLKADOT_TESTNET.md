# JamTalk Development Roadmap (Team-Scale) + Polkadot Testnet Launch Path

_Last updated: 2026-03-01_

## 1) Product Vision

JamTalk is an **unchained messaging alternative**: wallet-native identity, verifiable message flow, and configurable trust/abuse controls, with UX quality close to mainstream chat apps.

### North-star outcomes
- Private-by-default messaging UX that feels consumer-grade.
- Deterministic onchain integrity for critical state transitions.
- Low-friction onboarding from web2 mental model to web3 trust model.
- Deployable and observable stack for iterative shipping on testnet.

---

## 2) Team Structure (Recommended)

1. **Protocol/Core Runtime**
   - State model, refine/accumulate, deterministic invariants.
2. **Onchain Integration (Polkadot/JAM)**
   - Host bindings, deployment pipelines, chain interfaces.
3. **Backend/API**
   - Axum APIs, auth/session, operational endpoints, observability.
4. **Frontend/Product UX**
   - App shell, chat experience, onboarding, responsive design.
5. **Security/Cryptography**
   - Signature validation, E2EE envelope, key lifecycle, abuse controls.
6. **DevOps/SRE**
   - CI/CD, release engineering, telemetry, incident response.
7. **QA/Adversarial Testing**
   - Property tests, fuzzing, abuse simulation, load testing.
8. **Product/Compliance**
   - Rollout scope, policy docs, legal/privacy, user comms.

---

## 3) Delivery Phases

## Phase 0 — Foundations (Week 1–2)
- Lock architecture and data contracts (conv/member/message/blobs).
- Stabilize build/test matrix and contribution standards.
- Define release branches and deployment environments.

**Exit criteria**
- Green CI on every PR.
- Deterministic state transition invariants documented.
- Team owns a clear architecture decision record (ADR set).

## Phase 1 — MVP Core Runtime (Week 2–4)
- Complete signature validation path (remove placeholders).
- Harden nonce replay protection and sequence monotonicity.
- Finalize blob commitment and retrieval proof behavior.

**Exit criteria**
- `cargo test` + property tests green.
- Replay/ordering invariants proven under concurrent scenarios.
- Error taxonomy stable and mapped to API responses.

## Phase 2 — Frontend Productization (Week 3–6)
- Evolve current shell into a real chat product surface.
- Implement UX system and interaction model (mobile-first).

### Immediate frontend track (next sprints)
- Introduce chat-centric layout with:
  - left conversation list / right active thread (desktop)
  - single-pane conversational flow (mobile)
- Message timeline redesign:
  - bubble styles (self/other), delivery/read state chips, timestamp grouping
  - composer bar with sticky behavior and attachment affordances
- Session/onboarding UX:
  - guided wallet connect, challenge verify, status feedback
- Reduce operator/dev friction:
  - contextual forms, collapsible advanced panels, fewer raw JSON footguns

**Exit criteria**
- End-to-end demo flow usable by non-developer observers.
- Lighthouse/accessibility baseline acceptable.
- Design tokens + component consistency established.

## Phase 3 — Polkadot Testnet Integration (Week 5–8)
- Implement chain adapter and host function bindings.
- Deploy minimal onchain component(s) on target testnet.
- Wire API runtime to onchain state transitions where required.

**Exit criteria**
- Testnet deployment reproducible from CI pipeline.
- Message and conversation lifecycle demonstrable with onchain proofs.
- Rollback and migration strategy documented.

## Phase 4 — Security + Abuse Hardening (Week 7–10)
- Bond/fee anti-spam strategy validated.
- Sender allowlist / policy controls.
- Key management lifecycle and compromise handling.

**Exit criteria**
- Abuse scenarios tested and measurable mitigation in place.
- Security review checklist passed.
- Incident response runbook dry-run completed.

## Phase 5 — Beta Readiness (Week 9–12)
- Observability, analytics funnel, error budgets.
- Beta launch checklist and staged rollout.

**Exit criteria**
- Reliability SLO agreed and tracked.
- Post-launch support process active.
- Public beta go/no-go approved.

---

## 4) Polkadot Testnet MVP Starting Point (Practical)

This is the recommended **starting point now** for getting a working MVP on testnet.

## Step A — Freeze MVP scope
Ship only:
1. Wallet auth (challenge/verify)
2. Conversation create/list + membership changes
3. Message send/list/read with deterministic sequence
4. Blob registration path required by messaging flow

## Step B — Define chain target + contract/runtime boundary
- Pick the exact Polkadot/JAM-compatible testnet target and confirm execution model.
- Decide what is strictly onchain vs API-mediated but verifiable.

## Step C — Implement host bindings first
- Prioritize `host.rs` + `runtime.rs` integration to real host APIs.
- Keep fallback/mocked adapter for local dev tests.

## Step D — Build deployment lane in CI
- One-command testnet deploy from clean CI runner.
- Artifact versioning, migration hooks, and post-deploy health check.

## Step E — Onchain launch rehearsal
- Dry-run full flow:
  1) deploy,
  2) create conversation,
  3) send messages,
  4) read receipt,
  5) verify state/proofs,
  6) rollback test.

## Step F — Public testnet pilot
- Small internal user cohort first.
- Capture latency, failure types, and abuse metrics.
- Iterate before external beta.

---

## 5) Onchain Launch Guidance (Testnet)

Use this as launch sequence:
1. **Preflight**: chain health, funded deploy wallet, version pinning.
2. **Deploy**: publish runtime/contract artifact with immutable tag.
3. **Initialize**: set config (fees/bonds/limits), register admin keys.
4. **Smoke Test**:
   - health endpoints
   - auth flow
   - conv + send + read happy path
5. **Invariant Check**:
   - replay rejected
   - sequence monotonic
   - blob mismatch rejected
6. **Observability Check**:
   - dashboards + alerts online
7. **Pilot Enablement**:
   - limited access group
   - support channel + incident process

---

## 6) Engineering Standards

- Mandatory tests for every state transition touch.
- Property tests on sequencing/nonces.
- Security review required for crypto/auth code changes.
- No schema-breaking API change without migration note.
- Keep docs and runbooks updated in same PR when behavior changes.

---

## 7) Risks + Mitigations

1. **Chain integration complexity**
   - Mitigate via adapter isolation + CI testnet deploy rehearsal.
2. **UX too technical for users**
   - Mitigate with progressive disclosure and “simple mode”.
3. **Spam/abuse economics not tuned**
   - Mitigate via staged rollout and telemetry-driven parameter tuning.
4. **Security regressions under speed**
   - Mitigate with required security gates and adversarial test budget.

---

## 8) Immediate Next Actions (from today)

1. Build **chat-first frontend milestone** (next):
   - conversation list, thread bubbles, delivery/read chips, improved composer UX.
2. Lock **MVP testnet boundary** and publish ADR.
3. Implement host bindings for core message lifecycle path.
4. Add CI deploy job for testnet dry-run.
5. Run first end-to-end testnet rehearsal and capture gaps.

---

## 9) Definition of MVP Done (Testnet)

- User can authenticate with wallet and maintain session.
- User can create/join conversation and exchange messages.
- Message ordering and replay protections hold.
- System runs on testnet with reproducible deployment.
- Frontend is usable on mobile/desktop without dev-only friction.
- Observability + rollback plan exists and is tested.
