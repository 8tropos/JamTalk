# JamTalk Milestone Board (M0–M5)

_Last updated: 2026-03-01_

## M0 — Foundations & Operating Baseline
**Goal:** stable engineering base for fast iteration.

### Deliverables
- Architecture decision records (ADR) for runtime boundary, onchain scope, and API surface.
- CI baseline (lint/test/build) with branch protections.
- Environments defined: local, staging/testnet, pilot.
- Security baseline checklist and ownership map.

### Owners
- Tech Lead, DevOps/SRE, Security, Protocol

### Exit Criteria
- CI always green on main.
- Reproducible local setup in README.
- ADR set approved.

---

## M1 — Core Runtime Correctness
**Goal:** deterministic protocol behavior under stress.

### Deliverables
- Signature verification path finalized.
- Nonce replay and sequence monotonicity hardening.
- Blob commitment validation and error mapping hardened.
- Property tests expanded for ordering/replay edge cases.

### Owners
- Protocol/Core Runtime, Security, QA

### Exit Criteria
- Invariant tests + property tests pass.
- Error taxonomy stable and documented.

---

## M2 — Product-Grade Frontend (Chat-first)
**Goal:** transform shell into a usable chat product surface.

### Deliverables
- Conversation list + active thread layout (desktop split / mobile single-pane).
- Message bubble UI (self/other), delivery/read chips, grouped timestamps.
- Composer strip (sticky), keyboard-safe mobile behavior.
- Guided wallet/auth onboarding flow with clear state feedback.
- “Advanced” dev JSON controls collapsed behind debug toggles.

### Owners
- Frontend/Product UX, Backend/API

### Exit Criteria
- Non-dev user can complete first message flow.
- Responsive QA pass on mobile and desktop.

---

## M3 — Polkadot/JAM Testnet Integration
**Goal:** deploy and run the MVP path on testnet.

### Deliverables
- Host bindings integrated in runtime path.
- CI testnet deploy job with versioned artifacts.
- Minimal onchain launch runbook tested end-to-end.
- API + frontend wired to testnet-backed state flow.

### Owners
- Onchain Integration, DevOps, Protocol, Backend

### Exit Criteria
- One-command deployment to testnet from CI.
- Successful smoke flow: auth -> conversation -> send -> read.

---

## M4 — Security, Abuse Controls, Observability
**Goal:** safe, monitorable pilot posture.

### Deliverables
- Fee/bond anti-spam parameters tested and tuned.
- Abuse response controls (rate limits, moderation hooks, policy toggles).
- Dashboards + alerts for API/runtime/deploy health.
- Incident and rollback runbooks validated.

### Owners
- Security, SRE, Backend, Protocol

### Exit Criteria
- No critical unresolved findings.
- Alerting and rollback drills completed.

---

## M5 — Pilot & Beta Readiness
**Goal:** controlled user pilot and release confidence.

### Deliverables
- Pilot cohort onboarding + support playbook.
- UX polish pass from pilot feedback.
- Release readiness checklist and go/no-go review.
- Public beta gating criteria published.

### Owners
- Product, Frontend, Backend, SRE, Security

### Exit Criteria
- Pilot KPIs hit (stability + usability thresholds).
- Team signs off go/no-go.

---

## Cross-Milestone Tracking Fields (for tickets)
- `owner`
- `milestone`
- `priority` (P0/P1/P2)
- `risk` (low/med/high)
- `status` (todo/in-progress/blocked/done)
- `depends_on`
- `definition_of_done`
