# JamTalk Sprint 1 Execution Checklist

_Target: establish chat-first UX + testnet-ready architecture lane_

## Sprint Goal
Deliver a usable chat-first frontend slice and lock the technical path to a working Polkadot/JAM testnet MVP.

## Proposed Sprint Length
- 2 weeks

## Workstreams

## A) Frontend / Product UX (Highest impact)
1. **Conversation Shell v1**
   - Build conversation list panel + active thread panel.
   - Mobile: single-pane flow with drill-in thread.
   - DoD: navigation between threads works on desktop/mobile.

2. **Timeline UI v1**
   - Bubble cards (self/other), grouped timestamps, sender context.
   - Delivery/read chips in each message row.
   - DoD: timeline renders with visual hierarchy and status cues.

3. **Composer v1**
   - Sticky composer with keyboard-safe behavior on mobile.
   - Clear send/disabled/pending states.
   - DoD: no overlap/glitch with virtual keyboard.

4. **Onboarding UX v1**
   - Guided wallet connect + challenge verify with progress states.
   - Remove friction from raw JSON paths for normal users.
   - DoD: first-time user can complete connect/verify/send in <= 3 minutes.

5. **Debug Mode Toggle**
   - Keep advanced JT controls behind collapsible “Developer mode”.
   - DoD: default UX no longer overwhelming.

---

## B) Backend / API
1. **Frontend-support DTO cleanup**
   - Ensure stable response fields needed by chat UI.
   - DoD: UI consumes responses without ad-hoc parsing hacks.

2. **Status + health contract stabilization**
   - Guarantee predictable health/status payloads.
   - DoD: monitoring widgets can rely on fixed schema.

3. **Error consistency pass**
   - Harmonize API errors for auth/conversation/message flow.
   - DoD: UI can show user-friendly errors with deterministic mapping.

---

## C) Protocol / Runtime
1. **Runtime boundary ADR**
   - Finalize what is onchain-critical vs API-mediated.
   - DoD: ADR merged and referenced in roadmap.

2. **Host adapter implementation plan**
   - Break down host.rs/runtime.rs integration tasks.
   - DoD: implementation tickets created with acceptance criteria.

3. **Invariant extension pack**
   - Add test vectors for sequence/replay and blob mismatch.
   - DoD: tests included in CI matrix.

---

## D) Onchain Integration (Polkadot/JAM)
1. **Testnet target confirmation**
   - Lock exact network and deployment assumptions.
   - DoD: documented in `docs/` with prerequisites.

2. **Deploy pipeline scaffold**
   - Add CI job skeleton for testnet deploy dry-run.
   - DoD: pipeline executes smoke checks and publishes artifacts.

3. **Launch runbook draft**
   - Preflight -> Deploy -> Init -> Smoke -> Rollback.
   - DoD: runbook executable by non-author team member.

---

## E) DevOps / SRE
1. **Release channels and env strategy**
   - Define `dev/staging/testnet` secrets and promotion flow.
   - DoD: documented environment matrix.

2. **Observability starter pack**
   - Basic dashboards + alert rules for API health and runtime errors.
   - DoD: alerts fire in test simulation.

3. **Backup/restore verification for JamTalk artifacts**
   - Ensure project-specific restore path is documented.
   - DoD: restore drill completed once.

---

## F) Security / QA
1. **Threat model v1**
   - Message spoofing, replay, membership abuse, session misuse.
   - DoD: mitigations mapped to code owners.

2. **Adversarial test checklist**
   - Abuse scenarios for auth/session/message endpoints.
   - DoD: checklist executed in CI/manual pass.

3. **UI security checklist**
   - CSP, no secret leakage, safe error output, secure defaults.
   - DoD: checklist passed before Sprint 1 close.

---

## Ticket Template (use for each item)
- Title
- Milestone (M2/M3 etc.)
- Owner
- Priority (P0/P1/P2)
- Dependencies
- Acceptance Criteria
- Test Plan
- Risk notes

---

## Sprint 1 Definition of Done (Program-level)
- Chat-first frontend slice is demonstrably usable.
- Architecture path to testnet is concretely locked (ADR + tickets + pipeline scaffold).
- CI remains green.
- No new critical security findings introduced.
