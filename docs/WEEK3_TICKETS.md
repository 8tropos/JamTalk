# JamTalk Week 3 Ticket Breakdown (Execution Plan)

## Sprint Goal
Move from MVP-hardening into beta-readiness: safer auth/session lifecycle, better conversation UX, and stronger operational guardrails.

## Tickets

### JT-025 (P0) — Auth logout/session invalidation endpoint + UI
- Add `POST /v1/auth/logout` to invalidate wallet auth session challenge state
- Add browser UI action to logout and reset local auth markers
- Status: ✅ implemented

### JT-026 (P0) — Wallet network guardrails
- Detect/validate allowed EVM chain IDs in UI auth flow
- Reject unsupported chain before challenge verify
- Add configurable allowed chain list in browser shell
- Status: ✅ implemented

### JT-027 (P0) — Conversation participant listing endpoint
- Add `GET /v1/conversations/members?conv_id=...`
- Render member roster in browser UI
- Status: ✅ implemented

### JT-028 (P1) — Role management endpoint (promote/demote admin)
- Add admin role mutation endpoints with signature checks
- Add browser controls + dev sign helpers for promote/demote
- Status: ✅ implemented

### JT-029 (P1) — Message pagination cursor API
- Add paged message listing (`limit`, `before_seq`)
- Update timeline UI to page older messages
- Status: ⏳ planned

### JT-030 (P1) — Security headers / CSP baseline
- Add restrictive-but-working headers for web shell
- Status: ⏳ planned

### JT-031 (P1) — Rate limit scaffold for auth endpoints
- Add in-memory token-bucket style limiter for challenge/verify
- Status: ⏳ planned

### JT-032 (P1) — CI quality gate expansion
- Add clippy/fmt checks (when toolchain components available)
- Include API smoke route checks for main endpoints
- Status: ⏳ planned
