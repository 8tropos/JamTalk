# JamTalk Week 2 Ticket Breakdown (Execution Plan)

## Sprint Goal
Harden auth/session safety and move from dev-only UX toward production-safe browser flows.

## Tickets

### JT-017 (P0) — Injected EVM wallet adapter auth bridge
- Add browser wallet connect for injected EVM providers
- Add challenge sign via `personal_sign` and server-side EVM verification endpoint
- Status: ✅ implemented

### JT-018 (P0) — Auth challenge hardening (TTL + replay guard)
- Add challenge TTL expiry checks
- Enforce one-time challenge consumption
- Add explicit replay detection guard
- Status: ✅ implemented

### JT-019 (P0) — Wallet capability detection + UX fallback states
- Detect provider availability and surface clear fallback CTAs
- Disable EVM-specific actions when provider is absent
- React to wallet account/network changes in-session
- Status: ✅ implemented

### JT-020 (P0) — Structured API error objects for UI handling
- Replace plain text errors with machine-readable API error envelope
- Status: ⏳ planned

### JT-021 (P0) — Message detail endpoint + timeline enrichment
- Expose fuller message metadata for richer chat rendering
- Status: ⏳ planned

### JT-022 (P1) — Conversation participant management endpoint
- Add add/remove participant flow with auth checks
- Status: ⏳ planned

### JT-023 (P1) — Basic auth/session metrics endpoint
- Add counters for challenge issued/verified/expired/replayed
- Status: ⏳ planned

### JT-024 (P1) — Mobile interaction polish pass
- Touch target improvements + keyboard-safe spacing and sticky composer behavior
- Status: ⏳ planned
