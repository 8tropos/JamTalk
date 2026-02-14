# JamTalk Week 1 Ticket Breakdown (Execution Plan)

## Sprint Goal
Deliver a browser-first MVP skeleton with API + project planning foundations.

## Tickets

### JT-001 (P0) — API runtime bootstrap
- Add HTTP server binary (`jamtalk-api`)
- Add `/health` and `/v1/status`
- Acceptance: local server starts and both endpoints return 200 JSON
- Status: ✅ implemented

### JT-002 (P0) — Milestone + issue architecture docs
- Write milestone breakdown and label strategy
- Acceptance: `docs/GITHUB_MILESTONES.md` committed
- Status: ✅ implemented

### JT-003 (P0) — Week-1 executable ticket map
- Create implementable ticket list with priorities
- Acceptance: `docs/WEEK1_TICKETS.md` committed
- Status: ✅ implemented

### JT-004 (P0) — Wallet challenge auth endpoint
- Add `/v1/auth/challenge` and `/v1/auth/verify`
- Start with deterministic challenge store in memory
- Acceptance: tests for challenge issue/verify lifecycle
- Status: ✅ implemented

### JT-005 (P0) — PoP verify API wrapper endpoint
- Add `/v1/pop/verify`
- Bridge to existing PoP verification pipeline
- Acceptance: endpoint returns verified/denied with deterministic error mapping
- Status: ✅ implemented

### JT-006 (P0) — Conversation and messaging API skeleton
- Add `/v1/conversations`, `/v1/messages/send`, `/v1/messages/read`
- Acceptance: happy-path state transitions with integration tests
- Status: ✅ implemented

## Notes
- Browser-first + mobile-friendly remains default product direction.
- Current phase remains **MVP / Phase 2.4+** with strong PoP backend foundations.
