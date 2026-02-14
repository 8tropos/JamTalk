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

### JT-007 (P0) — Responsive browser UI shell (mobile-first)
- Add static web shell served by API runtime (`/`, `/app.js`, `/styles.css`)
- Include developer forms for auth + PoP + status interactions
- Acceptance: UI routes served, smoke route tests present
- Status: ✅ implemented (initial shell)

### JT-008 (P0) — Wallet-connect style browser session flow
- Add local browser session persistence (`localStorage`) for wallet/auth state
- Add connect/save/clear session controls in UI
- Preserve challenge/signature/pubkey drafts across refresh
- Status: ✅ implemented

### JT-009 (P0) — Browser UI workflow for conversation/send/read
- Add concrete form flow in web shell for create conversation, send message, and read ack endpoints
- Acceptance: manual browser interaction can hit JT-006 APIs end-to-end
- Status: ✅ implemented

## Notes
- Browser-first + mobile-friendly remains default product direction.
- Current phase remains **MVP / Phase 2.4+** with strong PoP backend foundations.
