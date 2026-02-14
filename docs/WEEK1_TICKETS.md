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

### JT-010 (P0) — Dev signature helper flow in browser shell
- Add dev endpoints for signing challenge/pop/conversation/send/read payloads
- Add UI buttons to auto-generate signatures and bootstrap device registration for local dev
- Status: ✅ implemented

### JT-011 (P0) — One-click end-to-end demo bootstrap
- Add single API action to bootstrap 2 dev identities, conversation, blob, first message, and read-ack
- Add UI button to trigger one-click bootstrap and auto-fill key fields
- Status: ✅ implemented

### JT-012 (P0) — Conversation/message query + UI state rendering
- Add `GET /v1/conversations` and `GET /v1/messages?conv_id=...`
- Add UI controls to fetch and render these lists
- Status: ✅ implemented

### JT-013 (P0) — UI auto-refresh with mobile-safe throttling
- Add periodic polling for status/conversations/messages
- Add start/stop controls and configurable interval
- Pause refresh when tab hidden and auto-resume when visible
- Status: ✅ implemented

### JT-014 (P0) — Blob registration from browser text
- Add blob register endpoint for text payload to chunk/root pipeline
- Add dev sign helper for blob signatures
- Add UI section to register blob and auto-fill send fields
- Status: ✅ implemented

### JT-015 (P0) — In-browser chat timeline renderer
- Add message timeline cards (seq/sender/flags/len)
- Integrate with list/refresh flows
- Add optional auto-scroll
- Status: ✅ implemented

### JT-016 (P0) — Compose UX polish + quick send flow
- Add preset text helper for blob compose
- Add success/error toasts
- Disable action buttons while pending
- Add one-tap send+refresh pipeline
- Status: ✅ implemented

### JT-017 (P0) — Injected EVM wallet adapter auth bridge
- Add browser wallet connect for injected EVM providers
- Add challenge sign via `personal_sign` and server-side EVM verification endpoint
- Status: ✅ implemented

## Notes
- Browser-first + mobile-friendly remains default product direction.
- Current phase remains **MVP / Phase 2.4+** with strong PoP backend foundations.
