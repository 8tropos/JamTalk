# JamTalk Week 6 Ticket Breakdown (Execution Plan)

## Sprint Goal
Public-beta readiness: onboarding/disclosures and lightweight product analytics.

## Tickets

### JT-039 (P1) — Landing page + onboarding routes
- Add simple landing route with product overview + quickstart links
- Keep app shell available at `/app`
- Status: ✅ implemented

### JT-040 (P1) — Privacy/terms disclosure pages
- Add `/privacy` and `/terms` static disclosure routes
- Link from landing + app shell
- Status: ✅ implemented

### JT-041 (P1) — Funnel analytics counters endpoint
- Add in-memory counters for auth/session, conversation, and messaging funnel events
- Expose `GET /v1/analytics/funnel`
- Status: ⏳ planned
