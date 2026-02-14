# JamTalk Week 4 Ticket Breakdown (Execution Plan)

## Sprint Goal
Close key closed-beta backend gaps: delivery/read status visibility, safe client retries, and ops-facing abuse controls.

## Tickets

### JT-033 (P0) — Delivery/read status model endpoint
- Add `GET /v1/messages/status?conv_id=...&seq=...`
- Report per-member read state from read cursors and aggregate delivery/read counts
- Status: ✅ implemented

### JT-034 (P0) — Idempotent message send retry support
- Add optional `Idempotency-Key` handling on `POST /v1/messages/send`
- Return original send result for safe retries with same payload/key
- Reject key reuse with mismatched payload
- Status: ⏳ planned

### JT-035 (P1) — Auth abuse dashboard + ops controls
- Add `GET /v1/ops/rate-limits` for bucket visibility
- Add `POST /v1/ops/rate-limits/reset` for targeted key reset
- Status: ⏳ planned
