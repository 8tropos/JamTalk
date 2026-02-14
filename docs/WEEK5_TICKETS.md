# JamTalk Week 5 Ticket Breakdown (Execution Plan)

## Sprint Goal
Operational hardening for multi-environment rollout and resilient wallet session lifecycle.

## Tickets

### JT-036 (P0) — Runtime environment profile + CORS allowlist
- Add env-profile config (`local`, `staging`, `production`) surfaced via API
- Apply strict `Access-Control-Allow-Origin` allowlist
- Status: ⏳ planned

### JT-037 (P0) — Wallet session refresh endpoint
- Add `POST /v1/auth/refresh` to rotate/extend active challenge lifecycle safely
- Preserve one-time challenge protections
- Status: ⏳ planned

### JT-038 (P1) — Ops runbook + deployment configuration docs
- Add environment/deployment and incident handling runbook in `docs/`
- Keep README aligned with new profile/CORS/auth refresh behavior
- Status: ⏳ planned
