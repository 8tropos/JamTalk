# JamTalk GitHub Milestones & Issue Map

## Labels
- `milestone:m1-alpha`
- `milestone:m2-closed-beta`
- `milestone:m3-public-beta`
- `area:frontend`
- `area:backend`
- `area:wallet`
- `area:pop`
- `area:security`
- `area:devops`
- `priority:p0`
- `priority:p1`
- `priority:p2`

## Milestone M1 — Internal Alpha (P0)
Target: browser-first, mobile-friendly end-to-end chat for internal testers.

### Suggested issues
1. **API bootstrap (health/status + versioning) [DONE-initial]**
2. **Wallet challenge auth API + session token**
3. **Register device API endpoint**
4. **Verify personhood API endpoint**
5. **Create conversation + send + ack read API endpoints**
6. **Responsive web shell (mobile-first)**
7. **Wallet connect UI + signed challenge flow**
8. **PoP verification UI + state feedback**
9. **Chat thread UI (send + read cursor updates)**
10. **E2E smoke test in CI (headless)**

## Milestone M2 — Closed Beta (P1)
Target: 20-100 users, stable mobile browser UX.

### Suggested issues
1. Delivery/read status model (sent/delivered/read)
2. Retry/idempotency for client submits
3. Abuse/rate limit dashboard + ops controls
4. Security hardening (CSP, headers, CORS)
5. Staging/prod split + secrets management
6. Wallet reconnect/session refresh UX

## Milestone M3 — Public Beta (P1/P2)
Target: open beta with monitoring and support loop.

### Suggested issues
1. Landing page + onboarding funnel
2. Privacy policy + terms + PoP disclosures
3. Analytics funnel + retention dashboards
4. Horizontal scaling + queue for verifier path
5. Incident runbooks + on-call docs
