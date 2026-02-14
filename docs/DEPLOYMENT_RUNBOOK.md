# JamTalk Deployment & Incident Runbook

## Runtime Profiles

Configured through environment variables:

- `JAMTALK_ENV_PROFILE` = `local` | `staging` | `production`
- `JAMTALK_ALLOWED_ORIGINS` = comma-separated origin allowlist
- Optional PoP runtime vars (existing):
  - `JAM_POP_HTTP_PROVIDER`
  - `JAM_POP_HTTP_ENDPOINT`

## Recommended Baselines

### local
- `JAMTALK_ENV_PROFILE=local`
- `JAMTALK_ALLOWED_ORIGINS=http://127.0.0.1:8080`

### staging
- `JAMTALK_ENV_PROFILE=staging`
- `JAMTALK_ALLOWED_ORIGINS=https://staging.jamtalk.example`

### production
- `JAMTALK_ENV_PROFILE=production`
- `JAMTALK_ALLOWED_ORIGINS=https://jamtalk.example`

## Start / Verify

```bash
cargo run --bin jamtalk-api
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/v1/status
curl -fsS http://127.0.0.1:8080/v1/config
```

## CI Expectations

Required jobs:
- `quality` (fmt + clippy)
- `test` (default + pop-http)
- `smoke-api` (health/status/index)

If CI fails on `quality`:
1. Run `cargo fmt`
2. Run `cargo clippy --all-targets --all-features -- -D warnings`
3. Re-run tests and push fix.

## Incident Handling

### 1) CI fails after push
- Check failing workflow and exact job (`quality`, `test`, or `smoke-api`).
- Reproduce locally with matching command.
- Apply minimal fix; verify full suite; push hotfix commit.

### 2) Auth failures spike
- Inspect:
  - `GET /v1/auth/metrics`
  - `GET /v1/ops/rate-limits`
- If abusive key identified, reset bucket:
  - `POST /v1/ops/rate-limits {"key":"<bucket-key>"}`

### 3) Browser CORS breakage
- Validate `JAMTALK_ALLOWED_ORIGINS` contains exact origin (scheme+host+port).
- Verify with browser request including `Origin` header and inspect `Access-Control-Allow-Origin`.

### 4) Wallet auth refresh complaints
- Confirm challenge lifecycle:
  - issue challenge (`/v1/auth/challenge`)
  - refresh (`/v1/auth/refresh`)
  - verify (`/v1/auth/verify-wallet`)
- Check for replay/expiry in structured error codes.

## Release Checklist

- [ ] CI green (all jobs)
- [ ] `README.md` endpoint list updated
- [ ] Week ticket docs status updated
- [ ] No pending local changes
- [ ] Latest commit pushed to `origin/main`
