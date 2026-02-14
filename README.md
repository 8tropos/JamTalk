# JamTalk (Spec v0.2 skeleton)

This repository is a rigorous, implementation-oriented scaffold for an **on-chain messenger on JAM**.

## What this is

- Deterministic service model for:
  - identity/key registration
  - conversation membership
  - message commit ordering
  - blob registration
  - anti-spam fee/bond controls
- Clean split between:
  - `refine.rs` (signature + bounds + blob commitment checks)
  - `accumulate.rs` (stateful checks + canonical state updates)

## What this is not (yet)

- Full JAM host function integration (adapter trait added, real host binding pending)
- Full PVM build/deploy scripts
- Production-grade crypto ratchet and privacy hardening

## Quick start

```bash
cargo test
cargo run --bin jamtalk-api
```

Then open:
- `http://127.0.0.1:8080/health`
- `http://127.0.0.1:8080/v1/status`

## Modules

- `types.rs` — protocol constants, WI/result/event structs
- `errors.rs` — deterministic error mapping
- `state.rs` — canonical state maps + verified chunk retrieval helpers
- `crypto.rs` — hash/merkle helpers, proof build/verify, msg id derivation
- `auth.rs` — domain-separated signing payloads + Ed25519 verification
- `client_crypto.rs` — E2E payload/envelope builder (X25519 + HKDF + XChaCha20Poly1305)
- `host.rs` — host adapter trait for JAM runtime integration
- `persistence.rs` — state load/save to host
- `runtime.rs` — host-backed work-item execution pipeline
- `refine.rs` — stateless validation layer
- `accumulate.rs` — state transition layer + anti-spam bond slashing path

## Product launch path (strict)

1. Replace signature placeholder with real Ed25519 checks against active device keys.
2. Add JAM host bindings for:
   - persistent storage APIs
   - fee/bond accounting
   - event emission
3. Build integration tests against local JAM-compatible devnet.
4. Add abuse controls:
   - sender allowlists
   - bond slashing path
   - per-conversation throttles
5. Add client SDK with E2EE envelope generation and chunking.
6. Run adversarial testing + load tests.

## Exit criteria for public beta

- No replay or nonce regression under fuzzing.
- Sequence monotonicity invariant holds under concurrent send attempts.
- Blob commitment mismatches always rejected.
- Read-cursor safety invariant proven with property tests.
- Cost profile under realistic usage within target budget.
