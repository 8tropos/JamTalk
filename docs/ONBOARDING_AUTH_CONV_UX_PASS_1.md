# Onboarding, Auth, and Conversation UX Pass 1

Date: 2026-03-13

## What changed

Implemented a first-pass frontend UX layer for onboarding, auth, and conversation creation without changing backend API contracts.

### Onboarding/auth UX
- Added a guided onboarding card in the right rail with:
  - a 4-step checklist
  - progress bar
  - dynamic next-step summary
  - one-click actions for demo identity, demo sign-in, starter chat creation, and demo bootstrap
- Kept existing auth endpoints and signing routes intact:
  - `POST /v1/auth/challenge`
  - `POST /v1/auth/verify`
  - `POST /v1/auth/verify-wallet`
  - existing dev signing endpoints
- Improved state feedback by tying the onboarding card to live session, conversation, and message state.

### Conversation creation UX
- Added a “Quick create” conversation block above the advanced conversation controls.
- Users can now:
  - choose DM vs group
  - enter a local chat label
  - enter simple demo seeds instead of manually editing full `[u8;32]` JSON arrays
  - generate a fresh conversation id client-side
  - auto-fill creator, participants, sender, member-actor, member-target, and read-reader fields
  - create a starter chat through the existing sign-and-create flow
- Preserved the advanced JSON-based controls for debugging and protocol validation.

### Conversation/message helpers
- Added a helper to align message/member fields with the current conversation participants.
- Added local draft naming so newly created chats can show friendlier labels in the UI even when the backend response does not provide one yet.

## Files changed
- `web/index.html`
- `web/app.js`
- `web/styles.css`

## Validation
- `node --check web/app.js`
- lightweight HTML parse check for `web/index.html`
- `~/.cargo/bin/cargo test`

## Where to check locally

Run:

```bash
cargo run --bin jamtalk-api
```

Then open:

- app shell: `http://127.0.0.1:8080/app`
- landing page: `http://127.0.0.1:8080/`

Focus areas in the app shell:
- right-rail onboarding card under “Health and session”
- quick conversation creation block under “Start or manage a chat”
- conversation naming and message/member field auto-fill behavior

## Commits
- Previously pushed frontend baseline: `d603fb58ea873541148547bd044e654254769abf`
- UX pass 1 commit: `ef9b77ab8c44d65f6175daf6378576624e6c58dd`
