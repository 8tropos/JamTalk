# JamTalk Frontend Audit

## Executive summary

JamTalk currently has a **developer-facing web shell**, not an end-user messaging product yet.

What exists is useful as a protocol/API exerciser:
- wallet auth and challenge flows
- PoP verification form
- conversation/member mutation forms
- blob registration and send/read actions
- status/health/debug outputs

What does **not** exist yet is the UX model users expect from a Telegram-style app:
- chat list + active thread layout
- message bubbles with timestamps and delivery states
- composer-first interaction model
- user/profile abstractions instead of raw JSON arrays
- navigation, onboarding, settings, and empty states
- polished mobile ergonomics

The highest-leverage move is to **split the current control-room shell from a real consumer app shell**. Keep the existing `/app` or move it to `/dev`, and build a separate chat-first `/app` experience.

---

## 1. Current frontend structure

### Runtime / rendering model
- Frontend is served directly by the Rust API via `axum` in `src/web_api.rs`.
- HTML/CSS/JS are embedded with `include_str!()` from `web/`.
- No React/Vue/Svelte/Next/Vite app is present.
- No component system, bundler, router, design tokens layer, or frontend state architecture beyond plain DOM + `localStorage`.

### Frontend files
- `web/landing.html`
- `web/index.html`
- `web/privacy.html`
- `web/terms.html`
- `web/styles.css`
- `web/app.js`

### Routes/pages
Defined in `src/web_api.rs`:
- `/` → landing page
- `/app` → main app shell
- `/privacy`
- `/terms`
- `/app.js`
- `/styles.css`

### API routes used directly by the UI
The app shell directly calls backend endpoints such as:
- auth: `/v1/auth/*`
- conversations: `/v1/conversations*`
- messages: `/v1/messages*`
- PoP: `/v1/pop/verify`
- blobs: `/v1/blobs/register`
- dev helpers: `/v1/dev/*`
- ops/status: `/health`, `/v1/status`, `/v1/auth/metrics`

This means the frontend is currently coupled to backend/internal protocol shapes.

---

## 2. Current information architecture

### Existing IA
The app shell is organized as one long vertical page with cards:
1. Header / quick links
2. Control Room intro
3. Health
4. Wallet Session
5. Auth Challenge / Verify
6. PoP Verify
7. Blob Register
8. Conversation + Send + Read
   - create conversation
   - participants
   - send message
   - read ack
   - list convs/messages
   - timeline
   - status

### Assessment
This IA is logical for QA and protocol validation, but wrong for a consumer messenger.

It exposes implementation details instead of user goals. A normal user thinks in:
- Chats
- Contacts / people
- New message
- Attachments
- Search
- Settings
- Security / linked devices

The current IA instead makes users think in:
- blobs
- roots
- signatures
- byte arrays
- nonces
- fee limits
- admin mutations

That is the single biggest UX gap.

---

## 3. Current components/patterns present

There is no formal component system, but these UI patterns exist:

### Page-level sections
- Header hero
- Card sections
- Two-column auth area
- Sticky compose area
- Timeline container
- Toast notifications

### Reusable interaction patterns in JS
- `callJson()` fetch wrapper
- `withPending()` button busy-state helper
- `toast()` transient feedback
- `renderSession()` local session snapshot
- `fetchMessagesPage()` + pagination cursor handling
- `renderTimeline()` lightweight timeline rendering
- wallet capability detection for injected EVM wallets
- mobile keyboard safety via `visualViewport`

### Current “components” implied by DOM/CSS
- cards
- pill nav links
- capability banners
- timeline cards
- toast
- sticky composer
- responsive `row` / `grid-2`

### Important note
The current message timeline is not a real chat component. It renders protocol metadata cards such as:
- sequence number
- slot
- sender bytes
- message ID hex preview
- cipher length
- chunk count
- flags

That is useful for debugging, but not for conversation UX.

---

## 4. Styling approach

### What is in place
- Single global stylesheet: `web/styles.css`
- Dark theme only
- Strong visual identity already started: gradients, glassmorphism-style cards, neon accents
- Basic responsive breakpoints at ~720px and ~820px
- 44px minimum control height is good for touch
- Sticky compose and safe-area handling are good instincts for mobile

### Strengths
- Modern dark aesthetic is directionally good for a messaging app
- Consistent spacing/radius language
- Buttons/inputs are readable and touch-friendly
- Visual hierarchy is decent for a prototype

### Weaknesses
- Styling is page-level, not system-level
- No typographic scale for chat UI patterns
- No chat-specific primitives: message bubble, avatar, unread badge, chat row, app bar, tab bar, date separator
- No state styling for selected conversation, unread, sent/delivered/read, typing, disabled, error inline
- No light theme or theme token structure
- Heavy “control panel card” look dominates everything

### Conclusion
The current styling is a **good prototype skin**, but not yet a product design system.

---

## 5. Responsiveness status

### What is working
- Viewport meta is present
- Layout collapses to one column on small screens
- Rows become two columns on larger widths
- Inputs/buttons are generally mobile tappable
- Sticky composer exists
- Keyboard handling tries to avoid sticky composer issues on mobile
- Safe-area padding is considered

### What is missing / risky
- No real app-shell layout for mobile chat usage
- Long forms create extreme vertical scroll fatigue
- No split-pane desktop layout for chat list + thread
- No bottom navigation for mobile
- No thumb-zone optimization for primary actions
- No tested handling for long chat histories, virtualized lists, or media-heavy threads
- No clear handling of narrow screens with JSON-heavy inputs

### Verdict
**Technically somewhat responsive, product-wise not mobile-ready.**
It adapts layout, but it does not yet behave like a mobile messenger.

---

## 6. Major UX gaps blocking a Telegram-style end-user app

### A. The UI is protocol-first, not user-first
Users should never see raw `[u8;32]` account arrays, signatures, nonce fields, cipher roots, or fee/bond values in the primary app.

### B. No canonical app shell
Missing:
- sidebar or chat list
- active chat thread view
- message composer as the primary affordance
- settings/profile area
- search/discovery
- contacts/member directory

### C. No identity abstraction
Current wallet/session handling is dev-oriented. A Telegram-like app needs:
- profile name
- avatar
- handle or human-readable identity
- device/session management
- wallet connection as setup/security, not the main screen

### D. No onboarding
There is no guided first-run flow explaining:
- what JamTalk is
- how identity works
- how to connect/verify
- how to start a chat
- what PoP means in practical language

### E. Message experience is absent
Missing:
- outgoing vs incoming bubble alignment
- timestamps
- read receipts
- grouping by sender/time
- day separators
- draft persistence
- message retry/error states
- attachments/media preview
- empty and loading states

### F. Admin/member flows are too exposed
Conversation administration currently appears as raw mutation controls. In a user product, these belong in secondary screens or bottom sheets inside chat info.

### G. No trust/safety product layer
Given JamTalk’s trust-aware positioning, the UI needs comprehensible surfaces for:
- verified personhood status
- trusted / pending / restricted states
- report/block/spam controls
- invite/access rules

### H. Debug output dominates screen real estate
Large `pre` blocks and raw JSON outputs overwhelm the interface and signal “dev tool,” not “consumer app.”

---

## 7. Highest-leverage frontend changes

## Priority 1: Separate dev console from user app
**Do this first.**

Recommendation:
- keep the current control-room UI as `/dev` or `/lab`
- reserve `/app` for the real consumer chat experience

Why this matters:
- protects internal/debug capabilities from polluting product UX
- lets product decisions happen cleanly
- avoids trying to turn one mega-form into a messenger

## Priority 2: Introduce a real Telegram-style app IA
Target IA:
- **Chats**: chat list, unread badges, pinned chats, search
- **Chat thread**: header, message list, composer
- **Contacts / New chat**
- **Profile & Settings**
- **Chat info / Members**
- **Linked devices / Security**

Desktop layout:
- left sidebar: chat list + search
- main pane: active thread
- optional right pane: chat info/details

Mobile layout:
- default screen = chat list
- tap into thread
- thread header + message list + bottom composer
- secondary screens pushed as separate views

## Priority 3: Build a tiny UI component system
Even without React, define reusable blocks first:
- AppShell
- TopBar
- BottomTabBar
- ChatListItem
- Avatar
- Badge
- MessageBubble
- MessageComposer
- EmptyState
- InlineError
- Modal / Sheet
- SettingsRow
- MemberRow

If the project is expected to grow quickly, this is also the point where moving to a component framework becomes justified.

## Priority 4: Introduce view models that hide protocol shapes
Create frontend-facing models that map raw API data into user-friendly entities:
- `UserProfile`
- `ChatSummary`
- `MessageView`
- `MemberView`
- `SessionView`
- `TrustStateView`

Example:
- backend: `[1,1,1,...]`
- frontend: `Koen`, `@koen`, or shortened wallet with label

This abstraction will massively improve both UX and maintainability.

## Priority 5: Replace the current timeline with a real chat thread
Implement:
- bubble alignment
- timestamps
- read/delivery markers
- sender grouping
- date dividers
- pending/sending/failed states
- scroll anchoring to newest messages
- lazy pagination for older history

Keep protocol detail views behind a per-message “Inspect” action for dev mode only.

## Priority 6: Redesign auth/onboarding
Suggested flow:
1. Welcome screen
2. Connect wallet / create identity
3. Verify ownership
4. Optional personhood verification
5. Set display name + avatar
6. Land in empty chat list with CTA: “Start a conversation”

Important principle:
- wallet auth should feel like setup/security infrastructure
- not the main app itself

## Priority 7: Add trust and safety UX as product features
JamTalk has a trust-aware backend direction; surface it well:
- verified badge semantics
- access status labels
- invite approval state
- anti-spam state messaging
- block/report actions
- restricted user explanation copy

This is a differentiator if done clearly.

---

## 8. Suggested target screen map

### Core product screens
1. **Welcome / onboarding**
2. **Connect wallet**
3. **Verify identity**
4. **Optional personhood verification**
5. **Chats list**
6. **Chat thread**
7. **New chat / contacts**
8. **Chat info**
9. **Members management**
10. **Profile & settings**
11. **Linked devices / sessions**

### Secondary/debug screens
12. **Developer console**
13. **Protocol inspector**
14. **API status / health**

This split keeps product UX clean without losing the existing useful tooling.

---

## 9. Recommended implementation path

### Phase A: Product shell
- Create a new `/app` layout with:
  - chat list pane
  - active thread pane
  - empty state if no chat selected
- Move current form-heavy shell to `/dev`
- Keep current backend endpoints; just change presentation first

### Phase B: Messaging UX
- Build message bubble UI
- Render message metadata as normal chat content states
- Add composer, draft handling, attachment affordances, send status
- Add unread and recency sorting in chat list

### Phase C: Identity and trust
- Human-readable profiles
- session settings
- personhood/trust badges
- member management screens

### Phase D: Polish
- motion and transitions
- skeleton loading
- better icons/avatars
- desktop split view and mobile bottom-nav polish
- accessibility pass

---

## 10. Tech recommendation

### Short-term
You can continue with server-served static files for one more iteration **if** you first modularize the UI structure and keep scope small.

### Medium-term
If JamTalk is intended to become a serious end-user app, adopt a component-based frontend stack.

Reason:
- chat UIs have lots of repeated interactive components
- state coordination becomes complex quickly
- settings, onboarding, chat thread behavior, and member management will outgrow plain DOM scripting

A small React + Vite frontend, or similar, would likely pay for itself quickly.

---

## 11. Concrete audit verdict

### Current state
- **Frontend maturity:** prototype / QA console
- **Visual maturity:** promising prototype aesthetic
- **Product maturity:** far from consumer-ready
- **Responsiveness:** basic responsive support, not messenger-grade mobile UX
- **Architecture:** simple and workable now, but not ideal for scaling UI complexity

### Best immediate move
Build a **new chat-first `/app`** and demote the existing shell to **developer tooling**.

### Most important product principle going forward
**Hide protocol complexity behind a human messaging experience.**
That is the difference between a blockchain demo and a Telegram-style app people would actually want to use.

---

## 12. Top 10 action list

1. Move current app shell to `/dev`.
2. Rebuild `/app` as chat list + thread + composer.
3. Introduce frontend view models that hide raw protocol fields.
4. Replace metadata cards with real message bubbles.
5. Add onboarding for wallet connect, verify, and profile setup.
6. Create chat info and member management as secondary screens.
7. Add avatars, names, handles, unread counts, and timestamps.
8. Implement mobile-first navigation and thumb-friendly composer UX.
9. Keep protocol inspection behind debug toggles, not primary UI.
10. Consider moving to a component framework before UI complexity compounds.
