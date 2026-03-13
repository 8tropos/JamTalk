# JamTalk Telegram-Style Web Frontend Redesign Plan

## 1. Goal

Redesign JamTalk's current QA-style web shell into a product-facing messaging app that feels closer to Telegram Web while preserving JamTalk's core differentiators:

- wallet-native identity
- trusted membership controls
- verifiable sequencing and message status
- beta/ops transparency for a protocol-first product

This should **not** copy Telegram literally. It should borrow the interaction model users already understand:

- left conversation list
- central chat pane
- compact top bars
- persistent composer
- lightweight overlays for details/settings
- fast scanability on desktop and mobile

The result should make JamTalk feel like a real messenger first, while still exposing protocol power where it matters.

---

## 2. Current State Summary

The current `/app` is a single long control panel optimized for API QA. It is useful for testing, but not for normal messaging because:

- every action is exposed as a raw form
- conversation creation, auth, PoP, blob registration, membership, sending, reading, and timeline rendering live on one page
- the primary visual pattern is stacked cards and raw JSON output
- the timeline is secondary instead of central
- there is no persistent information architecture around chats, people, and settings
- advanced protocol actions are not progressively disclosed

### Keep from current app

- browser-first wallet flows
- clear auth/session visibility
- existing status and error transparency
- support for message detail/status inspection
- mobile keyboard safety work already present in `app.js`

### Replace / reposition

- move raw JSON utilities out of the main messaging surface
- replace the long vertical form flow with app-shell navigation
- make chat list and active conversation the default center of gravity
- expose protocol/debug tools in drawers, inspector panels, or a dedicated lab mode

---

## 3. Product Principles

1. **Messaging first**  
   The default experience should be reading, sending, searching, and managing chats, not manually assembling payloads.

2. **Trust is visible, not noisy**  
   Wallet identity, verified membership, and delivery/read state should be shown as confidence signals, not walls of protocol jargon.

3. **Progressive disclosure**  
   Casual users see a clean messenger. Power users can open message proofs, blob metadata, member roles, or API diagnostics when needed.

4. **Desktop-native efficiency**  
   Telegram Web works because it is dense, fast, and keyboard-friendly. JamTalk should aim for the same.

5. **Mobile-safe without becoming a separate product**  
   Responsive behavior should preserve core structures rather than replacing the app with unrelated layouts.

6. **Beta honesty**  
   JamTalk is still evolving. The UI should say so clearly through environment badges, empty-state guidance, and transparent failure states.

---

## 4. Target Information Architecture

## Primary app areas

### A. Public / pre-auth surface

- Landing page
- Privacy
- Terms
- Status / health
- Connect wallet entry point

### B. Authenticated app shell

- Chats
- Contacts / members
- Wallet session
- Settings
- Debug / protocol inspector

### C. Contextual overlays

- New chat / new group modal
- Chat info drawer
- Member management drawer
- Wallet/auth sheet
- Message detail inspector
- Search panel
- Global command palette

## Recommended IA map

```text
JamTalk
├─ Landing
├─ Privacy
├─ Terms
└─ App
   ├─ Sidebar
   │  ├─ Search
   │  ├─ Chat list
   │  ├─ New message / new group
   │  └─ Profile + settings entry
   ├─ Active chat pane
   │  ├─ Chat header
   │  ├─ Message timeline
   │  ├─ Composer
   │  └─ Inline status / system events
   ├─ Right utility pane (desktop, optional)
   │  ├─ Chat info
   │  ├─ Members / roles
   │  ├─ Message proof/status
   │  └─ Shared files / media later
   └─ Global overlays
      ├─ Wallet connect + verify
      ├─ Conversation creation
      ├─ Add/remove/promote/demote member
      ├─ Protocol diagnostics
      └─ App settings
```

## Route recommendation

Use shallow routes so the app feels like one shell:

- `/` landing
- `/app` main shell
- `/app/chat/:convId` active conversation deep link
- `/app/settings`
- `/app/debug` optional advanced mode

If JamTalk stays framework-light for now, route state can be handled client-side first, then upgraded later.

---

## 5. Target Layout

## Desktop layout, primary target

### Three-column structure

**Left rail: 300 to 360px**
- brand / environment badge
- search field
- chat filters: All, Unread, Groups, Verified, Pending
- conversation list
- bottom profile/session capsule

**Center pane: flexible primary column**
- chat header
- timeline
- system notices inline
- sticky composer

**Right utility pane: 320 to 380px, collapsible**
- chat details
- member list and role controls
- selected message detail / proof info
- session/debug widgets when needed

This matches Telegram's mental model but gives JamTalk a dedicated space for trust metadata.

## Tablet layout

- default to two panes: list + active chat
- right utility pane becomes slide-over drawer
- if no active chat selected, list occupies full width

## Mobile layout

- one pane at a time
- chat list screen -> tap into conversation screen
- chat info, search, wallet, and debug use bottom sheets / full-screen overlays
- composer remains sticky, safe-area aware
- member management actions live behind top-right overflow menu

---

## 6. Screen-by-Screen Plan

## 6.1 App shell

### Header / shell chrome

Include:
- JamTalk wordmark
- environment chip: Beta / Local / Testnet
- connection badge: Connected / Reconnecting / Offline
- wallet capsule: truncated address + verification state

### Why

Users need immediate confidence on three things:
- am I in the right environment?
- is the app connected?
- who am I signed in as?

## 6.2 Left sidebar: chat index

### Conversation list item structure

Each item should show:
- conversation avatar or initials
- title
- last message preview
- timestamp
- unread badge
- verification/trust badge if relevant
- muted/pinned indicators later

### Filters

Top-level chips:
- All
- Unread
- Groups
- DMs
- Verified

Optional secondary sort:
- Recent
- Unread first
- Trusted first

### Empty state

If no chats exist:
- explain that JamTalk starts from wallet-authenticated conversation creation
- CTA: `New conversation`
- secondary CTA: `Open demo conversation`

## 6.3 Active chat header

Show:
- conversation title
- participant summary
- trust summary: verified members count / pending members / admin count
- optional subtitle such as `Verifiable timeline active`
- actions: search, members, info, more

For groups, the subtitle can contain meaningful protocol hints in plain English:
- `4 verified members`
- `Read sync on`
- `Protected by wallet identity`

## 6.4 Timeline

### Message groups

Visually group messages by sender and time block, similar to Telegram.

### Bubble types

- outgoing message bubble
- incoming message bubble
- system event row
- pending message bubble
- failed / rejected message bubble

### Inline metadata strategy

Hide heavy protocol data by default. Show only:
- timestamp
- send status icon
- read icon if available

Expose detailed metadata through click/tap:
- sequence number
- slot
- message id
- cipher length
- chunk count
- envelope root / blob root
- API response history if useful in debug mode

### System event examples

- `Wallet verified for this session`
- `Alice added Bob`
- `Bob promoted to admin`
- `Read state synced to #184`
- `Network issue, retrying send`

These turn protocol mechanics into readable product language.

## 6.5 Composer

### Primary composer fields

Visible by default:
- text input
- send button
- attach button placeholder
- optional emoji button later

### Hidden advanced send controls

Move current raw fields into an expandable `Advanced` panel or debug drawer:
- sender nonce
- cipher root
- envelope root
- fee limit
- bond limit
- chunk count
- recipient hints

In the normal path, these should be generated or resolved automatically from the message draft and session state.

### Composer behaviors

- sticky at bottom
- auto-grow up to a sensible max height
- Enter to send, Shift+Enter for newline on desktop
- disable send when wallet/auth is invalid
- show inline send progress state
- show retry CTA for failed sends

## 6.6 Chat info drawer

Sections:
- conversation summary
- members and roles
- trust / verification state
- shared media/files placeholder
- conversation actions

Actions:
- add member
- remove member
- promote/demote admin
- inspect conversation id
- copy conversation link/id

## 6.7 Wallet and auth sheet

This replaces the current large auth control area.

### Show in one compact flow

1. Connect wallet
2. Verify challenge
3. Session active
4. Refresh / logout controls

### For advanced users

Add collapsible `Developer signing tools` section with:
- dev seed
- sign challenge
- sign PoP
- sign conversation
- sign send
- sign read
- bootstrap demo

This preserves current QA power without contaminating the main UX.

## 6.8 Protocol / debug panel

A dedicated space for current raw outputs.

Include tabs such as:
- Requests
- Responses
- Timeline internals
- Auth metrics
- Rate limits
- Health/status

This can live:
- as `/app/debug`, or
- as a right drawer only visible in developer mode

Recommendation: support both, with the drawer as a quick inspector and `/app/debug` as a full lab.

---

## 7. Component Map

## Shell components

- `AppShell`
- `TopStatusBar`
- `Sidebar`
- `ChatList`
- `ChatListItem`
- `ActiveChatView`
- `RightInspector`
- `BottomSheet` / `Modal`
- `ToastHost`

## Session / auth

- `WalletSessionChip`
- `WalletConnectModal`
- `ChallengeVerifyPanel`
- `AuthStateBanner`
- `ConnectionStatusBadge`

## Chat domain

- `ChatHeader`
- `TrustBadgeRow`
- `MessageTimeline`
- `MessageGroup`
- `MessageBubbleIncoming`
- `MessageBubbleOutgoing`
- `SystemEventRow`
- `MessageStatusIcon`
- `Composer`
- `ComposerAdvancedPanel`

## Conversation management

- `NewConversationModal`
- `MemberList`
- `MemberRoleBadge`
- `MemberActionMenu`
- `ChatInfoDrawer`

## Diagnostics

- `JsonInspector`
- `RequestLogPanel`
- `MessageProofDrawer`
- `HealthStatusCard`
- `RateLimitCard`

## Empty/loading/error

- `EmptyChatsState`
- `EmptyTimelineState`
- `SkeletonChatList`
- `SkeletonTimeline`
- `InlineErrorBanner`
- `OfflineBanner`

---

## 8. Visual Direction

## Positioning

Telegram-like in structure, but more premium and trust-centric in expression.

### Current visual language to evolve

Current JamTalk already uses:
- dark theme
- glassy cards
- cyan/violet accents

Keep that base, but simplify it. Telegram works because it is quieter than the current card-heavy shell.

## Proposed visual system

### Color

Base:
- deep graphite / blue-black app background
- slightly lighter panel surfaces
- strong contrast for text

Accent:
- keep cyan as primary action / active state
- keep violet as secondary brand accent
- add semantic green for verified/trusted states
- use amber for pending / caution
- use red only for real errors or failed sends

### Surface hierarchy

- app background
- panel background
- hover row background
- active conversation highlight
- selected message highlight

Reduce strong borders. Prefer subtle separators, soft elevation, and row highlighting.

### Typography

- cleaner hierarchy than current all-caps sectioning
- avoid overusing uppercase headings inside the app shell
- primary text 14 to 16px
- metadata 12 to 13px
- title weights medium to semibold

### Shape

- moderate radius, not overly rounded everywhere
- message bubbles more rounded than panels
- sidebar rows lightly rounded
- buttons compact and dense rather than large marketing-style pills

### Icons

Use a consistent icon set for:
- search
- compose
- verified
- members
- info
- send
- read
- retry
- settings
- wallet

## Suggested aesthetic references

Blend:
- Telegram Web's information density
- Linear / Raycast-like clarity for tooling surfaces
- a subtle on-chain/trust identity through badges and inspectors

---

## 9. Responsive Behavior

## Desktop, 1280px+

- show left sidebar, active chat, and optional right inspector
- search always visible
- keyboard shortcuts enabled
- dense message layout with hover actions

## Small desktop / tablet, 768px to 1279px

- left sidebar remains visible
- right inspector collapses into overlay
- chat header actions become icon-only where needed
- composer remains full width

## Mobile, below 768px

- show either chat list or active chat, not both
- use top navigation/back affordance
- full-width bottom composer
- chat info and wallet/auth appear as sheets
- preserve unread counts and trust badges in compact form

## Mobile-specific considerations

- maintain `visualViewport` keyboard safety already present
- ensure safe-area padding for composer and bottom sheets
- avoid oversized diagnostic text in default paths
- use swipe-back or explicit back button for chat exit if framework supports it

---

## 10. State Model and UX States

## Global states

### Signed out
- landing or app shell with auth gate
- prompt to connect wallet
- allow read-only demo mode if desired

### Connected but unverified
- wallet visible
- restricted actions explained clearly
- CTA: verify challenge

### Verified session
- full messaging enabled
- session chip shows active state

### Offline / degraded API
- persistent banner
- timeline cache remains visible if available
- composer disabled or queued depending on implementation stage

## Conversation states

### No chats
- friendly onboarding empty state

### Chat selected, no messages
- invite first message
- if group, suggest adding members

### Loading history
- skeleton rows, not raw `...`

### Sending
- pending bubble appears immediately
- status icon changes as API confirms

### Failed send
- bubble shows failed state + retry
- reason available on click

### Message detail selected
- proof/status drawer opens

## Membership states

- verified member
- pending/unverified member
- admin
- removed / blocked later if added

Make these states legible via concise badges, not verbose labels.

---

## 11. Interaction Patterns

## Recommended primary interactions

- click chat to open
- search chats inline
- compose/send from persistent footer
- click message to open detail/proof drawer
- click chat header to open chat info drawer
- click wallet chip to open session sheet
- use command palette for power actions

## Keyboard shortcuts worth implementing

- `Ctrl/Cmd + K`: global search / command palette
- `Ctrl/Cmd + N`: new chat
- `Esc`: close drawer or modal
- `↑` in empty composer: edit last draft later
- `Enter`: send
- `/` focus search when not typing

## Recommended progressive disclosure pattern

### Default user view
- title
- messages
- badges
- composer

### Expanded detail view
- sequence
- slot
- message ID
- proof/blob metadata
- request/response payloads

This is the right compromise between consumer familiarity and protocol transparency.

---

## 12. Mapping Existing Functions to New UI

Current UI/API capability should map like this:

| Existing capability | New UI home |
|---|---|
| Health / status | status badge + debug panel |
| Auth challenge / verify / refresh / logout | wallet/auth sheet |
| EVM wallet connect / verify | wallet/auth sheet |
| PoP verify | trust/debug tools or admin tools |
| Blob register | internal composer pipeline + debug detail |
| Create conversation | new conversation modal |
| Add/remove/promote/demote member | chat info drawer |
| List conversations | left sidebar data source |
| List messages / pagination | timeline + infinite scroll/load older |
| Message detail / status | right-side message inspector |
| Send message | main composer |
| Read ack | automatic read-state logic + inspector visibility |
| Dev sign tools | developer tools accordion |
| Demo bootstrap | onboarding CTA / debug tool |

---

## 13. Suggested Data and UI Simplifications

To reach a Telegram-style UX, the frontend should introduce client-side view models instead of binding raw endpoint payloads directly into the UI.

## Create view-model layers

### ConversationViewModel
- id
- title
- type
- avatar
- membersSummary
- lastMessagePreview
- lastActivityAt
- unreadCount
- trustState

### MessageViewModel
- id
- seq
- senderDisplay
- direction
- bodyPreview or decryptedBody
- sentAt or slot-derived display
- sendState
- readState
- proofAvailable
- raw

### SessionViewModel
- wallet
- walletType
- chainId
- authState
- connectedAt
- capabilities

This will let the UI stay clean even if APIs remain protocol-centric.

---

## 14. Phased Implementation Roadmap

## Phase 0: Design and architecture prep

**Objective:** prepare the frontend for shell-based UX without changing backend behavior.

Tasks:
- document target routes and layout regions
- define view models and state containers
- inventory reusable API helpers from current `app.js`
- separate protocol actions from presentation logic
- create low-fidelity wireframes for desktop and mobile

Deliverables:
- route map
- component tree
- state model
- annotated wireframes

## Phase 1: App shell and conversation-first layout

**Objective:** replace the long QA page with a Telegram-style shell.

Tasks:
- implement left sidebar, active chat pane, and top status bar
- load conversation list into sidebar
- load selected conversation into central pane
- move raw output areas out of main flow
- introduce empty states and skeleton states

Success criteria:
- user can open app and understand the product in under 10 seconds
- chats and active conversation become the default focus

## Phase 2: Wallet/auth integration redesign

**Objective:** compact the identity flow into a polished session experience.

Tasks:
- create wallet/auth modal or sheet
- surface connect, verify, refresh, and logout in one place
- add session badge in shell chrome
- gate sending and group actions based on auth state
- move dev signing utilities behind advanced disclosure

Success criteria:
- auth no longer consumes the main page
- user can clearly see whether messaging is enabled

## Phase 3: Composer and timeline polish

**Objective:** make messaging feel real-time and product-grade.

Tasks:
- build message bubbles, grouping, timestamps, and pending states
- optimistic sending with retry/fail handling
- auto-refresh or polling abstraction with connection state
- load older messages via timeline pagination
- expose message detail in inspector drawer

Success criteria:
- sending, reading, and browsing history feel coherent
- protocol state is inspectable without being intrusive

## Phase 4: Conversation and member management

**Objective:** support realistic group workflows.

Tasks:
- build new conversation modal
- create chat info drawer with member list and role badges
- add member mutation actions with confirmation UX
- display trust/admin states clearly
- translate system actions into timeline event rows

Success criteria:
- group administration is understandable to non-developers
- membership trust becomes a visible product strength

## Phase 5: Debug / protocol inspector mode

**Objective:** preserve QA power for beta and engineering.

Tasks:
- implement debug drawer or `/app/debug`
- request/response log viewer
- health, status, metrics, and rate-limit panels
- raw JSON inspectors for selected messages/conversations
- developer mode toggle stored locally

Success criteria:
- engineers can still test everything
- normal users are no longer overwhelmed

## Phase 6: Visual refinement and usability pass

**Objective:** make the shell feel production-credible.

Tasks:
- tune spacing, density, and typography
- standardize icons and badges
- improve hover/focus/accessibility states
- test keyboard flows and mobile layouts
- add polished empty states and onboarding hints

Success criteria:
- app looks intentional, not transitional
- desktop and mobile both feel stable and fast

---

## 15. Suggested Technical Refactor for Frontend Code

The current `web/app.js` is a single imperative file. For the redesign, refactor before or during implementation.

## Minimum refactor path

Split into:
- `api/` for endpoint wrappers
- `state/` for session, conversations, messages, UI state
- `components/` for render units
- `views/` for shell screens
- `utils/` for formatting, JSON parsing, status mapping

If staying framework-free:
- use small render modules and event delegation
- keep state in a central store object
- avoid direct DOM updates scattered across unrelated features

If adopting a framework later:
- this layout maps naturally to React, Vue, or Svelte
- but the IA and component model should be defined first, independent of framework choice

---

## 16. Risks and Mitigations

## Risk: Telegram mimicry without JamTalk differentiation

Mitigation:
- preserve JamTalk identity through trust badges, wallet session chip, proof drawer, and environment transparency

## Risk: advanced protocol features disappear

Mitigation:
- keep a deliberate debug mode and message inspector

## Risk: frontend complexity increases too quickly

Mitigation:
- phase the work, starting with shell and layout before micro-interactions

## Risk: mobile suffers because desktop is primary

Mitigation:
- design mobile navigation rules up front, especially for drawers, sheets, and composer behavior

## Risk: raw backend data is too technical for clean UI binding

Mitigation:
- create view-model adapters and formatter utilities early

---

## 17. Recommended MVP Redesign Scope

If the team wants the highest impact with limited effort, implement this subset first:

1. New app shell with sidebar + chat pane
2. Wallet/auth modal with session chip
3. Conversation list bound to `/v1/conversations`
4. Timeline bound to `/v1/messages`
5. Composer bound to send flow
6. Message pending/error states
7. Chat info drawer with members
8. Hidden debug drawer for current raw outputs

This is enough to change JamTalk from a testing dashboard into a credible messenger beta.

---

## 18. Definition of Done

The redesign should be considered successful when:

- a new user can identify chats, current conversation, and message composer immediately
- wallet connection and auth are understandable in one compact flow
- sending a message feels like a chat action, not an API operation
- trust, verification, and admin state are visible but not overwhelming
- protocol data remains available on demand for debugging and beta operations
- desktop, tablet, and mobile each have a coherent navigation model

---

## 19. Final Recommendation

JamTalk should move from a **protocol cockpit** to a **messenger shell with protocol depth**.

The right model is:
- **Telegram for layout and navigation clarity**
- **JamTalk for trust semantics and verifiable messaging**
- **a hidden lab mode for engineering-grade inspection**

That combination gives JamTalk the best chance of feeling familiar to users while still expressing what makes it meaningfully different.
