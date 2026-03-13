const q = (id) => document.getElementById(id);
const SESSION_KEY = 'jamtalk.session.v1';

let timelineItems = [];
let nextBeforeSeq = null;
let autoRefreshWanted = false;
let refreshTimer = null;
let conversationItems = [];
let activeConversationKey = null;
let selectedMessageSeq = null;
let conversationDraftNames = {};

function readSession() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_KEY) || '{}');
  } catch {
    return {};
  }
}

function writeSession(s) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(s));
}

function shortAccount(a) {
  if (!Array.isArray(a)) return 'unknown';
  return `${a.slice(0, 4).join(',')}...`;
}

function accountInitials(a) {
  if (!Array.isArray(a) || !a.length) return 'JT';
  return a.slice(0, 2).map((v) => Number(v).toString(16).padStart(2, '0')).join('').toUpperCase();
}

function seededAccount(seed) {
  const n = Number(seed || 0);
  return Array.from({ length: 32 }, () => n);
}

function randomConversationId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)));
}

function parseSeedCsv(value) {
  return (value || '')
    .split(',')
    .map((part) => Number(part.trim()))
    .filter((part) => Number.isInteger(part) && part >= 0 && part <= 255);
}

function currentConversationDraftName() {
  return q('quick-conv-name')?.value?.trim() || 'New chat';
}

function setConversationHint(text, kind = 'ok') {
  const box = q('quick-conv-hint');
  if (!box) return;
  box.classList.remove('ok', 'warn');
  if (kind) box.classList.add(kind);
  box.textContent = text;
}

function syncConversationDraftFromForm() {
  const convValue = q('conv-id')?.value?.trim();
  if (!convValue) return;
  conversationDraftNames[convValue] = currentConversationDraftName();
}

function prefillParticipantFields(accounts = []) {
  if (!accounts.length) return;
  q('conv-creator').value = JSON.stringify(accounts[0]);
  q('msg-sender').value = JSON.stringify(accounts[0]);
  q('member-actor').value = JSON.stringify(accounts[0]);
  q('read-reader').value = JSON.stringify(accounts[Math.min(1, accounts.length - 1)]);
  if (accounts[1]) q('member-target').value = JSON.stringify(accounts[1]);
}

function syncQuickConversationInputsFromAdvanced() {
  try {
    const participants = JSON.parse(q('conv-participants').value);
    const seeds = Array.isArray(participants)
      ? participants.map((account) => Array.isArray(account) ? Number(account[0]) : null).filter((v) => Number.isInteger(v))
      : [];
    if (seeds.length) q('quick-participant-seeds').value = seeds.join(',');
  } catch {}
  try {
    const creator = JSON.parse(q('conv-creator').value);
    if (Array.isArray(creator) && creator.length) q('quick-creator-seed').value = String(Number(creator[0]));
  } catch {}
  if (q('conv-type')?.value) q('quick-conv-type').value = q('conv-type').value;
  const storedName = conversationDraftNames[q('conv-id')?.value?.trim() || ''];
  if (storedName) q('quick-conv-name').value = storedName;
}

function buildQuickConversationDraft() {
  const creatorSeed = Number(q('quick-creator-seed').value || '1');
  const participantSeeds = parseSeedCsv(q('quick-participant-seeds').value);
  const uniqueSeeds = [...new Set([creatorSeed, ...participantSeeds])].filter((seed) => Number.isInteger(seed) && seed >= 0 && seed <= 255);
  if (!uniqueSeeds.length) throw new Error('Enter at least one valid demo seed between 0 and 255');
  const accounts = uniqueSeeds.map(seededAccount);
  const convId = randomConversationId();
  q('conv-id').value = JSON.stringify(convId);
  q('conv-type').value = q('quick-conv-type').value;
  q('conv-creator').value = JSON.stringify(accounts[0]);
  q('conv-participants').value = JSON.stringify(accounts);
  prefillParticipantFields(accounts);
  conversationDraftNames[q('conv-id').value] = currentConversationDraftName();
  setConversationHint(`Draft ready: ${currentConversationDraftName()} with ${accounts.length} participant${accounts.length === 1 ? '' : 's'}. Sign and create when ready.`, 'ok');
  updateShellSummary();
  return { convId, accounts };
}

function onboardingState() {
  const session = readSession();
  return {
    connected: !!session.wallet,
    verified: !!session.authVerified,
    hasConversation: !!activeConversationItem() || conversationItems.length > 0,
    hasMessages: timelineItems.length > 0,
  };
}

function renderOnboardingChecklist() {
  const box = q('onboarding-checklist');
  if (!box) return;
  const state = onboardingState();
  const steps = [
    ['Connect wallet', state.connected, state.connected ? 'Wallet linked locally.' : 'Use demo identity or connect an injected wallet.'],
    ['Verify access', state.verified, state.verified ? 'Session verified and ready for chat actions.' : 'Complete challenge verification to unlock messaging.'],
    ['Open a chat', state.hasConversation, state.hasConversation ? 'A conversation is selected or available.' : 'Create a starter chat or load demo data.'],
    ['Send a message', state.hasMessages, state.hasMessages ? 'Timeline has at least one message.' : 'Send your first encrypted message to complete the flow.'],
  ];
  const completed = steps.filter(([, done]) => done).length;
  const current = Math.min(completed + 1, steps.length);
  box.innerHTML = steps.map(([label, done, meta], index) => `
    <div class="checklist-item ${done ? 'done' : ''}">
      <span>${done ? '✓' : index + 1}</span>
      <div><strong>${label}</strong><p>${meta}</p></div>
    </div>
  `).join('');
  if (q('onboarding-progress-bar')) q('onboarding-progress-bar').style.width = `${(completed / steps.length) * 100}%`;
  if (q('onboarding-progress-copy')) q('onboarding-progress-copy').textContent = completed === steps.length ? 'All core steps complete' : `Step ${current} of ${steps.length}`;
  if (q('onboarding-summary')) q('onboarding-summary').textContent = !state.connected
    ? 'Start by linking a wallet or using the built-in demo identity.'
    : !state.verified
      ? 'Wallet linked. Next, complete sign-in so the session can create chats and send messages.'
      : !state.hasConversation
        ? 'You are signed in. Create a starter chat or bootstrap demo data.'
        : !state.hasMessages
          ? 'Chat ready. Send the first message to confirm the end-to-end flow.'
          : 'Core onboarding is complete. You can now manage members, inspect details, and continue testing.';
}

function shortHexBytes(a) {
  if (!Array.isArray(a)) return 'n/a';
  return a.slice(0, 6).map((v) => Number(v).toString(16).padStart(2, '0')).join('') + '...';
}

function prettyJson(value, fallback = 'Waiting…') {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function setOutput(id, value, fallback) {
  const el = q(id);
  if (!el) return;
  el.textContent = prettyJson(value, fallback);
}

function isOutgoingMessage(message) {
  try {
    const sender = Array.isArray(message?.sender) ? JSON.stringify(message.sender) : '';
    const composerSender = q('msg-sender')?.value?.trim() || '';
    const creator = q('conv-creator')?.value?.trim() || '';
    return !!sender && (sender === composerSender || sender === creator);
  } catch {
    return false;
  }
}

function deriveConversationKey(conv) {
  if (!conv) return q('conv-id')?.value?.trim() || 'active';
  if (typeof conv.conv_id === 'string') return conv.conv_id;
  if (Array.isArray(conv.conv_id)) return JSON.stringify(conv.conv_id);
  if (Array.isArray(conv.id)) return JSON.stringify(conv.id);
  return String(conv.conv_id || conv.id || 'active');
}


function activeConversationItem() {
  return conversationItems.find((item) => deriveConversationKey(item) === activeConversationKey) || null;
}

function selectedMessageItem() {
  return timelineItems.find((item) => item.seq === selectedMessageSeq) || null;
}

function conversationParticipantCount(conv) {
  if (!conv) return 0;
  if (Array.isArray(conv.participants)) return conv.participants.length;
  if (Array.isArray(conv.initial_participants)) return conv.initial_participants.length;
  return Number(conv.member_count || 0);
}

function humanConversationTitle(conv, index = 0) {
  if (!conv) return 'No chat selected';
  return conv.title || conversationDraftNames[deriveConversationKey(conv)] || `${(conv.conv_type || conv.kind || 'chat').toUpperCase()} ${index + 1}`;
}

function humanMessageTitle(message) {
  if (!message) return 'No message selected';
  return `Message #${message.seq}`;
}

function updateOverviewCards() {
  const session = readSession();
  const conv = activeConversationItem();
  const message = selectedMessageItem();
  const state = summarizeSessionState(session);
  const walletShort = session.wallet ? `${String(session.wallet).slice(0, 8)}…${String(session.wallet).slice(-4)}` : 'No wallet';

  if (q('session-human-state')) q('session-human-state').textContent = state === 'Verified' ? 'Verified session ready' : state === 'Connected' ? 'Wallet connected, verify to send' : 'Connect a wallet to start';
  if (q('session-wallet-short')) q('session-wallet-short').textContent = walletShort;
  if (q('summary-session-trust')) q('summary-session-trust').textContent = state;
  if (q('summary-session-meta')) q('summary-session-meta').textContent = state === 'Verified'
    ? `Signed in${session.walletType ? ` via ${session.walletType.toUpperCase()}` : ''}. Messaging and member actions are available.`
    : state === 'Connected'
      ? 'Wallet linked locally. Finish challenge verification for full messaging.'
      : 'No active wallet session yet.';

  if (q('summary-conversation-name')) q('summary-conversation-name').textContent = conv ? humanConversationTitle(conv, conversationItems.indexOf(conv)) : 'No chat selected';
  if (q('summary-conversation-meta')) q('summary-conversation-meta').textContent = conv
    ? `${conversationParticipantCount(conv)} participant${conversationParticipantCount(conv) === 1 ? '' : 's'} • ${conv.conv_type || conv.kind || 'chat'} • ${timelineItems.length} visible message${timelineItems.length === 1 ? '' : 's'}`
    : 'Choose a conversation to load its participant and timeline summary.';

  if (q('hero-active-chat')) q('hero-active-chat').textContent = conv ? humanConversationTitle(conv, conversationItems.indexOf(conv)) : 'No selection';
  if (q('hero-active-chat-meta')) q('hero-active-chat-meta').textContent = conv
    ? `${conversationParticipantCount(conv)} participant${conversationParticipantCount(conv) === 1 ? '' : 's'} • ${conv.conv_type || conv.kind || 'chat'}`
    : 'Choose or create a conversation';
  if (q('hero-trust-state')) q('hero-trust-state').textContent = state === 'Verified' ? 'Trusted session live' : state === 'Connected' ? 'Verification pending' : 'Session pending';
  if (q('hero-trust-meta')) q('hero-trust-meta').textContent = state === 'Verified'
    ? 'Wallet verified. You can send and manage conversations.'
    : state === 'Connected'
      ? 'Wallet connected. Run challenge verification to unlock full actions.'
      : 'Verify a wallet session to unlock the full flow';

  if (q('summary-message-title')) q('summary-message-title').textContent = humanMessageTitle(message);
  if (q('summary-message-meta')) q('summary-message-meta').textContent = message
    ? `Sender ${shortAccount(message.sender)} • slot ${message.slot ?? '-'} • ${message.cipher_len ?? '-'} encrypted bytes • ${message.chunk_count ?? '-'} chunk${message.chunk_count === 1 ? '' : 's'}`
    : 'Click a message bubble to inspect delivery and payload details.';
}

function markSyncState(label, meta) {
  if (q('hero-sync-state')) q('hero-sync-state').textContent = label;
  if (q('hero-sync-meta')) q('hero-sync-meta').textContent = meta;
}

function selectMessage(seq) {
  selectedMessageSeq = seq;
  const message = selectedMessageItem();
  if (message && q('detail-seq')) q('detail-seq').value = String(message.seq);
  updateOverviewCards();
  renderOnboardingChecklist();
}


function summarizeSessionState(session = readSession()) {
  if (session.authVerified) return 'Verified';
  if (session.wallet) return 'Connected';
  return 'Offline';
}

function updateShellSummary() {
  syncQuickConversationInputsFromAdvanced();
  const session = readSession();
  const state = summarizeSessionState(session);
  const convCount = conversationItems.length;
  const msgCount = timelineItems.length;

  if (q('sidebar-conversation-count')) q('sidebar-conversation-count').textContent = String(convCount);
  if (q('sidebar-message-count')) q('sidebar-message-count').textContent = String(msgCount);
  if (q('sidebar-session-state')) q('sidebar-session-state').textContent = state;

  const conv = activeConversationItem();
  if (q('active-conversation-title')) {
    q('active-conversation-title').textContent = conv ? humanConversationTitle(conv, conversationItems.indexOf(conv)) : 'Your secure inbox';
  }
  if (q('active-conversation-subtitle')) {
    q('active-conversation-subtitle').textContent = conv
      ? `${conversationParticipantCount(conv)} participant${conversationParticipantCount(conv) === 1 ? '' : 's'} • ${conv.conv_type || conv.kind || 'chat'} • ${msgCount} message${msgCount === 1 ? '' : 's'} visible`
      : `${session.wallet ? `Wallet ${session.wallet}` : 'No wallet connected yet'} • ${state} session • choose a chat or bootstrap demo data.`;
  }

  updateOverviewCards();
  renderOnboardingChecklist();
}

function setActiveConversationTitle(title, subtitle) {
  if (q('active-conversation-title')) q('active-conversation-title').textContent = title;
  if (q('active-conversation-subtitle')) q('active-conversation-subtitle').textContent = subtitle;
}

function renderSession() {
  const s = readSession();
  setOutput('out-session', s, 'No local session yet.');
  if (s.wallet) q('wallet').value = s.wallet;
  if (s.challenge) q('challenge').value = s.challenge;
  if (s.pubkey) q('pubkey').value = JSON.stringify(s.pubkey);
  if (s.signature) q('sig').value = JSON.stringify(s.signature);
  updateShellSummary();
  updateOverviewCards();
}

async function callJson(url, method = 'GET', body = null) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const txt = await res.text();
  let parsed;
  try { parsed = JSON.parse(txt); } catch { parsed = txt; }
  return { ok: res.ok, status: res.status, body: parsed };
}

function toast(msg, isError = false) {
  const t = q('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.remove('hidden');
  t.classList.toggle('error', isError);
  setTimeout(() => t.classList.add('hidden'), 2200);
}

function apiErrorText(res, fallback = 'Request failed') {
  if (res?.body?.error?.code) {
    return `${res.body.error.code}: ${res.body.error.message}`;
  }
  return fallback;
}

async function withPending(btnId, fn) {
  const btn = q(btnId);
  if (!btn) return fn();
  const prev = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Working...';
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.textContent = prev;
  }
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function messagePreview(message) {
  if (!message) return 'No messages yet';
  return `seq #${message.seq} • cipher ${message.cipher_len ?? '-'} bytes • ${message.chunk_count ?? '-'} chunk${message.chunk_count === 1 ? '' : 's'}`;
}

function renderConversationList() {
  const box = q('conversation-list');
  if (!box) return;
  if (!conversationItems.length) {
    box.innerHTML = `
      <div class="empty-state compact">
        <div class="empty-icon">💬</div>
        <div>
          <strong>No chats loaded yet</strong>
          <p>Run the demo bootstrap or refresh conversations to populate the sidebar.</p>
        </div>
      </div>
    `;
    updateShellSummary();
    return;
  }

  box.innerHTML = conversationItems.map((conv, index) => {
    const key = deriveConversationKey(conv);
    const active = key === activeConversationKey || (!activeConversationKey && index === 0);
    const title = humanConversationTitle(conv, index);
    const participantCount = Array.isArray(conv.participants)
      ? conv.participants.length
      : Array.isArray(conv.initial_participants)
        ? conv.initial_participants.length
        : Number(conv.member_count || 0);
    const snippet = conv.last_message_preview || conv.last_message || `Secure ${conv.conv_type || conv.kind || 'chat'} • ${participantCount || 0} participant${participantCount === 1 ? '' : 's'}`;
    const avatar = escapeHtml((title || 'JT').slice(0, 2).toUpperCase());
    return `
      <button class="conversation-card ${active ? 'active' : ''}" data-conv-key="${escapeHtml(key)}" type="button">
        <div class="conversation-card-main">
          <div class="conversation-avatar">${avatar}</div>
          <div class="conversation-card-copy">
            <div class="conversation-card-header">
              <span class="conversation-title">${escapeHtml(title)}</span>
              <span class="conversation-meta">${escapeHtml(conv.conv_type || conv.kind || 'chat')}</span>
            </div>
            <p class="conversation-snippet">${escapeHtml(snippet)}</p>
            <div class="conversation-meta">${participantCount || 0} participant${participantCount === 1 ? '' : 's'}</div>
          </div>
        </div>
      </button>
    `;
  }).join('');

  box.querySelectorAll('[data-conv-key]').forEach((el) => {
    el.addEventListener('click', async () => {
      const key = el.getAttribute('data-conv-key');
      const conv = conversationItems.find((item) => deriveConversationKey(item) === key);
      activeConversationKey = key;
      if (conv?.conv_id && Array.isArray(conv.conv_id)) {
        q('conv-id').value = JSON.stringify(conv.conv_id);
      }
      renderConversationList();
      setActiveConversationTitle(
        humanConversationTitle(conv, conversationItems.indexOf(conv)),
        `${conversationParticipantCount(conv)} participant${conversationParticipantCount(conv) === 1 ? '' : 's'} • ${conv?.conv_type || conv?.kind || 'chat'}`
      );
      updateOverviewCards();
      await fetchMessagesPage(null, false);
    });
  });

  updateShellSummary();
}

function renderTimeline(msgRes) {
  const box = q('timeline');
  if (!box) return;
  const items = msgRes?.body?.items || timelineItems;
  if (!items.length) {
    box.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🫧</div>
        <div>
          <strong>No timeline yet</strong>
          <p>Create a conversation or bootstrap demo data to see the message stream here.</p>
        </div>
      </div>
    `;
    selectedMessageSeq = null;
    updateShellSummary();
    return;
  }

  const ordered = [...items].sort((a, b) => a.seq - b.seq);
  if (!selectedMessageSeq || !ordered.some((m) => m.seq === selectedMessageSeq)) {
    selectedMessageSeq = ordered[ordered.length - 1]?.seq ?? null;
  }
  box.innerHTML = ordered.map((m) => {
    const outgoing = isOutgoingMessage(m);
    const label = outgoing ? 'You' : 'Member';
    const selected = m.seq === selectedMessageSeq;
    return `
      <article class="message-row ${outgoing ? 'outgoing' : 'incoming'} ${selected ? 'selected' : ''}">
        <button class="message-cluster message-selectable" data-message-seq="${m.seq}" type="button">
          <div class="message-avatar">${escapeHtml(accountInitials(m.sender))}</div>
          <div class="message-bubble">
            <div class="message-card-top">
              <strong>${label}</strong>
              <span class="message-badge">Delivered • #${m.seq}</span>
            </div>
            <p class="message-body">Encrypted JamTalk message<br/><span class="message-subline">Sender ${escapeHtml(shortAccount(m.sender))} • message ${escapeHtml(shortHexBytes(m.msg_id))}</span></p>
            <div class="message-card-bottom">
              <span class="message-meta">slot ${m.slot ?? '-'} • flags ${m.flags ?? 0}</span>
              <span class="message-meta">${m.cipher_len ?? '-'} encrypted bytes • ${m.chunk_count ?? '-'} chunk${m.chunk_count === 1 ? '' : 's'}</span>
            </div>
          </div>
        </button>
      </article>
    `;
  }).join('');

  box.querySelectorAll('[data-message-seq]').forEach((el) => {
    el.addEventListener('click', () => {
      selectMessage(Number(el.getAttribute('data-message-seq')));
      renderTimeline();
    });
  });

  const latest = ordered[ordered.length - 1];
  markSyncState('Timeline synced', `Latest ${messagePreview(latest)}`);

  if (q('timeline-autoscroll')?.checked) {
    box.scrollTop = box.scrollHeight;
  }
  updateShellSummary();
}

async function fetchMessagesPage(beforeSeq = null, append = false) {
  const conv = q('conv-id').value.trim();
  const limit = Number(q('msg-page-limit').value || '20');
  const params = new URLSearchParams({ conv_id: conv, limit: String(limit) });
  if (beforeSeq !== null && beforeSeq !== undefined && beforeSeq !== '') {
    params.set('before_seq', String(beforeSeq));
  }
  const res = await callJson(`/v1/messages?${params.toString()}`);
  if (res.ok) {
    nextBeforeSeq = res.body?.next_before_seq ?? null;
    q('msg-before-seq').value = nextBeforeSeq ? String(nextBeforeSeq) : '';
    if (append) {
      const existing = new Map(timelineItems.map((m) => [m.seq, m]));
      (res.body?.items || []).forEach((m) => existing.set(m.seq, m));
      timelineItems = [...existing.values()];
    } else {
      timelineItems = res.body?.items || [];
    }
    renderTimeline();
    updateOverviewCards();
    markSyncState('Timeline synced', `Loaded ${timelineItems.length} message${timelineItems.length === 1 ? '' : 's'}${nextBeforeSeq ? ` • older cursor #${nextBeforeSeq}` : ''}`);
  }
  return res;
}

async function refreshLists() {
  const convRes = await callJson('/v1/conversations');
  if (convRes.ok) {
    const list = convRes.body?.items || convRes.body?.conversations || convRes.body || [];
    conversationItems = Array.isArray(list) ? list : [];
    if (!activeConversationKey && conversationItems.length) {
      activeConversationKey = deriveConversationKey(conversationItems[0]);
    }
    renderConversationList();
  }
  const msgRes = await fetchMessagesPage(null, false);
  setOutput('out-list', { conversations: convRes, messages: msgRes }, 'No list payload yet.');
  updateOverviewCards();
}


function devSeed() {
  return Number(q('dev-seed')?.value || '1');
}

function setWalletCapability(kind, text) {
  const box = q('wallet-capability');
  if (!box) return;
  box.classList.remove('ok', 'warn');
  if (kind) box.classList.add(kind);
  box.textContent = text;
}

function allowedChainIds() {
  return (q('evm-allowed-chains')?.value || '')
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isFinite(n) && n > 0);
}

async function currentChainIdDec() {
  if (!window.ethereum) return null;
  const hex = await window.ethereum.request({ method: 'eth_chainId' });
  return Number.parseInt(hex, 16);
}

async function refreshWalletCapability() {
  const hasEvm = !!window.ethereum;
  const evmBtns = ['btn-connect-evm', 'btn-evm-sign-verify'];
  evmBtns.forEach((id) => {
    const el = q(id);
    if (el) el.disabled = !hasEvm;
  });

  if (hasEvm) {
    const cid = await currentChainIdDec();
    if (Number.isFinite(cid)) q('evm-chain-id').value = String(cid);
    const allowed = allowedChainIds();
    if (cid && allowed.length && !allowed.includes(cid)) {
      setWalletCapability('warn', `Injected EVM wallet detected on chain ${cid}, but it is not in allowed list (${allowed.join(', ')}).`);
    } else {
      setWalletCapability('ok', 'Injected EVM wallet detected. You can connect and use personal_sign verification.');
    }
  } else {
    setWalletCapability('warn', 'No injected EVM wallet detected. Install MetaMask or Rabby in this browser, or use manual/dev signing flow.');
  }
  updateOverviewCards();
}

q('btn-connect').onclick = () => {
  const wallet = q('wallet').value.trim() || `wallet-${Date.now()}`;
  const s = readSession();
  s.wallet = wallet;
  s.connectedAt = new Date().toISOString();
  writeSession(s);
  renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
  toast('Wallet connected locally');
};

q('btn-connect-evm').onclick = async () => {
  if (!window.ethereum) {
    toast('No injected wallet found', true);
    return;
  }
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const wallet = accounts?.[0];
    if (!wallet) return;
    const cid = await currentChainIdDec();
    if (Number.isFinite(cid)) q('evm-chain-id').value = String(cid);

    q('wallet').value = wallet;
    const s = readSession();
    s.wallet = wallet;
    s.walletType = 'evm';
    s.chainId = cid;
    s.connectedAt = new Date().toISOString();
    writeSession(s);
    renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
    await refreshWalletCapability();
    toast('EVM wallet connected');
  } catch {
    toast('Wallet connect failed', true);
  }
};

q('btn-save-session').onclick = () => {
  const s = readSession();
  s.wallet = q('wallet').value.trim();
  try { s.pubkey = JSON.parse(q('pubkey').value); } catch {}
  try { s.signature = JSON.parse(q('sig').value); } catch {}
  s.challenge = q('challenge').value.trim();
  writeSession(s);
  renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
  toast('Session saved locally');
};

q('btn-clear-session').onclick = () => {
  localStorage.removeItem(SESSION_KEY);
  renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
  toast('Session cleared');
};

q('btn-refresh-auth').onclick = async () => withPending('btn-refresh-auth', async () => {
  const wallet = q('wallet').value.trim();
  const current_challenge = q('challenge').value.trim();
  const res = await callJson('/v1/auth/refresh', 'POST', { wallet, current_challenge });
  setOutput('out-session', res);
  if (res.ok && res.body?.challenge) {
    q('challenge').value = res.body.challenge;
    const s = readSession();
    s.challenge = res.body.challenge;
    writeSession(s);
    renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
    toast('Auth challenge refreshed');
  } else {
    toast(apiErrorText(res, 'Auth refresh failed'), true);
  }
});

q('btn-logout').onclick = async () => withPending('btn-logout', async () => {
  const wallet = q('wallet').value.trim();
  const res = await callJson('/v1/auth/logout', 'POST', { wallet });
  setOutput('out-session', res);
  if (res.ok) {
    const s = readSession();
    s.authVerified = false;
    s.authVerifiedAt = null;
    s.challenge = '';
    writeSession(s);
    q('challenge').value = '';
    q('sig').value = '[]';
    renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
    toast('Logged out / auth invalidated');
  } else {
    toast(apiErrorText(res, 'Logout failed'), true);
  }
});

q('btn-health').onclick = async () => {
  setOutput('out-health', 'Loading…');
  setOutput('out-health', await callJson('/health'));
};

q('btn-status').onclick = async () => {
  setOutput('out-status', 'Loading…');
  setOutput('out-status', await callJson('/v1/status'));
};

q('btn-auth-metrics').onclick = async () => {
  setOutput('out-auth-metrics', 'Loading…');
  setOutput('out-auth-metrics', await callJson('/v1/auth/metrics'));
};

q('btn-list-convs').onclick = async () => {
  setOutput('out-list', 'Loading…');
  const res = await callJson('/v1/conversations');
  setOutput('out-list', res);
  if (res.ok) {
    const list = res.body?.items || res.body?.conversations || res.body || [];
    conversationItems = Array.isArray(list) ? list : [];
    renderConversationList();
    toast('Conversation list refreshed');
  }
};

q('btn-list-messages').onclick = async () => {
  setOutput('out-list', 'Loading…');
  const before = q('msg-before-seq').value.trim();
  const res = await fetchMessagesPage(before || null, false);
  setOutput('out-list', res);
};

q('btn-load-recent').onclick = async () => {
  setOutput('out-list', 'Loading…');
  const res = await fetchMessagesPage(null, false);
  setOutput('out-list', res);
};

q('btn-load-older').onclick = async () => {
  setOutput('out-list', 'Loading…');
  const before = q('msg-before-seq').value.trim();
  if (!before) {
    toast('No older-page cursor available yet', true);
    return;
  }
  const res = await fetchMessagesPage(Number(before), true);
  setOutput('out-list', res);
};

q('btn-render-timeline').onclick = async () => {
  await refreshLists();
};

q('btn-message-detail').onclick = async () => {
  const conv = encodeURIComponent(q('conv-id').value.trim());
  const seq = Number(q('detail-seq').value || '1');
  const res = await callJson(`/v1/messages/detail?conv_id=${conv}&seq=${seq}`);
  setOutput('out-message-detail', res);
  if (res.ok) selectMessage(seq);
  if (!res.ok) toast(apiErrorText(res, 'Message detail failed'), true);
};

q('btn-challenge').onclick = async () => {
  setOutput('out-challenge', 'Loading…');
  const wallet = q('wallet').value.trim();
  const res = await callJson('/v1/auth/challenge', 'POST', { wallet });
  setOutput('out-challenge', res);
  if (res.ok && res.body?.challenge) {
    q('challenge').value = res.body.challenge;
    const s = readSession();
    s.wallet = wallet;
    s.challenge = res.body.challenge;
    writeSession(s);
    renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
    toast('Challenge ready');
  }
};

q('btn-verify').onclick = async () => {
  setOutput('out-verify', 'Loading…');
  const payload = {
    wallet: q('wallet').value.trim(),
    challenge: q('challenge').value.trim(),
    sig_pubkey_ed25519: JSON.parse(q('pubkey').value),
    signature_ed25519: JSON.parse(q('sig').value),
  };
  const res = await callJson('/v1/auth/verify', 'POST', payload);
  setOutput('out-verify', res);
  if (res.ok) {
    const s = readSession();
    s.authVerified = true;
    s.authVerifiedAt = new Date().toISOString();
    writeSession(s);
    renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
    toast('Auth verified');
  } else {
    toast(apiErrorText(res, 'Auth verify failed'), true);
  }
};

q('btn-evm-sign-verify').onclick = async () => withPending('btn-evm-sign-verify', async () => {
  if (!window.ethereum) {
    toast('No injected wallet found', true);
    return;
  }
  const wallet = q('wallet').value.trim();
  if (!wallet || !wallet.startsWith('0x')) {
    toast('Connect an EVM wallet first', true);
    return;
  }

  const cid = await currentChainIdDec();
  if (Number.isFinite(cid)) q('evm-chain-id').value = String(cid);
  const allowed = allowedChainIds();
  if (Number.isFinite(cid) && allowed.length && !allowed.includes(cid)) {
    toast(`Unsupported chain ${cid}. Allowed: ${allowed.join(', ')}`, true);
    return;
  }

  let challenge = q('challenge').value.trim();
  if (!challenge) {
    const c = await callJson('/v1/auth/challenge', 'POST', { wallet });
    if (!c.ok) {
      setOutput('out-verify', c);
      toast(apiErrorText(c, 'Challenge request failed'), true);
      return;
    }
    challenge = c.body.challenge;
    q('challenge').value = challenge;
  }

  const sigHex = await window.ethereum.request({ method: 'personal_sign', params: [challenge, wallet] });

  const res = await callJson('/v1/auth/verify-wallet', 'POST', {
    wallet,
    challenge,
    signature_hex: sigHex,
  });
  setOutput('out-verify', res);
  if (res.ok) {
    const s = readSession();
    s.authVerified = true;
    s.authVerifiedAt = new Date().toISOString();
    s.walletType = 'evm';
    writeSession(s);
    renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
    toast('EVM auth verified');
  } else {
    toast(apiErrorText(res, 'EVM verify failed'), true);
  }
});

q('btn-pop').onclick = async () => {
  setOutput('out-pop', 'Loading…');
  const payload = {
    account: JSON.parse(q('pop-account').value),
    provider: q('pop-provider').value.trim(),
    proof_blob: JSON.parse(q('pop-proof').value),
    nullifier: JSON.parse(q('pop-nullifier').value),
    expires_at_slot: Number(q('pop-expiry').value),
    signature_ed25519: JSON.parse(q('pop-sig').value),
    current_slot: 10,
  };
  setOutput('out-pop', await callJson('/v1/pop/verify', 'POST', payload));
};

q('btn-onboarding-connect').onclick = () => {
  q('wallet').value = `demo-wallet-${q('quick-creator-seed')?.value || '1'}`;
  q('btn-connect').onclick();
  prefillParticipantFields([seededAccount(Number(q('quick-creator-seed')?.value || '1')), seededAccount(2)]);
  setConversationHint('Demo identity loaded. Next step: complete demo sign-in.', 'ok');
};

q('btn-onboarding-verify').onclick = async () => withPending('btn-onboarding-verify', async () => {
  if (!q('wallet').value.trim()) q('btn-onboarding-connect').onclick();
  await q('btn-challenge').onclick();
  await q('btn-dev-sign-challenge').onclick();
  await q('btn-verify').onclick();
});

q('btn-onboarding-create').onclick = async () => withPending('btn-onboarding-create', async () => {
  buildQuickConversationDraft();
  await q('btn-dev-sign-conv').onclick();
  await q('btn-conv-create').onclick();
});

q('btn-onboarding-bootstrap').onclick = async () => {
  await q('btn-demo-bootstrap').onclick();
};

q('btn-quick-fill-conv').onclick = () => {
  try {
    buildQuickConversationDraft();
  } catch (error) {
    setConversationHint(error.message || 'Unable to generate conversation draft', 'warn');
    toast(error.message || 'Unable to generate conversation draft', true);
  }
};

q('btn-quick-create-conv').onclick = async () => withPending('btn-quick-create-conv', async () => {
  try {
    buildQuickConversationDraft();
  } catch (error) {
    setConversationHint(error.message || 'Unable to generate conversation draft', 'warn');
    toast(error.message || 'Unable to generate conversation draft', true);
    return;
  }
  await q('btn-dev-sign-conv').onclick();
  await q('btn-conv-create').onclick();
});

q('btn-auto-fill-message').onclick = () => {
  try {
    const participants = JSON.parse(q('conv-participants').value);
    prefillParticipantFields(participants);
    toast('Message sender and member fields aligned with this chat');
  } catch {
    toast('Conversation participants are not valid JSON yet', true);
  }
};

q('btn-conv-create').onclick = async () => {
  setOutput('out-conv', 'Loading…');
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    conv_type: q('conv-type').value.trim(),
    creator: JSON.parse(q('conv-creator').value),
    initial_participants: JSON.parse(q('conv-participants').value),
    signature_ed25519: JSON.parse(q('conv-sig').value),
    current_slot: 20,
  };
  const res = await callJson('/v1/conversations', 'POST', payload);
  setOutput('out-conv', res);
  if (res.ok) {
    const key = JSON.stringify(payload.conv_id);
    conversationDraftNames[key] = currentConversationDraftName();
    activeConversationKey = key;
    setConversationHint(`Conversation created: ${conversationDraftNames[key]}`, 'ok');
    toast('Conversation created');
    await refreshLists();
  } else {
    toast(apiErrorText(res, 'Conversation create failed'), true);
  }
};

q('btn-add-member').onclick = async () => withPending('btn-add-member', async () => {
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
    signature_ed25519: JSON.parse(q('member-sig').value),
    current_slot: 22,
  };
  const res = await callJson('/v1/conversations/add-member', 'POST', payload);
  setOutput('out-members', res);
  if (res.ok) {
    toast('Member added');
    await refreshLists();
  } else {
    toast(apiErrorText(res, 'Add member failed'), true);
  }
});

q('btn-remove-member').onclick = async () => withPending('btn-remove-member', async () => {
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
    signature_ed25519: JSON.parse(q('member-sig').value),
    current_slot: 23,
  };
  const res = await callJson('/v1/conversations/remove-member', 'POST', payload);
  setOutput('out-members', res);
  if (res.ok) {
    toast('Member removed');
    await refreshLists();
  } else {
    toast(apiErrorText(res, 'Remove member failed'), true);
  }
});

q('btn-list-members').onclick = async () => {
  const conv = encodeURIComponent(q('conv-id').value.trim());
  const res = await callJson(`/v1/conversations/members?conv_id=${conv}`);
  setOutput('out-members-list', res);
  if (res.ok) markSyncState('Members synced', 'Conversation membership snapshot updated');
  if (!res.ok) toast(apiErrorText(res, 'List members failed'), true);
};

q('btn-promote-member').onclick = async () => withPending('btn-promote-member', async () => {
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
    signature_ed25519: JSON.parse(q('member-sig').value),
  };
  const res = await callJson('/v1/conversations/promote-member', 'POST', payload);
  setOutput('out-members', res);
  if (res.ok) {
    toast('Member promoted to admin');
    await q('btn-list-members').onclick();
  } else {
    toast(apiErrorText(res, 'Promote member failed'), true);
  }
});

q('btn-demote-member').onclick = async () => withPending('btn-demote-member', async () => {
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
    signature_ed25519: JSON.parse(q('member-sig').value),
  };
  const res = await callJson('/v1/conversations/demote-member', 'POST', payload);
  setOutput('out-members', res);
  if (res.ok) {
    toast('Member demoted');
    await q('btn-list-members').onclick();
  } else {
    toast(apiErrorText(res, 'Demote member failed'), true);
  }
});

q('btn-msg-send').onclick = async () => withPending('btn-msg-send', async () => {
  setOutput('out-list', 'Loading…');
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    sender: JSON.parse(q('msg-sender').value),
    sender_nonce: Number(q('msg-nonce').value),
    cipher_root: JSON.parse(q('msg-cipher-root').value),
    cipher_len: Number(q('msg-cipher-len').value),
    chunk_count: Number(q('msg-chunk-count').value),
    envelope_root: JSON.parse(q('msg-envelope-root').value),
    recipients_hint_count: Number(q('msg-recipients-hint').value),
    fee_limit: Number(q('msg-fee-limit').value),
    bond_limit: Number(q('msg-bond-limit').value),
    signature_ed25519: JSON.parse(q('msg-sig').value),
    current_slot: 21,
  };
  const res = await callJson('/v1/messages/send', 'POST', payload);
  setOutput('out-list', res);
  if (res.ok) {
    toast('Message sent');
    await fetchMessagesPage(null, false);
  } else {
    toast(apiErrorText(res, 'Send failed'), true);
  }
});

q('btn-read-ack').onclick = async () => {
  setOutput('out-read', 'Loading…');
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    reader: JSON.parse(q('read-reader').value),
    seq: Number(q('read-seq').value),
    signature_ed25519: JSON.parse(q('read-sig').value),
    current_slot: 22,
  };
  setOutput('out-read', await callJson('/v1/messages/read', 'POST', payload));
};

q('btn-dev-register-device').onclick = async () => {
  const account = JSON.parse(q('conv-creator').value);
  const res = await callJson('/v1/dev/register-device', 'POST', {
    seed: devSeed(),
    account,
    current_slot: 1,
  });
  setOutput('out-session', res);
  if (res.ok && res.body?.pubkey) {
    q('pubkey').value = JSON.stringify(res.body.pubkey);
  }
};

q('btn-dev-sign-challenge').onclick = async () => {
  const res = await callJson('/v1/dev/sign/challenge', 'POST', {
    seed: devSeed(),
    challenge: q('challenge').value.trim(),
  });
  setOutput('out-verify', res);
  if (res.ok) {
    q('pubkey').value = JSON.stringify(res.body.sig_pubkey_ed25519);
    q('sig').value = JSON.stringify(res.body.signature_ed25519);
  }
};

q('btn-dev-sign-pop').onclick = async () => {
  const res = await callJson('/v1/dev/sign/pop', 'POST', {
    seed: devSeed(),
    account: JSON.parse(q('pop-account').value),
    provider: q('pop-provider').value.trim(),
    proof_blob: JSON.parse(q('pop-proof').value),
    nullifier: JSON.parse(q('pop-nullifier').value),
    expires_at_slot: Number(q('pop-expiry').value),
  });
  setOutput('out-pop', res);
  if (res.ok) q('pop-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-blob').onclick = async () => {
  const res = await callJson('/v1/dev/sign/blob', 'POST', {
    seed: devSeed(),
    sender: JSON.parse(q('msg-sender').value),
    text: q('blob-text').value,
  });
  setOutput('out-blob', res);
  if (res.ok) q('blob-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-blob-register').onclick = async () => withPending('btn-blob-register', async () => {
  const payload = {
    sender: JSON.parse(q('msg-sender').value),
    text: q('blob-text').value,
    signature_ed25519: JSON.parse(q('blob-sig').value),
    current_slot: 19,
  };
  const res = await callJson('/v1/blobs/register', 'POST', payload);
  setOutput('out-blob', res);
  if (res.ok && res.body) {
    q('msg-cipher-root').value = JSON.stringify(res.body.root);
    q('msg-cipher-len').value = String(res.body.total_len);
    q('msg-chunk-count').value = String(res.body.chunk_count);
    toast('Blob registered');
  } else {
    toast(apiErrorText(res, 'Blob register failed'), true);
  }
});

q('btn-dev-sign-conv').onclick = async () => {
  const res = await callJson('/v1/dev/sign/conversation', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    conv_type: q('conv-type').value.trim(),
    creator: JSON.parse(q('conv-creator').value),
    initial_participants: JSON.parse(q('conv-participants').value),
  });
  setOutput('out-conv', res);
  if (res.ok) q('conv-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-send').onclick = async () => {
  const res = await callJson('/v1/dev/sign/send', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    sender: JSON.parse(q('msg-sender').value),
    sender_nonce: Number(q('msg-nonce').value),
    cipher_root: JSON.parse(q('msg-cipher-root').value),
    cipher_len: Number(q('msg-cipher-len').value),
    chunk_count: Number(q('msg-chunk-count').value),
    envelope_root: JSON.parse(q('msg-envelope-root').value),
    recipients_hint_count: Number(q('msg-recipients-hint').value),
    fee_limit: Number(q('msg-fee-limit').value),
    bond_limit: Number(q('msg-bond-limit').value),
  });
  setOutput('out-list', res);
  if (res.ok) q('msg-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-add-member').onclick = async () => {
  const res = await callJson('/v1/dev/sign/add-member', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
  });
  setOutput('out-members', res);
  if (res.ok) q('member-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-remove-member').onclick = async () => {
  const res = await callJson('/v1/dev/sign/remove-member', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
  });
  setOutput('out-members', res);
  if (res.ok) q('member-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-promote-member').onclick = async () => {
  const res = await callJson('/v1/dev/sign/promote-member', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
  });
  setOutput('out-members', res);
  if (res.ok) q('member-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-demote-member').onclick = async () => {
  const res = await callJson('/v1/dev/sign/demote-member', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    actor: JSON.parse(q('member-actor').value),
    member: JSON.parse(q('member-target').value),
  });
  setOutput('out-members', res);
  if (res.ok) q('member-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-read').onclick = async () => {
  const res = await callJson('/v1/dev/sign/read', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    reader: JSON.parse(q('read-reader').value),
    seq: Number(q('read-seq').value),
  });
  setOutput('out-read', res);
  if (res.ok) q('read-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-demo-bootstrap').onclick = async () => {
  setOutput('out-session', 'Loading…');
  const res = await callJson('/v1/dev/bootstrap-demo', 'POST', { seed_a: 1, seed_b: 2 });
  setOutput('out-session', res);
  if (res.ok) {
    q('conv-id').value = JSON.stringify(res.body.conv_id);
    q('read-seq').value = String(res.body.msg_seq);
    activeConversationKey = JSON.stringify(res.body.conv_id);
    await refreshLists();
    toast('Demo bootstrap ready');
  } else {
    toast('Demo bootstrap failed', true);
  }
};

q('btn-blob-preset').onclick = () => {
  q('blob-text').value = `JamTalk quick message @ ${new Date().toLocaleTimeString()}`;
  toast('Preset text ready');
};

q('btn-send-refresh').onclick = async () => withPending('btn-send-refresh', async () => {
  await q('btn-dev-sign-blob').onclick();
  await q('btn-blob-register').onclick();
  await q('btn-dev-sign-send').onclick();
  await q('btn-msg-send').onclick();
  await refreshLists();
  toast('Quick send + refresh done');
});

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  q('btn-auto-refresh').textContent = 'Start auto-refresh';
  markSyncState('Manual refresh', 'Tap refresh or enable auto-refresh');
}

function startAutoRefresh() {
  stopAutoRefresh();
  const ms = Math.max(1500, Number(q('refresh-interval').value || '5000'));
  refreshTimer = setInterval(async () => {
    if (document.hidden) return;
    await refreshLists();
    setOutput('out-status', await callJson('/v1/status'));
  }, ms);
  q('btn-auto-refresh').textContent = `Auto-refresh ON (${ms}ms)`;
  markSyncState('Auto-refresh live', `Refreshing every ${ms}ms while this tab stays visible`);
}

q('btn-auto-refresh').onclick = async () => {
  if (autoRefreshWanted) {
    autoRefreshWanted = false;
    stopAutoRefresh();
  } else {
    autoRefreshWanted = true;
    await refreshLists();
    startAutoRefresh();
  }
};

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = null;
    if (autoRefreshWanted) q('btn-auto-refresh').textContent = 'Auto-refresh paused (tab hidden)';
  } else if (autoRefreshWanted) {
    startAutoRefresh();
  }
});

function installMobileKeyboardSafety() {
  const vv = window.visualViewport;
  if (!vv) return;

  const update = () => {
    const keyboardLikelyOpen = (window.innerHeight - vv.height) > 140;
    document.body.classList.toggle('keyboard-open', keyboardLikelyOpen);
  };

  vv.addEventListener('resize', update);
  vv.addEventListener('scroll', update);
  update();

  document.addEventListener('focusin', (ev) => {
    const t = ev.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA')) {
      setTimeout(() => t.scrollIntoView({ block: 'center', behavior: 'smooth' }), 120);
    }
  });
}

if (window.ethereum?.on) {
  window.ethereum.on('accountsChanged', (accounts) => {
    const wallet = accounts?.[0] || '';
    q('wallet').value = wallet;
    const s = readSession();
    s.wallet = wallet;
    if (wallet) s.walletType = 'evm';
    writeSession(s);
    renderSession();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
    refreshWalletCapability();
  });

  window.ethereum.on('chainChanged', () => {
    refreshWalletCapability();
  });
}

q('evm-allowed-chains')?.addEventListener('change', () => {
  refreshWalletCapability();
});

installMobileKeyboardSafety();
syncQuickConversationInputsFromAdvanced();
refreshWalletCapability();
renderConversationList();
renderTimeline();
renderSession();
renderOnboardingChecklist();
updateOverviewCards();
markSyncState('Ready', 'Open a chat or run the demo bootstrap to populate the timeline');
