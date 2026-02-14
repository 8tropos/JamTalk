const q = (id) => document.getElementById(id);
const SESSION_KEY = 'jamtalk.session.v1';

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

function renderSession() {
  const s = readSession();
  q('out-session').textContent = JSON.stringify(s, null, 2);
  if (s.wallet) q('wallet').value = s.wallet;
  if (s.challenge) q('challenge').value = s.challenge;
  if (s.pubkey) q('pubkey').value = JSON.stringify(s.pubkey);
  if (s.signature) q('sig').value = JSON.stringify(s.signature);
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

function devSeed() {
  return Number(q('dev-seed').value || '1');
}

function setWalletCapability(kind, text) {
  const box = q('wallet-capability');
  if (!box) return;
  box.classList.remove('ok', 'warn');
  if (kind) box.classList.add(kind);
  box.textContent = text;
}

function refreshWalletCapability() {
  const hasEvm = !!window.ethereum;
  const evmBtns = ['btn-connect-evm', 'btn-evm-sign-verify'];
  evmBtns.forEach((id) => {
    const el = q(id);
    if (el) el.disabled = !hasEvm;
  });

  if (hasEvm) {
    setWalletCapability('ok', 'Injected EVM wallet detected. You can connect and use personal_sign verification.');
  } else {
    setWalletCapability('warn', 'No injected EVM wallet detected. Install MetaMask/Rabby in this browser, or use manual/dev signing flow below.');
  }
}

q('btn-connect').onclick = () => {
  const wallet = q('wallet').value.trim() || `wallet-${Date.now()}`;
  const s = readSession();
  s.wallet = wallet;
  s.connectedAt = new Date().toISOString();
  writeSession(s);
  renderSession();
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
    q('wallet').value = wallet;
    const s = readSession();
    s.wallet = wallet;
    s.walletType = 'evm';
    s.connectedAt = new Date().toISOString();
    writeSession(s);
    renderSession();
    toast('EVM wallet connected');
  } catch (e) {
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
};

q('btn-clear-session').onclick = () => {
  localStorage.removeItem(SESSION_KEY);
  renderSession();
};

q('btn-health').onclick = async () => {
  q('out-health').textContent = '...';
  q('out-health').textContent = JSON.stringify(await callJson('/health'), null, 2);
};

q('btn-status').onclick = async () => {
  q('out-status').textContent = '...';
  q('out-status').textContent = JSON.stringify(await callJson('/v1/status'), null, 2);
};

q('btn-list-convs').onclick = async () => {
  q('out-list').textContent = '...';
  q('out-list').textContent = JSON.stringify(await callJson('/v1/conversations'), null, 2);
};

function shortAccount(a){
  if(!Array.isArray(a)) return 'unknown';
  return `${a.slice(0,4).join(',')}...`;
}

function renderTimeline(msgRes){
  const box = q('timeline');
  if (!box) return;
  const items = msgRes?.body?.items || [];
  if (!items.length) {
    box.innerHTML = '<div class="msg-meta">No messages yet.</div>';
    return;
  }
  box.innerHTML = items.map(m => `
    <div class="msg-card">
      <div><strong>seq #${m.seq}</strong></div>
      <div class="msg-meta">sender: ${shortAccount(m.sender)}</div>
      <div class="msg-meta">cipher_len: ${m.cipher_len} | flags: ${m.flags}</div>
    </div>
  `).join('');
  if (q('timeline-autoscroll')?.checked) {
    box.scrollTop = box.scrollHeight;
  }
}

async function refreshLists() {
  const convRes = await callJson('/v1/conversations');
  const conv = encodeURIComponent(q('conv-id').value.trim());
  const msgRes = await callJson(`/v1/messages?conv_id=${conv}`);
  q('out-list').textContent = JSON.stringify({ conversations: convRes, messages: msgRes }, null, 2);
  renderTimeline(msgRes);
}

q('btn-list-messages').onclick = async () => {
  q('out-list').textContent = '...';
  const conv = encodeURIComponent(q('conv-id').value.trim());
  const res = await callJson(`/v1/messages?conv_id=${conv}`);
  q('out-list').textContent = JSON.stringify(res, null, 2);
  renderTimeline(res);
};

q('btn-render-timeline').onclick = async () => {
  await refreshLists();
};

q('btn-challenge').onclick = async () => {
  q('out-challenge').textContent = '...';
  const wallet = q('wallet').value.trim();
  const res = await callJson('/v1/auth/challenge', 'POST', { wallet });
  q('out-challenge').textContent = JSON.stringify(res, null, 2);
  if (res.ok && res.body?.challenge) {
    q('challenge').value = res.body.challenge;
    const s = readSession();
    s.wallet = wallet;
    s.challenge = res.body.challenge;
    writeSession(s);
    renderSession();
  }
};

q('btn-verify').onclick = async () => {
  q('out-verify').textContent = '...';
  const payload = {
    wallet: q('wallet').value.trim(),
    challenge: q('challenge').value.trim(),
    sig_pubkey_ed25519: JSON.parse(q('pubkey').value),
    signature_ed25519: JSON.parse(q('sig').value),
  };
  const res = await callJson('/v1/auth/verify', 'POST', payload);
  q('out-verify').textContent = JSON.stringify(res, null, 2);
  if (res.ok) {
    const s = readSession();
    s.authVerified = true;
    s.authVerifiedAt = new Date().toISOString();
    writeSession(s);
    renderSession();
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
  let challenge = q('challenge').value.trim();
  if (!challenge) {
    const c = await callJson('/v1/auth/challenge', 'POST', { wallet });
    if (!c.ok) {
      q('out-verify').textContent = JSON.stringify(c, null, 2);
      toast(apiErrorText(c, 'Challenge request failed'), true);
      return;
    }
    challenge = c.body.challenge;
    q('challenge').value = challenge;
  }

  const sigHex = await window.ethereum.request({
    method: 'personal_sign',
    params: [challenge, wallet],
  });

  const res = await callJson('/v1/auth/verify-wallet', 'POST', {
    wallet,
    challenge,
    signature_hex: sigHex,
  });
  q('out-verify').textContent = JSON.stringify(res, null, 2);
  if (res.ok) {
    const s = readSession();
    s.authVerified = true;
    s.authVerifiedAt = new Date().toISOString();
    s.walletType = 'evm';
    writeSession(s);
    renderSession();
    toast('EVM auth verified');
  } else {
    toast(apiErrorText(res, 'EVM verify failed'), true);
  }
});

q('btn-pop').onclick = async () => {
  q('out-pop').textContent = '...';
  const payload = {
    account: JSON.parse(q('pop-account').value),
    provider: q('pop-provider').value.trim(),
    proof_blob: JSON.parse(q('pop-proof').value),
    nullifier: JSON.parse(q('pop-nullifier').value),
    expires_at_slot: Number(q('pop-expiry').value),
    signature_ed25519: JSON.parse(q('pop-sig').value),
    current_slot: 10,
  };
  q('out-pop').textContent = JSON.stringify(await callJson('/v1/pop/verify', 'POST', payload), null, 2);
};

q('btn-conv-create').onclick = async () => {
  q('out-conv').textContent = '...';
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    conv_type: q('conv-type').value.trim(),
    creator: JSON.parse(q('conv-creator').value),
    initial_participants: JSON.parse(q('conv-participants').value),
    signature_ed25519: JSON.parse(q('conv-sig').value),
    current_slot: 20,
  };
  q('out-conv').textContent = JSON.stringify(await callJson('/v1/conversations', 'POST', payload), null, 2);
};

q('btn-msg-send').onclick = async () => withPending('btn-msg-send', async () => {
  q('out-send').textContent = '...';
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
  q('out-send').textContent = JSON.stringify(res, null, 2);
  if (res.ok) {
    toast('Message sent');
  } else {
    toast(apiErrorText(res, 'Send failed'), true);
  }
});

q('btn-read-ack').onclick = async () => {
  q('out-read').textContent = '...';
  const payload = {
    conv_id: JSON.parse(q('conv-id').value),
    reader: JSON.parse(q('read-reader').value),
    seq: Number(q('read-seq').value),
    signature_ed25519: JSON.parse(q('read-sig').value),
    current_slot: 22,
  };
  q('out-read').textContent = JSON.stringify(await callJson('/v1/messages/read', 'POST', payload), null, 2);
};

q('btn-dev-register-device').onclick = async () => {
  const account = JSON.parse(q('conv-creator').value);
  const res = await callJson('/v1/dev/register-device', 'POST', {
    seed: devSeed(),
    account,
    current_slot: 1,
  });
  q('out-session').textContent = JSON.stringify(res, null, 2);
  if (res.ok && res.body?.pubkey) {
    q('pubkey').value = JSON.stringify(res.body.pubkey);
  }
};

q('btn-dev-sign-challenge').onclick = async () => {
  const res = await callJson('/v1/dev/sign/challenge', 'POST', {
    seed: devSeed(),
    challenge: q('challenge').value.trim(),
  });
  q('out-verify').textContent = JSON.stringify(res, null, 2);
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
  q('out-pop').textContent = JSON.stringify(res, null, 2);
  if (res.ok) q('pop-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-blob').onclick = async () => {
  const res = await callJson('/v1/dev/sign/blob', 'POST', {
    seed: devSeed(),
    sender: JSON.parse(q('msg-sender').value),
    text: q('blob-text').value,
  });
  q('out-blob').textContent = JSON.stringify(res, null, 2);
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
  q('out-blob').textContent = JSON.stringify(res, null, 2);
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
  q('out-conv').textContent = JSON.stringify(res, null, 2);
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
  q('out-send').textContent = JSON.stringify(res, null, 2);
  if (res.ok) q('msg-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-dev-sign-read').onclick = async () => {
  const res = await callJson('/v1/dev/sign/read', 'POST', {
    seed: devSeed(),
    conv_id: JSON.parse(q('conv-id').value),
    reader: JSON.parse(q('read-reader').value),
    seq: Number(q('read-seq').value),
  });
  q('out-read').textContent = JSON.stringify(res, null, 2);
  if (res.ok) q('read-sig').value = JSON.stringify(res.body.signature_ed25519);
};

q('btn-demo-bootstrap').onclick = async () => {
  q('out-session').textContent = '...';
  const res = await callJson('/v1/dev/bootstrap-demo', 'POST', {
    seed_a: 1,
    seed_b: 2,
  });
  q('out-session').textContent = JSON.stringify(res, null, 2);
  if (res.ok) {
    q('conv-id').value = JSON.stringify(res.body.conv_id);
    q('read-seq').value = String(res.body.msg_seq);
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

let refreshTimer = null;
let autoRefreshWanted = false;

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  q('btn-auto-refresh').textContent = 'Start auto-refresh';
}

function startAutoRefresh() {
  stopAutoRefresh();
  const ms = Math.max(1500, Number(q('refresh-interval').value || '5000'));
  refreshTimer = setInterval(async () => {
    if (document.hidden) return;
    await refreshLists();
    q('out-status').textContent = JSON.stringify(await callJson('/v1/status'), null, 2);
  }, ms);
  q('btn-auto-refresh').textContent = `Auto-refresh ON (${ms}ms)`;
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

if (window.ethereum?.on) {
  window.ethereum.on('accountsChanged', (accounts) => {
    const wallet = accounts?.[0] || '';
    q('wallet').value = wallet;
    const s = readSession();
    s.wallet = wallet;
    if (wallet) s.walletType = 'evm';
    writeSession(s);
    renderSession();
    refreshWalletCapability();
  });

  window.ethereum.on('chainChanged', () => {
    refreshWalletCapability();
  });
}

refreshWalletCapability();
renderSession();
