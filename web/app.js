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

function devSeed() {
  return Number(q('dev-seed').value || '1');
}

q('btn-connect').onclick = () => {
  const wallet = q('wallet').value.trim() || `wallet-${Date.now()}`;
  const s = readSession();
  s.wallet = wallet;
  s.connectedAt = new Date().toISOString();
  writeSession(s);
  renderSession();
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
  }
};

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

q('btn-msg-send').onclick = async () => {
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
  q('out-send').textContent = JSON.stringify(await callJson('/v1/messages/send', 'POST', payload), null, 2);
};

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
  }
};

renderSession();
