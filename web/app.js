const q = (id) => document.getElementById(id);

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
  q('out-verify').textContent = JSON.stringify(await callJson('/v1/auth/verify', 'POST', payload), null, 2);
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
