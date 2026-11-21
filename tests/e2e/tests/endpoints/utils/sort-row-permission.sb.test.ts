import { createDirectus, createItem, createPolicy, createUser, rest, staticToken, updatePolicy } from '@directus/sdk';
import { SchemaBuilder } from '@directus/schema-builder';
import { database } from '@utils/constants.js';
import { getUID } from '@utils/getUID.js';
import { sandboxPort } from '@utils/sandbox-port.js';
import { useSandbox } from '@utils/sandbox.js';
import { useSnapshot } from '@utils/use-snapshot.js';
import { randomUUID } from 'node:crypto';
import { afterAll, expect, test } from 'vitest';
import { LICENSE_KEYS } from '../../license/__fixtures__/licenses.js';

const schema = new SchemaBuilder()
  .collection('articles', (c) => {
    c.field('id').id();
    c.field('title').string();
    c.field('sort').integer();
  });
const snapshot = schema.snapshot();

const directus = await useSandbox(database, {
  port: sandboxPort(),
  inspect: false,
  prefix: 'sort-row-permission',
  env: { DB_FILENAME: `directus_test_sort_row_${getUID()}.db`, LICENSE_KEY: LICENSE_KEYS.UNLIMITED },
  extras: { license: true },
  docker: { suffix: getUID() },
  knex: true,
});
const apiUrl = `http://127.0.0.1:${directus.apis[0]!.port}`;
const admin = createDirectus<unknown>(apiUrl).with(rest()).with(staticToken('admin'));
const { collections } = await useSnapshot<{ articles: unknown }>(admin, snapshot);

afterAll(async () => { await directus.stop(); });

test('sort cannot reorder rows outside the caller row-level update filter', async () => {
  // Configure the collection's sortable field, then seed one restricted and one permitted row.
  await directus.knex!('directus_collections').where({ collection: collections.articles }).update({ sort_field: 'sort' });
  const victim = await admin.request<{ id: number }>(createItem(collections.articles, { title: 'victim-row', sort: 1 }));
  const own = await admin.request<{ id: number }>(createItem(collections.articles, { title: 'own-row', sort: 2 }));

  const token = randomUUID();
  const user = await admin.request<{ id: string }>(createUser({
    first_name: 'Sort', last_name: 'Tester', email: `${token}@example.com`, password: 'password', token,
  }));
  const policy = await admin.request<{ id: string }>(createPolicy({
    name: `sort-row-${randomUUID()}`, admin_access: false, app_access: false,
    users: [{ user: user.id }], permissions: [],
  }));
  await admin.request(updatePolicy(policy.id, {
    permissions: [{
      collection: collections.articles, action: 'update', fields: ['sort'],
      permissions: { title: { _eq: 'own-row' } },
    }],
  }));

  // Ordinary item update is denied for the victim row.
  const ordinary = await fetch(`${apiUrl}/items/${collections.articles}/${victim.id}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ sort: 99 }),
  });
  expect(ordinary.status).toBe(403);

  // Move the permitted row to the victim's position. The sort implementation's
  // range updates may also rewrite the victim row despite its row filter.
  const sorted = await fetch(`${apiUrl}/utils/sort/${collections.articles}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ item: own.id, to: victim.id }),
  });
  expect(sorted.status).toBe(200);

  const victimAfter = await directus.knex!(collections.articles).select('sort').where({ id: victim.id }).first();
  expect(victimAfter.sort).toBe(2);
});
