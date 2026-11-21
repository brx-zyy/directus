import { randomUUID } from 'node:crypto';
import { createDirectus, createItem, readItems, rest, staticToken, updateItem } from '@directus/sdk';
import { database } from '@utils/constants.js';
import { generateScopedUser } from '@utils/user-scoped.js';
import { sandboxPort } from '@utils/sandbox-port.js';
import { useSandbox } from '@utils/sandbox.js';
import { useSnapshot } from '@utils/use-snapshot.js';
import { afterAll, beforeAll, expect, test } from 'vitest';
import { snapshot } from '../query/sort/snapshot.js';

let directus: Awaited<ReturnType<typeof import('@directus/sandbox').sandbox>>;
let apiUrl: string;
let api: any;
let collections: any;
let appliedSnapshot: any;

beforeAll(async () => {
	directus = await useSandbox(database, {
		port: sandboxPort(0),
		inspect: false,
		prefix: `sort-authz-${randomUUID()}`,
		env: { DB_FILENAME: `directus_test_sort_authz_${randomUUID()}.db` },
		docker: { suffix: randomUUID() },
		cache: false,
		knex: true,
	});

	apiUrl = `http://127.0.0.1:${directus.apis[0].port}`;
	api = createDirectus<any>(apiUrl).with(rest()).with(staticToken('admin'));
	const applied = await useSnapshot<any>(api, snapshot);
	collections = applied.collections;
	appliedSnapshot = applied.snapshot;
}, 120_000);

afterAll(async () => {
	await directus?.stop();
});

test('utils sort bypasses row-level update filters', async () => {
	const marker = randomUUID();
	const attackerTitle = `attacker-${marker}`;
	const victimTitle = `victim-${marker}`;

	const attacker = await api.request(createItem(collections.articles, { title: attackerTitle, sort: 20 }));
	const victim = await api.request(createItem(collections.articles, { title: victimTitle, sort: 10 }));

	const { token } = await generateScopedUser(api, appliedSnapshot, ['read', 'update'], (permission) => ({
		...permission,
		...(permission.collection === 'articles'
			? { permissions: { title: { _eq: attackerTitle } } }
			: {}),
	}));

	const userApi = createDirectus<any>(apiUrl).with(rest()).with(staticToken(token));

	// Control: the same user cannot read or update the victim row through the normal Items API.
	await expect(userApi.request(readItems(collections.articles, { filter: { id: { _eq: victim.id } } }))).rejects.toMatchObject({
		errors: [expect.objectContaining({ extensions: expect.objectContaining({ code: 'FORBIDDEN' }) })],
	});

	await expect(userApi.request(updateItem(collections.articles, victim.id, { sort: 50 }))).rejects.toMatchObject({
		errors: [expect.objectContaining({ extensions: expect.objectContaining({ code: 'FORBIDDEN' }) })],
	});

	const before = await api.request(
		readItems(collections.articles, { filter: { id: { _eq: victim.id } }, fields: ['id', 'sort'] }),
	);
	expect(before[0]?.sort).toBe(10);

	// The sort endpoint checks collection-level update access and the sort field, but not row filters.
	const response = await fetch(`${apiUrl}/utils/sort/${collections.articles}`, {
		method: 'POST',
		headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
		body: JSON.stringify({ item: victim.id, to: attacker.id }),
	});
	expect(response.status).toBe(200);

	const after = await api.request(
		readItems(collections.articles, { filter: { id: { _eq: victim.id } }, fields: ['id', 'sort'] }),
	);
	expect(after[0]?.sort).toBe(20);
});
