import { createCollection, createDirectus, createItem, rest, staticToken } from '@directus/sdk';
import { database } from '@utils/constants.js';
import { getUID } from '@utils/getUID.js';
import { sandboxPort } from '@utils/sandbox-port.js';
import { useSandbox } from '@utils/sandbox.js';
import { afterAll, expect, test } from 'vitest';

const uid = getUID();
const collection = `share_limit_${uid}`;
const directus = await useSandbox(database, {
	port: sandboxPort(),
	inspect: false,
	prefix: `share-limit-${uid}`,
	env: {
		DB_FILENAME: `directus_test_${uid}.db`,
	},
	docker: { suffix: uid },
	cache: false,
	knex: true,
});

const apiUrl = `http://127.0.0.1:${directus.apis[0]!.port}`;
const api = createDirectus<Record<string, any>>(apiUrl).with(rest()).with(staticToken('admin'));

afterAll(async () => {
	await directus.stop();
});

test('a share configured for one use rejects the second authentication', async () => {
	await api.request(
		createCollection({
			collection,
			fields: [
				{
					field: 'id',
					type: 'uuid',
					meta: { hidden: true, readonly: true, special: ['uuid'] },
					schema: { is_primary_key: true },
				},
				{ field: 'title', type: 'string' },
			],
			schema: {},
		} as any),
	);

	const item = await api.request(createItem(collection, { title: 'share limit test' }));
	const createShare = await fetch(`${apiUrl}/shares`, {
		method: 'POST',
		headers: { Authorization: 'Bearer admin', 'Content-Type': 'application/json' },
		body: JSON.stringify({ collection, item: item.id, max_uses: 1 }),
	});
	expect(createShare.status).toBe(200);
	const { data: share } = await createShare.json();

	const authenticate = () =>
		fetch(`${apiUrl}/shares/auth`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ share: share.id, mode: 'json' }),
		});

	const first = await authenticate();
	expect(first.status).toBe(200);
	expect((await first.json()).data.access_token).toBeDefined();

	const second = await authenticate();
	expect(second.status).toBe(401);

	const record = await directus.knex!('directus_shares').select('times_used', 'max_uses').where({ id: share.id }).first();
	expect(record).toMatchObject({ times_used: 1, max_uses: 1 });
});
