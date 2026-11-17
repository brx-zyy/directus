import { randomUUID } from 'node:crypto';
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
	const user = await directus.knex!('directus_users').select('id').first();

	// The SQLite sandbox does not seed the system collection metadata rows.
	await directus.knex!('directus_collections').insert({ collection: 'directus_users' });

	const shareId = randomUUID();
	await directus.knex!('directus_shares').insert({
		id: shareId,
		name: 'one-use regression',
		collection: 'directus_users',
		item: user.id,
		max_uses: 1,
		times_used: 0,
	});

	const authenticate = () =>
		fetch(`${apiUrl}/shares/auth`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ share: shareId, mode: 'json' }),
		});

	const first = await authenticate();
	expect(first.status).toBe(200);
	expect((await first.json()).data.access_token).toBeDefined();

	const second = await authenticate();
	expect(second.status).toBe(401);

	const record = await directus.knex!('directus_shares').select('times_used', 'max_uses').where({ id: shareId }).first();
	expect(record).toMatchObject({ times_used: 1, max_uses: 1 });
});
