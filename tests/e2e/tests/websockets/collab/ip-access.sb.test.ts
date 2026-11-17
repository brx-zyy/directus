import { randomUUID } from 'node:crypto';
import { createDirectus, createItem, createUser, rest, staticToken, updateSettings } from '@directus/sdk';
import { LICENSE_KEYS } from '../../license/__fixtures__/licenses.js';
import { openCollab } from '@utils/collab.js';
import { database } from '@utils/constants.js';
import { getUID } from '@utils/getUID.js';
import { sandboxPort } from '@utils/sandbox-port.js';
import { useSandbox } from '@utils/sandbox.js';
import { useSnapshot } from '@utils/use-snapshot.js';
import { afterAll, expect, test } from 'vitest';
import type { Schema } from './schema.d.ts';
import { snapshot } from './snapshot.js';

const uid = getUID();
const directus = await useSandbox(database, {
	port: sandboxPort(),
	inspect: false,
	prefix: `collab-ip-${uid}`,
	env: {
		DB_FILENAME: `directus_test_${uid}.db`,
		IP_CUSTOM_HEADER: 'sec-websocket-protocol',
		LICENSE_KEY: LICENSE_KEYS.UNLIMITED,
	},
	docker: { suffix: uid },
	cache: false,
	knex: true,
	extras: { license: true },
});

const apiUrl = `http://127.0.0.1:${directus.apis[0]!.port}`;
const api = createDirectus<Schema>(apiUrl).with(rest()).with(staticToken('admin'));
await api.request(updateSettings({ collaborative_editing_enabled: true, custom_permission_rules_enabled: true } as any));
const { collections } = await useSnapshot<Schema>(api, snapshot);

afterAll(async () => {
	await directus.stop();
});

test('collaborative update permission is not reused across client IP addresses', async () => {
	const item = await api.request(createItem(collections.items, { title: 'Original Title' } as any));
	const token = randomUUID();

	await api.request(
		createUser({
			first_name: 'IP Restricted',
			last_name: 'Collab',
			email: `${token}@collab.example.com`,
			password: 'secret',
			token,
			policies: [
				{
					policy: {
						name: `Collab read ${token}`,
						admin_access: false,
						app_access: true,
						permissions: [
							{ collection: collections.items, action: 'read', fields: ['*'], permissions: {}, validation: {}, presets: {} },
						],
					},
				},
				{
					policy: {
						name: `Collab update ${token}`,
						admin_access: false,
						app_access: true,
						ip_access: ['203.0.113.10/32'],
						permissions: [
							{ collection: collections.items, action: 'update', fields: ['title'], permissions: {}, validation: {}, presets: {} },
						],
					},
				},
			],
		} as any),
	);

	const allowed = await openCollab(directus.apis[0]!.port, token, '203.0.113.10');
	const denied = await openCollab(directus.apis[0]!.port, token, '198.51.100.20');

	try {
		const allowedInit = await allowed.join(collections.items, item.id!);
		expect(allowedInit.action).toBe('init');

		const deniedInit = await denied.join(collections.items, item.id!);
		expect(deniedInit.action).toBe('init');

		// Populate the per-user/item/action update permission cache from an allowed IP.
		allowed.collab({ action: 'focus', room: allowedInit.room, field: 'title' });
		await allowed.waitFor('focus', (message) => message.field === 'title');
		allowed.collab({ action: 'focus', room: allowedInit.room, field: null });
		await allowed.waitFor('focus', (message) => message.field === null);

		// The same account from a disallowed IP must not inherit the cached update permission.
		denied.collab({ action: 'focus', room: deniedInit.room, field: 'title' });
		const deniedFocus = await denied.waitFor('error');
		expect(deniedFocus.code).toBe('FORBIDDEN');
	} finally {
		allowed.close();
		denied.close();
	}
});
