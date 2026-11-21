import { randomUUID } from 'node:crypto';
import { sandbox } from '@directus/sandbox';
import { database } from '@utils/constants.js';
import { sandboxPort } from '@utils/sandbox-port.js';
import { useSandbox } from '@utils/sandbox.js';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

let directus: Awaited<ReturnType<typeof sandbox>>;
let apiUrl: string;

async function request(path: string, options: RequestInit = {}, token = 'admin') {
	return fetch(`${apiUrl}${path}`, {
		...options,
		headers: {
			Authorization: `Bearer ${token}`,
			...(options.body ? { 'Content-Type': 'application/json' } : {}),
			...options.headers,
		},
	});
}

async function post(path: string, body: Record<string, unknown>) {
	const response = await request(path, { method: 'POST', body: JSON.stringify(body) });
	expect(response.status).toBe(200);
	return (await response.json() as { data: any }).data;
}

describe('role revocation', () => {
	beforeAll(async () => {
		directus = await useSandbox(database, {
			port: sandboxPort(0),
			inspect: false,
			prefix: `role-revocation-${randomUUID()}`,
			env: {
				DB_FILENAME: `directus_test_role_revocation_${randomUUID()}.db`,
			},
			docker: { suffix: randomUUID() },
			cache: false,
			knex: true,
		});
		apiUrl = `http://127.0.0.1:${directus.apis[0].port}`;
	});

	afterAll(async () => {
		await directus?.stop();
	});

	test('old access token retains the previous role permissions after role downgrade', async () => {
		const roleA = await post('/roles', { name: `Privileged-${randomUUID()}` });
		const roleB = await post('/roles', { name: `Restricted-${randomUUID()}` });
		const policy = await post('/policies', {
			name: `Role read-${randomUUID()}`,
			admin_access: false,
			app_access: false,
		});
		await post('/permissions', {
			policy: policy.id,
			collection: 'directus_roles',
			action: 'read',
			permissions: {},
			fields: ['*'],
		});
		await post('/access', { role: roleA.id, policy: policy.id });

		const email = `${randomUUID()}@example.com`;
		const user = await post('/users', {
			first_name: 'Role',
			last_name: 'Revocation',
			email,
			password: 'test-password',
			role: roleA.id,
			status: 'active',
		});

		const login = await request('/auth/login', {
			method: 'POST',
			body: JSON.stringify({ email, password: 'test-password' }),
			headers: { 'Content-Type': 'application/json' },
		});
		expect(login.status).toBe(200);
		const loginData = (await login.json() as { data: { access_token: string } }).data;
		const oldToken = loginData.access_token;

		const before = await request('/roles', {}, oldToken);
		expect(before.status).toBe(200);

		const downgrade = await request(`/users/${user.id}`, {
			method: 'PATCH',
			body: JSON.stringify({ role: roleB.id }),
		});
		expect(downgrade.status).toBe(200);

		// The same pre-downgrade JWT should no longer retain role A's permissions.
		const afterOldToken = await request('/roles', {}, oldToken);
		expect(afterOldToken.status).toBe(403);

		const newLogin = await request('/auth/login', {
			method: 'POST',
			body: JSON.stringify({ email, password: 'test-password' }),
			headers: { 'Content-Type': 'application/json' },
		});
		expect(newLogin.status).toBe(200);
		const newToken = (await newLogin.json() as { data: { access_token: string } }).data.access_token;
		const afterNewToken = await request('/roles', {}, newToken);
		expect(afterNewToken.status).toBe(403);
	});
});
