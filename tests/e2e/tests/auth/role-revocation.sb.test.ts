import { randomUUID } from 'node:crypto';
import { sandbox } from '@directus/sandbox';
import { database } from '@utils/constants.js';
import { sandboxPort } from '@utils/sandbox-port.js';
import { useSandbox } from '@utils/sandbox.js';
import { openAuthenticatedSocket } from '@utils/websocket.js';
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
				WEBSOCKETS_REST_AUTH: 'handshake',
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

	test('role downgrade does not revoke an existing stateful admin session', async () => {
		const roleA = await post('/roles', { name: `Privileged-${randomUUID()}` });
		const roleB = await post('/roles', { name: `Restricted-${randomUUID()}` });
		const policy = await post('/policies', {
			name: `Role read-${randomUUID()}`,
			admin_access: true,
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

		// Also create a stateful session cookie before the role downgrade.
		const sessionLogin = await request('/auth/login', {
			method: 'POST',
			body: JSON.stringify({ email, password: 'test-password', mode: 'session' }),
			headers: { 'Content-Type': 'application/json' },
		});
		expect(sessionLogin.status).toBe(200);
		const setCookie = sessionLogin.headers.get('set-cookie');
		expect(setCookie).toBeTruthy();
		const sessionCookie = setCookie!.split(';')[0]!;

		const beforeSession = await fetch(`${apiUrl}/roles`, { headers: { Cookie: sessionCookie } });
		expect(beforeSession.status).toBe(200);

		// Open a WebSocket while the session is still valid and subscribe to privileged role events.
		const sessionToken = decodeURIComponent(sessionCookie.slice(sessionCookie.indexOf('=') + 1));
		const ws = await openAuthenticatedSocket(`ws://127.0.0.1:${directus.apis[0].port}/websocket`, sessionToken);
		ws.send({ type: 'subscribe', collection: 'directus_roles', event: 'create', uid: 'role-events' });
		const initial = await ws.next((message) => message.type === 'subscription' && message.uid === 'role-events');
		expect(initial.event).toBe('init');

		const downgrade = await request(`/users/${user.id}`, {
			method: 'PATCH',
			body: JSON.stringify({ role: roleB.id }),
		});
		expect(downgrade.status).toBe(200);

		// The same pre-downgrade JWT should no longer retain role A's permissions.
		const afterOldToken = await request('/roles', {}, oldToken);
		expect(afterOldToken.status).toBe(200); // Existing JWT retains the role claim it was issued with.

		// Stateful session JWTs are expected to be checked against directus_sessions.
		// Verify whether a role downgrade invalidates the already-issued session token.
		const afterOldSession = await fetch(`${apiUrl}/roles`, { headers: { Cookie: sessionCookie } });
		expect(afterOldSession.status).toBe(200); // Existing session JWT retains admin_access until its session expires.

		const roleCreatedAfterDowngrade = await post('/roles', { name: `After-downgrade-${randomUUID()}` });
		const downgradeEvent = await ws.next(
			(message) => message.type === 'subscription' && message.uid === 'role-events' && message.event === 'create',
		);
		expect(downgradeEvent.data.id).toBe(roleCreatedAfterDowngrade.id);

		const newLogin = await request('/auth/login', {
			method: 'POST',
			body: JSON.stringify({ email, password: 'test-password' }),
			headers: { 'Content-Type': 'application/json' },
		});
		expect(newLogin.status).toBe(200);
		const newToken = (await newLogin.json() as { data: { access_token: string } }).data.access_token;
		const afterNewToken = await request('/roles', {}, newToken);
		expect(afterNewToken.status).toBe(403);

		// Control: a status suspension does revoke the same stateful session.
		const suspend = await request(`/users/${user.id}`, {
			method: 'PATCH',
			body: JSON.stringify({ status: 'suspended' }),
		});
		expect(suspend.status).toBe(200);

		const afterSuspension = await fetch(`${apiUrl}/roles`, { headers: { Cookie: sessionCookie } });
		expect(afterSuspension.status).toBe(401);

		// The HTTP session is revoked, but the existing WebSocket retains its connection-time
		// accountability and still receives administrator-only events until token expiry.
		const roleCreated = await post('/roles', { name: `After-suspension-${randomUUID()}` });
		const leaked = await ws.next(
			(message) => message.type === 'subscription' && message.uid === 'role-events' && message.event === 'create',
		);
		expect(leaked.data.id).toBe(roleCreated.id);
		ws.close();

	});
});
