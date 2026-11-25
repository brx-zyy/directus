import crypto from 'node:crypto';
import knex, { type Knex } from 'knex';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { McpOAuthService } from './index.js';
import { getAccountabilityForToken } from '../../utils/get-accountability-for-token.js';

const shared = vi.hoisted(() => ({ db: undefined as unknown }));

vi.mock('../../database/index.js', () => ({
	default: () => shared.db,
}));

vi.mock('@directus/env', () => ({
	useEnv: () => ({
		PUBLIC_URL: 'http://localhost:8055',
		ACCESS_TOKEN_TTL: 900_000,
		REFRESH_TOKEN_TTL: 604_800_000,
		MCP_OAUTH_REQUIRE_RESOURCE: false,
		MCP_OAUTH_MAX_CLIENTS: 10000,
		MCP_OAUTH_CLIENT_UNUSED_TTL: 259_200_000,
		MCP_OAUTH_CLIENT_IDLE_TTL: 0,
		MCP_OAUTH_DCR_ENABLED: true,
		MCP_OAUTH_CIMD_ENABLED: true,
		MCP_OAUTH_ALLOWED_CUSTOM_REDIRECTS: [],
		MCP_OAUTH_ALLOWED_REDIRECT_DOMAINS: [],
	}),
}));

vi.mock('../../utils/get-secret.js', () => ({
	getSecret: () => 'integration-test-secret-that-is-long-enough',
}));

vi.mock('../../logger/index.js', () => ({
	useLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

vi.mock('../../permissions/lib/fetch-roles-tree.js', () => ({
	fetchRolesTree: vi.fn().mockResolvedValue(['role-1']),
}));

vi.mock('../../permissions/modules/fetch-global-access/fetch-global-access.js', () => ({
	fetchGlobalAccess: vi.fn().mockResolvedValue({ app: true, admin: false }),
}));

vi.mock('../activity.js', () => ({
	ActivityService: vi.fn().mockImplementation(() => ({ createOne: vi.fn().mockResolvedValue('activity-1') })),
}));

function deferred() {
	let resolve!: () => void;
	const promise = new Promise<void>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

function pauseAfterFirstGrantRead(db: Knex, onRead: () => void, resume: Promise<void>): Knex {
	let paused = false;

	const wrapBuilder = (builder: any): any => {
		let proxy: any;
		proxy = new Proxy(builder, {
			get(target, property) {
				if (property === 'first') {
					return async (...args: unknown[]) => {
						const result = await target.first(...args);
						if (!paused) {
							paused = true;
							onRead();
							await resume;
						}
						return result;
					};
				}

				const value = Reflect.get(target, property, target);

				if (typeof value === 'function') {
					return (...args: unknown[]) => {
						const result = value.apply(target, args);
						return result === target ? proxy : result;
					};
				}

				return value;
			},
		});

		return proxy;
	};

	return new Proxy(db, {
		apply(target, thisArg, args: [string, ...unknown[]]) {
			const builder = Reflect.apply(target, thisArg, args);
			return args[0] === 'directus_oauth_tokens' ? wrapBuilder(builder) : builder;
		},
		get(target, property) {
			const value = Reflect.get(target, property, target);
			return typeof value === 'function' ? value.bind(target) : value;
		},
	}) as Knex;
}

describe('MCP OAuth refresh/revocation PostgreSQL race', () => {
	let db: Knex;

	beforeAll(async () => {
		if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required for this integration test');

		db = knex({ client: 'pg', connection: process.env.DATABASE_URL });
		shared.db = db;

		await db.raw('DROP TABLE IF EXISTS directus_oauth_tokens, directus_sessions, directus_users, directus_oauth_clients CASCADE');
		await db.raw(`
			CREATE TABLE directus_oauth_clients (
				client_id text PRIMARY KEY,
				client_name text NOT NULL,
				grant_types jsonb NOT NULL,
				token_endpoint_auth_method text NOT NULL,
				client_secret_hash text
			);
			CREATE TABLE directus_users (
				id text PRIMARY KEY,
				email text,
				status text NOT NULL,
				role text
			);
			CREATE TABLE directus_sessions (
				token text PRIMARY KEY,
				"user" text,
				share text,
				expires timestamptz NOT NULL,
				ip text,
				user_agent text,
				oauth_client text REFERENCES directus_oauth_clients(client_id) ON DELETE CASCADE
			);
			CREATE TABLE directus_oauth_tokens (
				id text PRIMARY KEY,
				client text NOT NULL REFERENCES directus_oauth_clients(client_id) ON DELETE CASCADE,
				"user" text NOT NULL REFERENCES directus_users(id) ON DELETE CASCADE,
				session text NOT NULL,
				previous_session text,
				resource text NOT NULL,
				scope text,
				code_hash text NOT NULL,
				expires_at timestamptz NOT NULL,
				date_created timestamptz NOT NULL,
				UNIQUE(client, "user")
			);
		`);
	});

	beforeEach(async () => {
		await db.raw('TRUNCATE directus_oauth_tokens, directus_sessions, directus_users, directus_oauth_clients CASCADE');
	});

	afterAll(async () => {
		if (db) await db.destroy();
	});

	it('keeps a refreshed access token authenticated when revocation read the old grant first', async () => {
		const clientId = 'client-race-test';
		const userId = 'user-race-test';
		const grantId = 'grant-race-test';
		const oldRefreshToken = 'old-refresh-token-for-race-test';
		const oldHash = crypto.createHash('sha256').update(oldRefreshToken).digest('hex');
		const resource = 'http://localhost:8055/mcp';
		const now = new Date();
		const expires = new Date(now.getTime() + 60 * 60 * 1000);

		await db('directus_oauth_clients').insert({
			client_id: clientId,
			client_name: 'Race test client',
			grant_types: JSON.stringify(['authorization_code', 'refresh_token']),
			token_endpoint_auth_method: 'none',
		});
		await db('directus_users').insert({ id: userId, email: 'race@example.test', status: 'active', role: 'role-1' });
		await db('directus_oauth_tokens').insert({
			id: grantId,
			client: clientId,
			user: userId,
			session: oldHash,
			resource,
			scope: 'mcp:access',
			code_hash: 'c'.repeat(64),
			expires_at: expires,
			date_created: now,
		});
		await db('directus_sessions').insert({
			token: oldHash,
			user: userId,
			share: null,
			expires,
			ip: '127.0.0.1',
			user_agent: 'integration-test',
			oauth_client: clientId,
		});

		const grantRead = deferred();
		const resumeRevoke = deferred();
		const revokeKnex = pauseAfterFirstGrantRead(
			db,
			() => grantRead.resolve(),
			resumeRevoke.promise,
		);

		const revoker = new McpOAuthService({ knex: revokeKnex, schema: {} as any });
		const refresher = new McpOAuthService({ knex: db, schema: {} as any });

		const revokePromise = revoker.revokeToken({ client_id: clientId, token: oldRefreshToken });
		await grantRead.promise;

		const refreshed = await refresher.refreshToken(
			{
				client_id: clientId,
				grant_type: 'refresh_token',
				refresh_token: oldRefreshToken,
				resource,
			},
			{ ip: '127.0.0.1', userAgent: 'integration-test' },
		);

		resumeRevoke.resolve();
		await revokePromise;

		const newHash = crypto.createHash('sha256').update(refreshed.refresh_token!).digest('hex');
		expect(await db('directus_oauth_tokens').where({ id: grantId }).first()).toBeUndefined();
		expect(await db('directus_sessions').where({ token: oldHash }).first()).toBeUndefined();
		expect(await db('directus_sessions').where({ token: newHash }).first()).toBeDefined();

		const accountability = await getAccountabilityForToken(refreshed.access_token);
		expect(accountability.user).toBe(userId);
		expect(accountability.session).toBe(newHash);
		expect(accountability.oauth?.client).toBe(clientId);
	});
});
