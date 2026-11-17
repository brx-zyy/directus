import knex from 'knex';
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest';

vi.mock('@directus/env', async () => {
	const { mockUseEnv } = await import('../test-utils/env.js');
	return mockUseEnv();
});

vi.mock('../logger/index.js', () => ({ useLogger: vi.fn().mockReturnValue({ error: vi.fn() }) }));
vi.mock('../permissions/cache.js', () => ({ clearCache: vi.fn(), useCache: vi.fn() }));
vi.mock('../permissions/modules/validate-access/validate-access.js', () => ({ validateAccess: vi.fn() }));
vi.mock('./mail/index.js', () => ({ MailService: vi.fn() }));
vi.mock('./items.js', async () => {
	const { mockItemsService } = await import('../test-utils/services/items-service.js');
	return mockItemsService();
});

import { SharesService } from './shares.js';

const db = knex({
	client: 'sqlite3',
	connection: { filename: ':memory:' },
	useNullAsDefault: true,
	pool: { min: 1, max: 1 },
});

const service = new SharesService({
	knex: db,
	schema: { collections: {}, relations: [] } as any,
});

beforeAll(async () => {
	await db.schema.createTable('directus_shares', (table) => {
		table.string('id').primary();
		table.integer('max_uses').nullable();
		table.integer('times_used').notNullable().defaultTo(0);
		table.dateTime('date_start').nullable();
		table.dateTime('date_end').nullable();
		table.string('password').nullable();
	});

	await db.schema.createTable('directus_sessions', (table) => {
		table.string('token').primary();
		table.dateTime('expires').notNullable();
		table.string('ip').nullable();
		table.string('user_agent').nullable();
		table.string('origin').nullable();
		table.string('share').nullable();
	});
});

afterAll(async () => {
	await db.destroy();
});

describe('share max_uses enforcement', () => {
	test('reproduces login succeeding after max_uses has already been reached', async () => {
		await db('directus_shares').insert({
			id: 'limit-one',
			max_uses: 1,
			times_used: 1,
		});

		// The share has already reached its one permitted use.
		// The current implementation accepts this login and issues another access token.
		const result = await service.login({ share: 'limit-one' });

		expect(result.accessToken).toBeTruthy();
		expect(await db('directus_shares').where({ id: 'limit-one' }).first('times_used')).toMatchObject({
			times_used: 2,
		});
	});
});
