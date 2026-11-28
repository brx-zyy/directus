import { randomUUID } from 'crypto';
import knex from 'knex';
import {
	createCollection,
	createDirectus,
	createItem,
	deleteItem,
	deleteItems,
	createPolicy,
	createUser,
	readItem,
	rest,
	staticToken,
	updateItem,
	updatePolicy,
} from '@directus/sdk';
import { sandbox } from '@directus/sandbox';
import { database } from '@utils/constants.js';
import { getUID } from '@utils/getUID.js';
import { afterAll, expect, test } from 'vitest';

const COLLECTION = 'security_toctou_items';
let directus: Awaited<ReturnType<typeof sandbox>> | undefined;
let blockerDb: ReturnType<typeof knex> | undefined;

afterAll(async () => {
	await blockerDb?.destroy();
	await directus?.stop();
});

test.skipIf(database !== 'postgres')(
	'row-level update permission is re-evaluated after a concurrent ownership transfer',
	{ timeout: 120_000 },
	async () => {
		directus = await sandbox('postgres', {
			env: {
				LOG_LEVEL: 'debug',
				LICENSE_KEY: 'D0000-00000-00000-00000-0000K',
				DB_FILENAME: `directus_test_${getUID()}.db`,
				CACHE_STORE: 'memory',
			},
			cache: true,
			extras: { license: true },
		});

		const url = `http://localhost:${directus.apis[0]!.port}`;
		const admin = createDirectus<unknown>(url).with(rest()).with(staticToken('admin'));

		await admin.request(
			createCollection({
				collection: COLLECTION,
				fields: [
					{
						field: 'id',
						type: 'integer',
						meta: { hidden: true, interface: 'input', readonly: true },
						schema: { is_primary_key: true, has_auto_increment: true },
					},
					{ field: 'owner', type: 'uuid', meta: { interface: 'input' }, schema: {} },
					{ field: 'title', type: 'string', meta: { interface: 'input' }, schema: {} },
				],
				schema: {},
				meta: { singleton: false },
			} as any),
		);

		const attackerToken = randomUUID();
		const attacker = await admin.request(
			createUser({
				first_name: 'TOCTOU',
				last_name: 'Attacker',
				email: `${attackerToken}@example.com`,
				password: 'password',
				token: attackerToken,
			}),
		);

		const victimToken = randomUUID();
		const victim = await admin.request(
			createUser({
				first_name: 'TOCTOU',
				last_name: 'Victim',
				email: `${victimToken}@example.com`,
				password: 'password',
				token: victimToken,
			}),
		);

		const policy = await admin.request(
			createPolicy({
				name: 'TOCTOU owner-only update',
				admin_access: false,
				app_access: false,
				users: [{ user: attacker.id }],
				permissions: [],
			} as any),
		);

		await admin.request(
			updatePolicy(policy.id, {
				permissions: [
					{
						action: 'update',
						collection: COLLECTION,
						fields: ['title'],
						permissions: { owner: { _eq: '$CURRENT_USER' } },
					},
					{
						action: 'delete',
						collection: COLLECTION,
						permissions: { owner: { _eq: '$CURRENT_USER' } },
					},
				] as any,
			}),
		);

		const record = await admin.request(
			createItem(COLLECTION, { owner: attacker.id, title: 'before-transfer' } as any),
		);

		const attackerApi = createDirectus<unknown>(url).with(rest()).with(staticToken(attackerToken));

		blockerDb = knex({
			client: 'pg',
			connection: {
				host: directus.env.DB_HOST,
				port: Number(directus.env.DB_PORT),
				user: directus.env.DB_USER,
				password: directus.env.DB_PASSWORD,
				database: directus.env.DB_DATABASE,
			},
			pool: { min: 0, max: 2 },
		});

		// Hold a row lock while transferring ownership. Under READ COMMITTED,
		// the attacker's permission SELECT can still see the previously committed owner.
		const transfer = await blockerDb.transaction();
		await transfer(COLLECTION).where({ id: record.id }).update({ owner: victim.id });

		const attackerWrite = attackerApi.request(
			updateItem(COLLECTION, record.id as number, { title: 'written-after-transfer' } as any),
		);

		let observedLock = false;
		const deadline = Date.now() + 20_000;

		while (Date.now() < deadline) {
			const waiting = await blockerDb('pg_stat_activity')
				.select('pid', 'query', 'wait_event_type')
				.where({ datname: directus.env.DB_DATABASE, wait_event_type: 'Lock' })
				.whereRaw('query ILIKE ?', [`%update "%${COLLECTION}"%`]);

			if (waiting.length > 0) {
				observedLock = true;
				break;
			}

			await new Promise((resolve) => setTimeout(resolve, 50));
		}

		if (!observedLock) {
			await transfer.rollback();
			await expect(attackerWrite).rejects.toThrow();
			throw new Error('Did not observe the API UPDATE waiting on the ownership-transfer row lock');
		}

		// The permission check has passed and the final UPDATE is now blocked.
		// Committing the transfer makes the row belong to the victim before the write resumes.
		await transfer.commit();
		await expect(attackerWrite).resolves.toBeDefined();

		const finalRecord = await blockerDb(COLLECTION).where({ id: record.id }).first();

		expect(finalRecord.owner).toBe(victim.id);
		expect(finalRecord.title).toBe('written-after-transfer');

		// Confirm the row is no longer eligible under the attacker's permission predicate.
		await expect(
			attackerApi.request(updateItem(COLLECTION, record.id as number, { title: 'second-write' } as any)),
		).rejects.toThrow();

		const adminRead = await admin.request(readItem(COLLECTION, record.id as number));
		expect(adminRead).toMatchObject({ owner: victim.id, title: 'written-after-transfer' });

		// Repeat the race with delete-only authorization to check whether the same
		// stale permission decision can delete a row after ownership changes.
		const deleteRecord = await admin.request(
			createItem(COLLECTION, { owner: attacker.id, title: 'delete-before-transfer' } as any),
		);

		const deleteTransfer = await blockerDb.transaction();
		await deleteTransfer(COLLECTION).where({ id: deleteRecord.id }).update({ owner: victim.id });

		const attackerDelete = attackerApi.request(deleteItem(COLLECTION, deleteRecord.id as number));
		let observedDeleteLock = false;
		const deleteDeadline = Date.now() + 20_000;

		while (Date.now() < deleteDeadline) {
			const waiting = await blockerDb('pg_stat_activity')
				.select('pid', 'query', 'wait_event_type')
				.where({ datname: directus.env.DB_DATABASE, wait_event_type: 'Lock' })
				.whereRaw('query ILIKE ?', [`%delete from "%${COLLECTION}"%`]);

			if (waiting.length > 0) {
				observedDeleteLock = true;
				break;
			}

			await new Promise((resolve) => setTimeout(resolve, 50));
		}

		if (!observedDeleteLock) {
			await deleteTransfer.rollback();
			await expect(attackerDelete).rejects.toThrow();
			throw new Error('Did not observe the API DELETE waiting on the ownership-transfer row lock');
		}

		await deleteTransfer.commit();
		await expect(attackerDelete).resolves.toBeDefined();
		expect(await blockerDb(COLLECTION).where({ id: deleteRecord.id }).first()).toBeUndefined();

		// Exercise the collection-level bulk DELETE route with the same race.
		const bulkDeleteRecord = await admin.request(
			createItem(COLLECTION, { owner: attacker.id, title: 'bulk-delete-before-transfer' } as any),
		);

		const bulkTransfer = await blockerDb.transaction();
		await bulkTransfer(COLLECTION).where({ id: bulkDeleteRecord.id }).update({ owner: victim.id });

		const attackerBulkDelete = attackerApi.request(deleteItems(COLLECTION, [bulkDeleteRecord.id as number]));
		let observedBulkDeleteLock = false;
		const bulkDeleteDeadline = Date.now() + 20_000;

		while (Date.now() < bulkDeleteDeadline) {
			const waiting = await blockerDb('pg_stat_activity')
				.select('pid', 'query', 'wait_event_type')
				.where({ datname: directus.env.DB_DATABASE, wait_event_type: 'Lock' })
				.whereRaw('query ILIKE ?', [`%delete from "%${COLLECTION}"%`]);

			if (waiting.length > 0) {
				observedBulkDeleteLock = true;
				break;
			}

			await new Promise((resolve) => setTimeout(resolve, 50));
		}

		if (!observedBulkDeleteLock) {
			await bulkTransfer.rollback();
			await expect(attackerBulkDelete).rejects.toThrow();
			throw new Error('Did not observe the bulk API DELETE waiting on the ownership-transfer row lock');
		}

		await bulkTransfer.commit();
		await expect(attackerBulkDelete).resolves.toBeDefined();
		expect(await blockerDb(COLLECTION).where({ id: bulkDeleteRecord.id }).first()).toBeUndefined();
	},
);
