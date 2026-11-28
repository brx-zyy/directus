import { randomUUID } from 'node:crypto';
import {
	createDirectus,
	createItem,
	readSingleton,
	rest,
	staticToken,
	updateSettings,
	updateSingleton,
} from '@directus/sdk';
import { openCollab } from '@utils/collab.js';
import { port } from '@utils/constants.js';
import { useSnapshot } from '@utils/use-snapshot.js';
import { afterAll, expect, test } from 'vitest';
import type { Schema } from './schema.d.ts';
import { snapshot } from './snapshot.js';
import { createRestrictedUser, type Rule } from './users.js';

const api = createDirectus<Schema>(`http://localhost:${port}`).with(rest()).with(staticToken('admin'));

await api.request(updateSettings({ collaborative_editing_enabled: true } as any));

const { collections } = await useSnapshot<Schema>(api, snapshot);

const clients: { close: () => void }[] = [];

afterAll(() => {
	for (const client of clients) client.close();
});

async function client(token = 'admin') {
	const collab = await openCollab(port, token);
	clients.push(collab);
	return collab;
}

async function restricted(permissions: Rule[]) {
	return client(await createRestrictedUser(api as any, permissions));
}

test('joining an item the user cannot read is refused', async () => {
	const item = await api.request(createItem(collections.private, { secret: 'Hidden' } as any));

	const collab = await restricted([]);

	expect(await collab.join(collections.private, item.id!)).toMatchObject({
		action: 'error',
		code: 'FORBIDDEN',
	});
});

test('an update to a field the user cannot read is not broadcast to them', async () => {
	const item = await api.request(
		createItem(collections.items, { title: 'Public Title', content: 'Secret Content' } as any),
	);

	const admin = await client();

	const viewer = await restricted([
		{ collection: collections.items, action: 'read', fields: ['id', 'title'] },
		{ collection: collections.items, action: 'update', fields: ['id', 'title'] },
	]);

	const init = await admin.join(collections.items, item.id!);
	await viewer.join(collections.items, item.id!);
	await admin.waitFor('join');

	const room = init.room;

	admin.collab({ action: 'focus', room, field: 'title' });
	await viewer.waitFor('focus', (message) => message.field === 'title');

	admin.collab({ action: 'update', room, field: 'title', changes: 'New Public Title' });

	expect(await viewer.waitFor('update', (message) => message.field === 'title')).toMatchObject({
		changes: 'New Public Title',
	});

	admin.collab({ action: 'focus', room, field: 'content' });
	admin.collab({ action: 'update', room, field: 'content', changes: 'New Secret Content' });

	// Nothing about `content` ever reaches a client that may not read it
	expect(await viewer.quiet('update', (message) => message.field === 'content')).toBe(true);
	expect(await viewer.quiet('focus', (message) => message.field === 'content')).toBe(true);
});

test('clearing a field only propagates when the recipient may read it', async () => {
	const item = await api.request(
		createItem(collections.items, { title: 'Public Title', content: 'Secret Content' } as any),
	);

	const admin = await client();

	const viewer = await restricted([
		{ collection: collections.items, action: 'read', fields: ['id', 'title'] },
		{ collection: collections.items, action: 'update', fields: ['id', 'title'] },
	]);

	const init = await admin.join(collections.items, item.id!);
	await viewer.join(collections.items, item.id!);
	await admin.waitFor('join');

	const room = init.room;

	admin.collab({ action: 'update', room, field: 'content', changes: null });

	expect(await viewer.quiet('update')).toBe(true);

	admin.collab({ action: 'update', room, field: 'title', changes: null });

	// Clearing a readable field reaches the viewer, together with the focus it implies
	const focus = await viewer.waitFor('focus', (message) => message.field === 'title');
	const update = await viewer.waitFor('update', (message) => message.field === 'title');

	expect(focus).toMatchObject({ room, field: 'title' });
	expect(update).toMatchObject({ room, field: 'title', changes: null });
});

test('initial changes touching a field the user cannot update are refused', async () => {
	const item = await api.request(
		createItem(collections.items, { title: 'Original Title', content: 'Original Content' } as any),
	);

	const collab = await restricted([
		{ collection: collections.items, action: 'read', fields: ['*'] },
		{ collection: collections.items, action: 'update', fields: ['id', 'title'] },
	]);

	collab.collab({
		action: 'join',
		collection: collections.items,
		item: item.id,
		version: null,
		initialChanges: { title: 'New Title', content: 'Invalid' },
	});

	expect(await collab.waitFor('error')).toMatchObject({
		code: 'FORBIDDEN',
		message: expect.stringMatching(/No permission to update field content or field does not exist/i),
	});
});

test('an update to a field the user cannot update is refused', async () => {
	const item = await api.request(
		createItem(collections.items, { title: 'Original Title', content: 'Original Content' } as any),
	);

	const collab = await restricted([
		{ collection: collections.items, action: 'read', fields: ['*'] },
		{ collection: collections.items, action: 'update', fields: ['id', 'title'] },
	]);

	const init = await collab.join(collections.items, item.id!);

	collab.collab({ action: 'update', room: init.room, field: 'content', changes: 'Unauthorized Update' });

	expect(await collab.waitFor('error')).toMatchObject({
		code: 'FORBIDDEN',
		message: expect.stringMatching(/No permission to update field content or field does not exist/i),
	});
});

test('a field that does not exist is refused, on join and on update', async () => {
	const item = await api.request(createItem(collections.items, { title: 'Original' } as any));

	const permissions: Rule[] = [
		{ collection: collections.items, action: 'read', fields: ['*'] },
		{ collection: collections.items, action: 'update', fields: ['*'] },
	];

	const token = await createRestrictedUser(api as any, permissions);

	const joiner = await client(token);

	joiner.collab({
		action: 'join',
		collection: collections.items,
		item: item.id,
		version: null,
		initialChanges: { non_existent: 'Invalid' },
	});

	expect(await joiner.waitFor('error')).toMatchObject({
		code: 'FORBIDDEN',
		message: expect.stringMatching(/No permission to update field non_existent or field does not exist/i),
	});

	const updater = await client(token);
	const init = await updater.join(collections.items, item.id!);

	updater.collab({ action: 'update', room: init.room, field: 'unknown_field', changes: 'Value' });

	expect(await updater.waitFor('error')).toMatchObject({
		code: 'FORBIDDEN',
		message: expect.stringMatching(/No permission to update field unknown_field or field does not exist/i),
	});
});

test('a discard only names the fields each recipient may read', async () => {
	const item = await api.request(createItem(collections.items, { title: 'Original', content: 'Original' } as any));

	const viewer = await restricted([
		{ collection: collections.items, action: 'read', fields: ['id', 'title', 'content'] },
		{ collection: collections.items, action: 'update', fields: ['id', 'title'] },
	]);

	const init = await viewer.join(collections.items, item.id!);
	const room = init.room;

	const admin = await client();
	await admin.join(collections.items, item.id!);
	await viewer.waitFor('join');

	viewer.collab({ action: 'update', room, field: 'title', changes: 'Dirty Title' });
	admin.collab({ action: 'update', room, field: 'content', changes: 'Admin Content' });

	await admin.waitFor('update', (message) => message.field === 'title');
	await viewer.waitFor('update', (message) => message.field === 'content');

	viewer.collab({ action: 'discard', room });

	// The restricted client may only discard what it is allowed to change
	for (const collab of [viewer, admin]) {
		const discard = await collab.waitFor('discard');

		expect(discard.fields).toContain('title');
		expect(discard.fields).not.toContain('content');
	}
});

test('a relational draft is trimmed to the fields the recipient may read', async () => {
	const main = await api.request(createItem(collections.relational, { name: 'Main Item' } as any));

	const admin = await client();

	const viewer = await restricted([
		{ collection: collections.relational, action: 'read', fields: ['*'] },
		{ collection: collections.relational, action: 'update', fields: ['*'] },
		{ collection: collections.m2o, action: 'read', fields: ['id', 'field_a'] },
	]);

	const init = await admin.join(collections.relational, main.id!);
	await viewer.join(collections.relational, main.id!);

	const ghost = randomUUID();

	admin.collab({
		action: 'update',
		room: init.room,
		field: 'm2o_related',
		changes: { id: ghost, field_a: 'Public Value', field_b: 'SENSITIVE GHOST DATA' },
	});

	const update = await viewer.waitFor('update', (message) => message.field === 'm2o_related');

	expect(update.changes).toMatchObject({ id: ghost, field_a: 'Public Value' });
	expect(update.changes).not.toHaveProperty('field_b');
});

test('a singleton room hands a restricted client only the fields it may read', async () => {
	await api.request(updateSingleton(collections.singleton, { confidential: 'Initial' } as any));

	const admin = await client();
	const init = await admin.join(collections.singleton, null as any);

	admin.collab({
		action: 'update',
		room: init.room,
		field: 'confidential',
		changes: 'SENSITIVE SINGLETON GHOST DATA',
	});

	const viewer = await restricted([{ collection: collections.singleton, action: 'read', fields: ['id'] }]);

	const joined = await viewer.join(collections.singleton, null as any);

	expect(joined.action).toBe('init');
	expect(joined.changes ?? {}).not.toHaveProperty('confidential');
});

test('updateAll can broadcast singleton changes with create but without update permission', async () => {
	await api.request(updateSingleton(collections.singleton, { title: 'Persisted Singleton Title' } as any));

	const attackerToken = await createRestrictedUser(api as any, [
		{ collection: collections.singleton, action: 'read', fields: ['*'] },
		{ collection: collections.singleton, action: 'create', fields: ['title'] },
	]);

	const observer = await client();
	const attacker = await client(attackerToken);

	const observerInit = await observer.join(collections.singleton, null as any);
	const attackerInit = await attacker.join(collections.singleton, null as any);

	expect(attackerInit.room).toBe(observerInit.room);
	await observer.waitFor('join');

	// The single-field path checks update permissions and must reject this user.
	attacker.collab({
		action: 'update',
		room: attackerInit.room,
		field: 'title',
		changes: 'Rejected Single-Field Draft',
	});

	expect(await attacker.waitFor('error')).toMatchObject({ code: 'FORBIDDEN' });

	// The update-all path validates a null singleton item as a create operation.
	attacker.collab({
		action: 'updateAll',
		room: attackerInit.room,
		changes: { title: 'Injected Collaborative Draft' },
	});

	// The observer must receive the unauthorized draft through the normal update event.
	const broadcast = await observer.waitFor('update', (message) => message.field === 'title');
	expect(broadcast).toMatchObject({
		room: observerInit.room,
		field: 'title',
		changes: 'Injected Collaborative Draft',
	});

	// The same account still cannot persist the change through the normal REST API.
	const attackerApi = createDirectus<Schema>(`http://localhost:${port}`).with(rest()).with(staticToken(attackerToken));

	await expect(
		attackerApi.request(updateSingleton(collections.singleton, { title: 'Unauthorized Persisted Title' } as any)),
	).rejects.toThrowError();

	// Collaboration state is a draft; the database value remains unchanged.
	expect(await api.request(readSingleton(collections.singleton))).toMatchObject({
		title: 'Persisted Singleton Title',
	});
});


test('updateAll does not broadcast changes to an existing item without update permission', async () => {
	const item = await api.request(createItem(collections.items, { title: 'Persisted Item Title' } as any));

	const attackerToken = await createRestrictedUser(api as any, [
		{ collection: collections.items, action: 'read', fields: ['*'] },
		{ collection: collections.items, action: 'create', fields: ['title'] },
	]);

	const observer = await client();
	const attacker = await client(attackerToken);

	const observerInit = await observer.join(collections.items, item.id!);
	const attackerInit = await attacker.join(collections.items, item.id!);

	expect(attackerInit.room).toBe(observerInit.room);
	await observer.waitFor('join');

	attacker.collab({
		action: 'updateAll',
		room: attackerInit.room,
		changes: { title: 'Unauthorized Existing Item Draft' },
	});

	expect(await attacker.waitFor('error')).toMatchObject({ code: 'FORBIDDEN' });
	expect(await observer.quiet('update', (message) => message.field === 'title')).toBe(true);

	expect(await api.request(readSingleton(collections.singleton))).toMatchObject({
		title: 'Persisted Singleton Title',
	});
});
