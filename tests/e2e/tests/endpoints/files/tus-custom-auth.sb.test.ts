import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { createDirectus, readAssetArrayBuffer, rest } from '@directus/sdk';
import { database } from '@utils/constants.js';
import { getUID } from '@utils/getUID.js';
import { sandboxPort } from '@utils/sandbox-port.js';
import { useSandbox } from '@utils/sandbox.js';
import { afterAll, beforeAll, expect, test } from 'vitest';

const PUBLIC_POLICY_ID = 'abf8a154-5b1c-4a46-ac9c-7300570f4f17';

let directus: Awaited<ReturnType<typeof useSandbox>>;
let api: ReturnType<typeof createDirectus>;
let apiUrl: string;

beforeAll(async () => {
	directus = await useSandbox(database, {
		port: sandboxPort(0),
		inspect: false,
		prefix: `tus-custom-auth-${getUID()}`,
		env: {
			TUS_ENABLED: 'true',
			EXTENSIONS_PATH: resolve(import.meta.dirname, 'hooks'),
			TEMP_PATH: './uploads/temp',
			DB_FILENAME: `directus_test_${getUID()}.db`,
		},
		docker: { suffix: getUID() },
		cache: false,
		knex: true,
	});

	apiUrl = `http://127.0.0.1:${directus.apis[0]!.port}`;
	api = createDirectus(apiUrl).with(rest());

	// Grant the built-in public policy explicit file create/read/update access.
	// The custom authenticate hook returns a modified anonymous accountability,
	// preserving role=null and user=null, so every unauthenticated client shares it.
	await directus.knex!('directus_permissions').insert(
		['create', 'read', 'update'].map((action) => ({
			id: randomUUID(),
			policy: PUBLIC_POLICY_ID,
			collection: 'directus_files',
			action,
			permissions: null,
			validation: null,
			presets: null,
			fields: '*',
		})),
	);
});

afterAll(async () => {
	await directus?.stop();
});

test('custom authenticate hook with public file update permission allows a second anonymous client to resume a known TUS URL', async () => {
	const filename = `custom-anon-${randomUUID()}.bin`;
	const encode = (value: string) => Buffer.from(value).toString('base64');

	const victimCreate = await fetch(`${apiUrl}/files/tus`, {
		method: 'POST',
		headers: {
			'Tus-Resumable': '1.0.0',
			'Upload-Length': '6',
			'Upload-Metadata': `filename_download ${encode(filename)},type ${encode('application/octet-stream')}`,
		},
	});
	expect(victimCreate.status).toBe(201);
	const uploadUrl = new URL(victimCreate.headers.get('location')!, apiUrl).toString();

	// A separate anonymous HTTP client is given the victim's upload URL.
	const attackerPatch = await fetch(uploadUrl, {
		method: 'PATCH',
		headers: {
			'Tus-Resumable': '1.0.0',
			'Upload-Offset': '0',
			'Content-Type': 'application/offset+octet-stream',
		},
		body: Buffer.from('evil!!'),
	});
	expect(attackerPatch.status).toBe(204);

	const file = await directus.knex!('directus_files').select('id').where({ filename_download: filename }).first();
	expect(file?.id).toBeDefined();

	const downloaded = await api.request(readAssetArrayBuffer(file.id));
	expect(Buffer.from(downloaded).toString()).toBe('evil!!');
});
