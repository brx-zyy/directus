import { getRedactedString, REDACTED_TEXT } from '@directus/utils';
import { describe, expect, it } from 'vitest';
import { FLOW_SECRET_KEYS } from '../constants.js';
import { redactObject } from './redact-object.js';

describe('flow revision secret redaction security regression', () => {
	it('redacts OAuth access tokens in operation results before revisions are stored', () => {
		const accessToken = 'synthetic-access-token-not-real';
		const result = redactObject(
			{
				'$trigger': { body: { action: 'fetch-token' } },
				request_operation: { access_token: accessToken, token_type: 'Bearer' },
			},
			{ keys: FLOW_SECRET_KEYS },
			getRedactedString,
		);

		expect(result).toMatchObject({
			request_operation: { access_token: REDACTED_TEXT, token_type: 'Bearer' },
		});
	});

	it('redacts refresh tokens nested in webhook bodies before revisions are stored', () => {
		const refreshToken = 'synthetic-refresh-token-not-real';
		const result = redactObject(
			{ '$trigger': { body: { refresh_token: refreshToken } } },
			{ keys: FLOW_SECRET_KEYS },
			getRedactedString,
		);

		expect(result).toMatchObject({ '$trigger': { body: { refresh_token: REDACTED_TEXT } } });
	});

	it('continues to redact covered password fields as a positive control', () => {
		const result = redactObject(
			{ '$trigger': { body: { password: 'synthetic-password' } } },
			{ keys: FLOW_SECRET_KEYS },
			getRedactedString,
		);

		expect(result).toMatchObject({ '$trigger': { body: { password: REDACTED_TEXT } } });
	});
});
