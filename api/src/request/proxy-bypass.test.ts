import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, expect, it, vi } from 'vitest';
import { _cache, getAxios } from './index.js';

const { isDeniedIp } = vi.hoisted(() => ({
	isDeniedIp: vi.fn((ip: string) => ip === '169.254.169.254'),
}));

vi.mock('./is-denied-ip.js', () => ({ isDeniedIp }));

const envKeys = ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy'];

afterEach(() => {
	_cache.axiosInstance = null;
	vi.clearAllMocks();
});

it('does not validate the target IP when Axios sends the request through an environment proxy', async () => {
	const previousEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
	const received: string[] = [];
	const proxy = createServer((req, res) => {
		received.push(req.url ?? '');
		res.writeHead(200, { 'Content-Type': 'text/plain' });
		res.end('internal-response');
	});

	try {
		await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
		const proxyPort = (proxy.address() as AddressInfo).port;

		process.env['HTTP_PROXY'] = `http://127.0.0.1:${proxyPort}`;
		process.env['http_proxy'] = `http://127.0.0.1:${proxyPort}`;
		process.env['HTTPS_PROXY'] = '';
		process.env['https_proxy'] = '';
		process.env['ALL_PROXY'] = '';
		process.env['all_proxy'] = '';
		process.env['NO_PROXY'] = '';
		process.env['no_proxy'] = '';

		const axios = await getAxios();
		const response = await axios.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/');

		expect(response.data).toBe('internal-response');
		expect(received).toEqual(['http://169.254.169.254/latest/meta-data/iam/security-credentials/']);
		expect(isDeniedIp).toHaveBeenCalledWith('127.0.0.1');
		expect(isDeniedIp).not.toHaveBeenCalledWith('169.254.169.254');
	} finally {
		for (const key of envKeys) {
			const value = previousEnv[key];
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}

		await new Promise<void>((resolve, reject) =>
			proxy.close((error) => (error ? reject(error) : resolve())),
		);
		_cache.axiosInstance = null;
	}
});
