        del payload['stream_options']
        self.assertEqual(sent, payload)
    def test_sse_delivered_before_upstream_finishes(self):
        conn, res = self.request({'stream': True, 'input': 'test', 'stream_options': {'include_usage': True}})
        self.assertEqual(res.read(len(FIRST)), FIRST)
        self.assertFalse(self.upstream.release.is_set())
        self.upstream.release.set()
        self.assertEqual(res.read(), LAST)
        conn.close()
    def test_chat_completions_keeps_usage(self):
        conn, res = self.request({'stream_options': {'include_usage': True}}, '/v1/chat/completions')
        res.read(); conn.close()
        self.assertEqual(res.getheader('X-Proxy-Sanitized-Count'), '0')
        self.assertEqual(self.upstream.received[2]['stream_options'], {'include_usage': True})
    def test_error_body_status_preserved(self):
        conn, res = self.request({'fail': True})
        self.assertEqual(res.status, 400)
        self.assertEqual(json.loads(res.read())['error']['message'], 'Unknown parameter: stream_options.include_usage')
        conn.close()
    def test_override_and_local_auth(self):
        self.proxy.config.api_key = 'real-upstream-key'
        self.proxy.config.local_key = 'local-secret'
        self.proxy.config.auth_header = 'api-key'
        conn, res = self.request({}, key='wrong')
        self.assertEqual(res.status, 401)
        res.read(); conn.close()
        conn, res = self.request({}, key='local-secret')
        self.assertEqual(res.status, 200)
        res.read(); conn.close()
        self.assertEqual(self.upstream.received[1]['api-key'], 'real-upstream-key')
        self.assertNotIn('authorization', self.upstream.received[1])
    def test_models_query(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port, timeout=2)
        conn.request('GET', '/v1/models?test=1')
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        res.read()
        self.assertEqual(self.upstream.received[0], '/v1/models?test=1')
        conn.close()
    def test_invalid_json(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port, timeout=2)
        conn.request('POST', '/responses', b'{bad')
        res = conn.getresponse()
        self.assertEqual(res.status, 400)
        res.read(); conn.close()
    def test_azure_override_path(self):
        cfg = Config('https://example.openai.azure.com', responses_path='/openai/responses?api-version=2025-04-01-preview')
        self.assertEqual(upstream_target(cfg, '/v1/responses')[1], '/openai/responses?api-version=2025-04-01-preview')


def run_probe(base_url, model):
    import getpass
    import sys
    base = urlsplit(base_url)
    if base.scheme not in ('http', 'https') or not base.hostname:
        raise ValueError('Probe base must be an http(s) URL')
    key = (os.getenv('PROBE_API_KEY') or os.getenv('PROXY_API_KEY', PROXY_API_KEY)
           or os.getenv('UPSTREAM_API_KEY', UPSTREAM_API_KEY))
    if not key and sys.stdin.isatty():
        key = getpass.getpass('API key for probe (blank if upstream key is configured in server): ')
    success = True
    for stream in (False, True):
        conn_type = http.client.HTTPSConnection if base.scheme == 'https' else http.client.HTTPConnection
        conn = conn_type(base.hostname, base.port, timeout=float(os.getenv('UPSTREAM_TIMEOUT_SECONDS', UPSTREAM_TIMEOUT_SECONDS)))
        try:
            payload = {'model': model, 'input': 'Reply with OK only.', 'stream': stream,
                       'stream_options': {'include_usage': True}}
            headers = {'Content-Type': 'application/json'}
            if key:
                headers['Authorization'] = 'Bearer ' + key
            conn.request('POST', base.path.rstrip('/') + '/responses', json.dumps(payload), headers)
            res = conn.getresponse()
            print('stream=', stream, 'status=', res.status,
                  'sanitized=', res.getheader('X-Proxy-Sanitized-Count'))
            if res.status >= 400:
                success = False
                print(res.read(8192).decode('utf-8', errors='replace'))
            elif stream:
                count = sum(1 for line in res if line.startswith(b'event:'))
                print('SSE event labels:', count)
            else:
                print(res.read().decode('utf-8', errors='replace'))
        finally:
            conn.close()
    return 0 if success else 1


def main():
    import sys
    parser = argparse.ArgumentParser(description='Single-file Responses sanitizing proxy (Python 3.11+)')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--self-test', action='store_true', help='Run embedded local tests; no external API calls')
    mode.add_argument('--probe', action='store_true', help='Test a running proxy with two API requests')
    mode.add_argument('--instructions', action='store_true', help='Print embedded Traditional Chinese instructions')
    parser.add_argument('--upstream', default=os.getenv('UPSTREAM_BASE_URL', UPSTREAM_BASE_URL))
    parser.add_argument('--host', default=os.getenv('PROXY_HOST', PROXY_HOST))
    parser.add_argument('--port', type=int, default=int(os.getenv('PROXY_PORT', PROXY_PORT)))
    parser.add_argument('--base', default='http://127.0.0.1:4004', help='Proxy base URL for --probe')
    parser.add_argument('--model', default='gpt-6.1-sol', help='Model ID for --probe')
    args = parser.parse_args()
    if args.instructions:
        print(__doc__)
        return 0
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProxyTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if args.probe:
        try:
            return run_probe(args.base, args.model)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            print('Probe failed:', type(exc).__name__, file=sys.stderr)
            return 1
    if not args.upstream and sys.stdin.isatty():
        args.upstream = input('Upstream AI Hub URL: ').strip()
    if not args.upstream:
        parser.error('Set UPSTREAM_BASE_URL in this file/environment or use --upstream URL')
    try:
        cfg = Config(
            upstream=args.upstream,
            api_key=os.getenv('UPSTREAM_API_KEY', UPSTREAM_API_KEY),
            auth_header=os.getenv('UPSTREAM_AUTH_HEADER', UPSTREAM_AUTH_HEADER),
            local_key=os.getenv('PROXY_API_KEY', PROXY_API_KEY),
            timeout=float(os.getenv('UPSTREAM_TIMEOUT_SECONDS', UPSTREAM_TIMEOUT_SECONDS)),
            ca_file=os.getenv('UPSTREAM_CA_FILE', UPSTREAM_CA_FILE),
            responses_path=os.getenv('UPSTREAM_RESPONSES_PATH', UPSTREAM_RESPONSES_PATH),
        )
    except ValueError as exc:
        parser.error(str(exc))
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    server = ProxyServer((args.host, args.port), cfg)
    LOG.info('Proxy listening on %s:%s', args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())