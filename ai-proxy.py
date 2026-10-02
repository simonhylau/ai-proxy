#!/usr/bin/env python3
# -*- coding: utf-8 -*-
UPSTREAM_BASE_URL = ""
UPSTREAM_API_KEY = ""
UPSTREAM_AUTH_HEADER = "authorization"
PROXY_API_KEY = ""
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 4004
UPSTREAM_TIMEOUT_SECONDS = 300
UPSTREAM_CA_FILE = ""
UPSTREAM_RESPONSES_PATH = ""

import argparse
import copy
import hmac
import http.client
import json
import logging
import os
import ssl
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

LOG = logging.getLogger('proxy')


def sanitize(payload):
    """Only remove Chat Completions include_usage from Responses payloads."""
    result = copy.deepcopy(payload)
    removed = 0
    options = result.get('stream_options')
    if isinstance(options, dict) and 'include_usage' in options:
        del options['include_usage']
        removed += 1
        if not options:
            del result['stream_options']
    # Some intermediaries serialize this as a flattened parameter.
    if 'stream_options.include_usage' in result:
        del result['stream_options.include_usage']
        removed += 1
    return result, removed


@dataclass
class Config:
    upstream: str
    api_key: str = ''
    auth_header: str = 'authorization'
    local_key: str = ''
    timeout: float = 300
    ca_file: str = ''
    responses_path: str = ''
    max_body: int = 32 * 1024 * 1024

    def __post_init__(self):
        parsed = urlsplit(self.upstream)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('UPSTREAM_BASE_URL must be an http(s) URL')
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Do not put credentials or fragments in UPSTREAM_BASE_URL')
        if self.auth_header.lower() not in ('authorization', 'api-key'):
            raise ValueError('UPSTREAM_AUTH_HEADER must be authorization or api-key')
        if self.local_key and not self.api_key:
            raise ValueError('PROXY_API_KEY requires UPSTREAM_API_KEY to avoid forwarding the local key')
        if self.responses_path and not self.responses_path.startswith('/'):
            raise ValueError('UPSTREAM_RESPONSES_PATH must start with /')


def upstream_target(config, incoming):
    base = urlsplit(config.upstream)
    src = urlsplit(incoming)
    path = src.path
    if path == '/v1' or path.startswith('/v1/'):
        path = path[3:] or '/'
    if path == '/responses' and config.responses_path:
        override = urlsplit(config.responses_path)
        target_path = override.path
        query = '&'.join(q for q in (base.query, override.query, src.query) if q)
    else:
        target_path = base.path.rstrip('/') + path
        query = '&'.join(q for q in (base.query, src.query) if q)
    return base, urlunsplit(('', '', target_path, query, ''))


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, config):
        self.config = config
        super().__init__(address, ProxyHandler)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass  # Never log bodies, keys, URLs, or query strings.

    def local_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def do_DELETE(self):
        self.forward()

    def forward(self):
        cfg = self.server.config
        started = time.monotonic()
        connection = None
        headers_sent = False
        removed = 0
        path = urlsplit(self.path).path
        normalized = path[3:] if path.startswith('/v1/') else path
        if path == '/health' and self.command == 'GET':
            self.local_json(200, {'status': 'ok', 'version': '1.1.0', 'mode': 'sanitize-responses'})
            return
        if cfg.local_key and not hmac.compare_digest(
            self.headers.get('Authorization', ''), 'Bearer ' + cfg.local_key
        ):
            self.close_connection = True
            self.local_json(401, {'error': {'message': 'Invalid proxy API key'}})
            return
        if not (normalized in ('/models', '/responses', '/chat/completions') or normalized.startswith('/responses/')):
            self.close_connection = True
            self.local_json(404, {'error': {'message': 'Supported routes: /models, /responses, /responses/*, /chat/completions (optional /v1 prefix)'}})
            return
        if '..' in normalized or '%' in normalized or '\\' in normalized:
            self.close_connection = True
            self.local_json(400, {'error': {'message': 'Invalid path'}})
            return
        try:
            if self.headers.get('Transfer-Encoding'):
                self.close_connection = True
                self.local_json(411, {'error': {'message': 'Send JSON with Content-Length, not chunked upload'}})
                return
            size = int(self.headers.get('Content-Length', '0'))
            if size < 0 or size > cfg.max_body:
                self.close_connection = True
                self.local_json(413, {'error': {'message': 'Request body exceeds limit'}})
                return
            body = self.rfile.read(size)
            if self.command == 'POST' and normalized in ('/responses', '/responses/compact'):
                try:
                    payload = json.loads(body)
                    if not isinstance(payload, dict):
                        raise ValueError()
                except (ValueError, UnicodeDecodeError):
                    self.local_json(400, {'error': {'message': 'Expected a JSON object'}})
                    return
                payload, removed = sanitize(payload)
                body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            base, target = upstream_target(cfg, self.path)
            outgoing = {}
            for name in ('authorization', 'api-key', 'content-type', 'accept', 'openai-organization', 'openai-project', 'openai-beta', 'x-request-id'):
                value = self.headers.get(name)
                if value is not None:
                    outgoing[name] = value
            if cfg.api_key:
                outgoing.pop('authorization', None)
                outgoing.pop('api-key', None)
                outgoing[cfg.auth_header.lower()] = ('Bearer ' if cfg.auth_header.lower() == 'authorization' else '') + cfg.api_key
            outgoing['accept-encoding'] = 'identity'
            if self.command == 'POST':
                outgoing['content-type'] = 'application/json'
            if base.scheme == 'https':
                context = ssl.create_default_context(cafile=cfg.ca_file or None)
                connection = http.client.HTTPSConnection(base.hostname, base.port, timeout=cfg.timeout, context=context)
            else:
                connection = http.client.HTTPConnection(base.hostname, base.port, timeout=cfg.timeout)
            connection.request(self.command, target, body=body or None, headers=outgoing)
            upstream = connection.getresponse()
            self.send_response(upstream.status)
            blocked = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'server', 'date'}
            blocked.update(v.strip().lower() for v in upstream.getheader('Connection', '').split(','))
            for name, value in upstream.getheaders():
                if name.lower() not in blocked:
                    self.send_header(name, value)
            self.send_header('X-Proxy-Sanitized-Count', str(removed))
            self.send_header('X-Accel-Buffering', 'no')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            headers_sent = True
            # read1 avoids waiting to fill a large buffer; each upstream piece is flushed.
            while True:
                chunk = upstream.read1(65536)
                if not chunk:
                    break
                self.wfile.write(('%X\r\n' % len(chunk)).encode() + chunk + b'\r\n')
                self.wfile.flush()
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
            LOG.info('method=%s route=%s status=%s sanitized=%s duration=%.3fs', self.command, normalized.split('/')[1], upstream.status, removed, time.monotonic() - started)
            if upstream.status == 400 and normalized.startswith('/responses'):
                LOG.warning('If upstream still rejects include_usage, inspect LiteLLM outgoing body; sanitizing a request BEFORE LiteLLM cannot remove parameters LiteLLM injects later.')
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except (OSError, http.client.HTTPException, ValueError) as exc:
            LOG.error('Upstream request failed: %s', type(exc).__name__)
            self.close_connection = True
            if not headers_sent:
                self.local_json(502, {'error': {'message': 'Upstream connection failed; check URL, VPN, certificate and timeout', 'type': type(exc).__name__}})
        finally:
            if connection:
                connection.close()



# Embedded local tests
import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIRST = b'event: response.output_text.delta\ndata: {"delta":"OK"}\n\n'
LAST = b'event: response.completed\ndata: {"response":{"usage":{"input_tokens":2}}}\n\n'

class Upstream(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_): pass
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        self.server.received = (self.path, dict(self.headers), payload)
        if payload.get('stream'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(FIRST + LAST)))
            self.end_headers()
            self.wfile.write(FIRST)
            self.wfile.flush()
            self.server.release.wait(3)
            self.wfile.write(LAST)
            self.wfile.flush()
        else:
            body = b'{"error":{"message":"Unknown parameter: stream_options.include_usage"}}' if payload.get('fail') else b'{"id":"resp_test","usage":{"input_tokens":2}}'
            self.send_response(400 if payload.get('fail') else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('x-request-id', 'upstream-test')
            self.end_headers()
            self.wfile.write(body)
    def do_GET(self):
        self.server.received = (self.path, dict(self.headers), None)
        body = b'{"data":[{"id":"gpt-6.1-sol"}]}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        self.upstream.daemon_threads = True
        self.upstream.release = threading.Event()
        self.proxy = ProxyServer(('127.0.0.1', 0), Config('http://127.0.0.1:%s/v1' % self.upstream.server_port))
        self.threads = []
        for server in (self.upstream, self.proxy):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)
    def tearDown(self):
        self.upstream.release.set()
        for server in (self.proxy, self.upstream):
            server.shutdown()
            server.server_close()
        for thread in self.threads: thread.join(2)
    def request(self, payload, path='/v1/responses', key='client-key'):
        conn = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port, timeout=2)
        conn.request('POST', path, json.dumps(payload), {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
        return conn, conn.getresponse()
    def test_sanitize_preserves_other_options(self):
        src = {'stream_options': {'include_usage': True, 'include_obfuscation': False}, 'stream': True}
        clean, removed = sanitize(src)
        self.assertEqual(removed, 1)
        self.assertEqual(clean['stream_options'], {'include_obfuscation': False})
        self.assertIn('include_usage', src['stream_options'])
    def test_tools_and_auth_preserved(self):
        payload = {'model': 'gpt-6.1-sol', 'input': [{'type': 'function_call_output', 'call_id': 'call_1', 'output': '成功'}], 'tools': [{'type': 'function', 'name': 'test', 'parameters': {'type': 'object'}}], 'reasoning': {'effort': 'low'}, 'stream_options': {'include_usage': True}}
        conn, res = self.request(payload)
        self.assertEqual(res.status, 200)
        self.assertEqual(res.getheader('X-Proxy-Sanitized-Count'), '1')
        self.assertEqual(res.getheader('x-request-id'), 'upstream-test')
        res.read(); conn.close()
        path, headers, sent = self.upstream.received
        self.assertEqual(path, '/v1/responses')
        self.assertEqual(headers['authorization'], 'Bearer client-key')
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
