from contextlib import closing
import importlib.util
import io
import json
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('trusosanta', Path(__file__).resolve().parents[1] / 'trusosanta_server.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

class Wire:
    def __init__(self, request):
        self.request = request
        self.response = bytearray()
    def makefile(self, *_): return io.BytesIO(self.request)
    def sendall(self, chunk): self.response.extend(chunk)
    def settimeout(self, _): pass

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = app.DEADLINE - 1
        self.db = app.Store(Path(self.temp.name) / 'entries.sqlite', clock=lambda: self.now)
    def tearDown(self): self.temp.cleanup()
    def create(self, name='Саша', size='M', key=None):
        key = key or secrets.token_hex(32)
        self.db.save(key, {'name': name, 'size': size})
        return key
    def error(self, status, func, *args, **kwargs):
        with self.assertRaises(app.APIError) as raised: func(*args, **kwargs)
        self.assertEqual(raised.exception.status, status)
    def request(self, method, path, token='', data=None, extra=''):
        payload = json.dumps(data).encode() if data is not None else b''
        headers = f'{method} {path} HTTP/1.1\r\nHost: localhost:8765\r\nConnection: close\r\n{extra}'
        if token: headers += f'Authorization: Bearer {token}\r\n'
        if data is not None: headers += f'Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n'
        wire = Wire(headers.encode() + b'\r\n' + payload)
        app.Handler(wire, ('127.0.0.1', 1), SimpleNamespace(store=self.db, public_origin=''))
        head, body = bytes(wire.response).split(b'\r\n\r\n', 1)
        return int(head.split()[1]), head, body
    def test_edit_delete_and_restart(self):
        key = self.create()
        self.db.save(key, {'name': 'Вика', 'size': '48–50 RU'}, editing=True)
        reboot = app.Store(self.db.path, clock=lambda: self.now)
        self.assertEqual(reboot.me(key)['entry'], {'name': 'Вика', 'size': '48–50 RU'})
        self.assertIsNone(reboot.me(key)['recipient'])
        reboot.delete(key); reboot.delete(key)
        self.error(404, reboot.me, key)
    def test_private_keys_and_public_state(self):
        first = self.create('Аня'); second = self.create('Борис', 'XL')
        self.assertNotIn('Борис', json.dumps(self.db.me(first), ensure_ascii=False))
        self.assertNotIn('entry', self.db.status())
        self.error(401, self.db.me, '')
        self.error(404, self.db.me, secrets.token_hex(32))
        raw = self.db.path.read_bytes()
        self.assertNotIn(first.encode(), raw); self.assertNotIn(second.encode(), raw)
    def test_retry_concurrent_registration(self):
        key = secrets.token_hex(32)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: self.create(key=key), range(12)))
        with closing(sqlite3.connect(self.db.path)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM participants').fetchone()[0], 1)
    def test_draw_concurrent_and_immutable(self):
        keys = [self.create(f'Участник {n}') for n in range(15)]
        self.assertIsNone(self.db.me(keys[0])['recipient'])
        self.now = app.DEADLINE
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(self.db.me, keys * 3))
        recipients = set()
        for n, key in enumerate(keys):
            item = results[n]
            self.assertEqual(item['status'], 'drawn')
            self.assertNotEqual(item['entry']['name'], item['recipient']['name'])
            recipients.add(item['recipient']['name'])
            self.assertEqual(item, results[n+15])
            self.assertEqual(item, results[n+30])
            self.assertEqual(item, self.db.me(key))
        self.assertEqual(len(recipients), len(keys))
        reboot = app.Store(self.db.path, clock=lambda: self.now)
        self.assertEqual(reboot.me(keys[0]), results[0])
    def test_deadline_rejects_mutations_but_allows_post_retry(self):
        keys = [self.create(str(n)) for n in range(3)]
        self.now = app.DEADLINE
        self.error(409, self.db.save, secrets.token_hex(32), {'name': 'late', 'size': 'L'})
        self.error(409, self.db.save, keys[0], {'name': 'edit', 'size': 'S'}, editing=True)
        self.error(409, self.db.delete, keys[0])
        retry = self.db.save(keys[0], {'name': 'ignored', 'size': 'M'})
        self.assertEqual(retry['entry']['name'], '0')
        self.assertEqual(retry['status'], 'drawn')
    def test_too_few_finalizes_without_assignments(self):
        key = self.create(); self.create()
        self.now = app.DEADLINE
        self.assertEqual(self.db.status()['status'], 'insufficient')
        self.assertIsNone(self.db.me(key)['recipient'])
        self.error(409, self.db.save, secrets.token_hex(32), {'name': 'late', 'size': 'L'})
    def test_payload_validation(self):
        for data in ({'name': ' ', 'size': 'M'}, {'name': 'x'*61, 'size': 'M'},
                     {'name': 4, 'size': 'M'}, {'name': 'a', 'size': '\n'}, [], None):
            self.error(400, self.db.save, secrets.token_hex(32), data)
    def test_http_flow_and_headers(self):
        key = secrets.token_hex(32)
        status, headers, body = self.request('POST', '/api/entries', key, {'name': '<b>Оля</b>', 'size': 'L'})
        self.assertEqual(status, 200)
        self.assertIn(b'Cache-Control: no-store, private', headers)
        self.assertNotIn(key.encode(), body)
        self.assertEqual(json.loads(body)['entry']['name'], '<b>Оля</b>')
        self.assertEqual(self.request('GET', '/api/me')[0], 401)
        self.assertEqual(self.request('GET', '/api/me', key)[0], 200)
        self.assertEqual(self.request('PATCH', '/api/me', key, {'name': 'Оля', 'size': 'XL'})[0], 200)
        self.assertEqual(self.request('DELETE', '/api/me', key)[0], 200)
        self.assertEqual(self.request('GET', '/api/me', key)[0], 404)
    def test_http_cannot_read_files_or_cross_origin(self):
        for path in ('/trusosanta_server.py', '/.trusosanta-data/participants.sqlite3', '/../../etc/passwd', '/api/participants'):
            self.assertEqual(self.request('GET', path)[0], 404)
        self.assertEqual(self.request('POST', '/api/entries', secrets.token_hex(32), {'name': 'X', 'size': 'L'}, 'Origin: https://other.example\r\n')[0], 403)
        status, headers, body = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'thong', body)
        self.assertNotIn('Что умеет эта HTML-версия?'.encode(), body)
        self.assertIn(b"frame-ancestors 'none'", headers)

if __name__ == '__main__':
    unittest.main(verbosity=2)
