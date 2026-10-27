#!/usr/bin/env python3
"""Standalone registration server. Python 3.10+, no external dependencies."""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from urllib.parse import urlsplit

DEADLINE = datetime.fromisoformat('2026-11-05T19:19:00+03:00').timestamp()
ROOT = Path(__file__).resolve().parent


class APIError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def key_hash(token):
    if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{64}', token):
        raise APIError(401, 'Нужна личная секретная ссылка.')
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def validate_entry(data):
    if not isinstance(data, dict):
        raise APIError(400, 'Нужны имя и размер.')
    clean = {}
    for key, limit in (('name', 60), ('size', 40)):
        value = data.get(key)
        if not isinstance(value, str):
            raise APIError(400, 'Нужны имя и размер.')
        value = value.strip()
        if not value or len(value) > limit or any(ord(c) < 32 for c in value):
            raise APIError(400, 'Проверь имя (до 60 символов) и размер (до 40 символов).')
        clean[key] = value
    return clean


class Store:
    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('PRAGMA foreign_keys=ON')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS event (
                    id INTEGER PRIMARY KEY CHECK (id=1),
                    status TEXT NOT NULL CHECK (status IN ('open','drawn','insufficient'))
                );
                INSERT OR IGNORE INTO event VALUES (1, 'open');
                CREATE TABLE IF NOT EXISTS participants (
                    id INTEGER PRIMARY KEY,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    size TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assignments (
                    giver INTEGER PRIMARY KEY REFERENCES participants(id),
                    receiver INTEGER UNIQUE NOT NULL REFERENCES participants(id),
                    CHECK (giver<>receiver)
                );
            ''')
        os.chmod(self.path, 0o600)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            # Serialize the deadline check, mutations and the entire draw.
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def advance(self, db):
        now = self.clock()
        status = db.execute('SELECT status FROM event WHERE id=1').fetchone()[0]
        if status == 'open' and now >= DEADLINE:
            ids = [r[0] for r in db.execute('SELECT id FROM participants ORDER BY id')]
            if len(ids) < 3:
                status = 'insufficient'
            else:
                secrets.SystemRandom().shuffle(ids)
                db.executemany('INSERT INTO assignments(giver,receiver) VALUES (?,?)',
                               [(giver, ids[(i + 1) % len(ids)]) for i, giver in enumerate(ids)])
                status = 'drawn'
            db.execute('UPDATE event SET status=? WHERE id=1', (status,))
        return {'status': status, 'deadline': int(DEADLINE * 1000), 'serverTime': int(now * 1000)}

    def status(self):
        with self.transaction() as db:
            return self.advance(db)

    @staticmethod
    def person(db, digest):
        row = db.execute('SELECT id,name,size FROM participants WHERE key_hash=?', (digest,)).fetchone()
        if row is None:
            raise APIError(404, 'Заявка по этой ссылке не найдена.')
        return row

    @staticmethod
    def snapshot(db, person, state):
        recipient = None
        if state['status'] == 'drawn':
            row = db.execute('''SELECT p.name,p.size FROM assignments a
                                JOIN participants p ON p.id=a.receiver WHERE a.giver=?''',
                             (person['id'],)).fetchone()
            recipient = dict(row) if row else None
        return {**state, 'entry': {'name': person['name'], 'size': person['size']}, 'recipient': recipient}

    def me(self, token):
        digest = key_hash(token)
        with self.transaction() as db:
            state = self.advance(db)
            return self.snapshot(db, self.person(db, digest), state)

    def save(self, token, data, editing=False):
        digest = key_hash(token)
        clean = validate_entry(data)
        with self.transaction() as db:
            state = self.advance(db)
            existing = db.execute('SELECT id,name,size FROM participants WHERE key_hash=?', (digest,)).fetchone()
            # Retrying an accepted POST is safe, including after the deadline.
            if existing is not None and not editing:
                return self.snapshot(db, existing, state)
            if state['status'] != 'open':
                db.commit()  # Preserve a draw triggered by this request.
                raise APIError(409, 'Приём заявок завершён. Изменения больше не принимаются.')
            if editing:
                self.person(db, digest)
                db.execute('UPDATE participants SET name=?,size=? WHERE key_hash=?',
                           (clean['name'], clean['size'], digest))
            else:
                if db.execute('SELECT COUNT(*) FROM participants').fetchone()[0] >= 500:
                    raise APIError(409, 'Лимит участников достигнут.')
                db.execute('INSERT INTO participants(key_hash,name,size) VALUES (?,?,?)',
                           (digest, clean['name'], clean['size']))
            return self.snapshot(db, self.person(db, digest), state)

    def delete(self, token):
        digest = key_hash(token)
        with self.transaction() as db:
            state = self.advance(db)
            if state['status'] != 'open':
                db.commit()
                raise APIError(409, 'Приём заявок завершён. Удаление больше недоступно.')
            # Deletion is idempotent: a retried request has the same outcome.
            db.execute('DELETE FROM participants WHERE key_hash=?', (digest,))
            return {**state, 'entry': None, 'recipient': None}


class Handler(BaseHTTPRequestHandler):
    server_version = 'Trusosanta'
    sys_version = ''

    def log_message(self, *_):
        # Do not log request URLs, authorization headers or participant records.
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def send(self, status, body, content_type='application/json; charset=utf-8'):
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store, private')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def token(self):
        header = self.headers.get('Authorization', '')
        return header[7:] if header.startswith('Bearer ') else ''

    def read_json(self):
        if self.headers.get_content_type() != 'application/json':
            raise APIError(415, 'Ожидается JSON.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise APIError(400, 'Некорректный запрос.')
        if not 0 < length <= 4096:
            raise APIError(413, 'Слишком большой или пустой запрос.')
        try:
            return json.loads(self.rfile.read(length).decode('utf-8'))
        except (ValueError, UnicodeError):
            raise APIError(400, 'Не удалось прочитать заявку.')

    def route(self):
        try:
            origin = self.headers.get('Origin')
            allowed = self.server.public_origin or 'http://' + self.headers.get('Host', '')
            if origin and origin != allowed:
                raise APIError(403, 'Запрос с другого сайта запрещён.')
            if self.headers.get('Sec-Fetch-Site') == 'cross-site' and self.path.startswith('/api/'):
                raise APIError(403, 'Запрос с другого сайта запрещён.')
            path = urlsplit(self.path).path
            if self.command in ('GET', 'HEAD') and path in ('/', '/trusosanta.html'):
                self.send(200, (ROOT / 'index.html').read_bytes(), 'text/html; charset=utf-8')
                return
            if self.command in ('GET','HEAD') and path == '/config.js':
                self.send(200, (ROOT / 'config.js').read_bytes(), 'text/javascript; charset=utf-8')
                return
            if self.command == 'GET' and path == '/api/status':
                result = self.server.store.status()
            elif self.command == 'GET' and path == '/api/me':
                result = self.server.store.me(self.token())
            elif self.command == 'POST' and path == '/api/entries':
                result = self.server.store.save(self.token(), self.read_json())
            elif self.command == 'PATCH' and path == '/api/me':
                result = self.server.store.save(self.token(), self.read_json(), editing=True)
            elif self.command == 'DELETE' and path == '/api/me':
                result = self.server.store.delete(self.token())
            else:
                raise APIError(404, 'Страница не найдена.')
            self.send(200, result)
        except APIError as error:
            self.send(error.status, {'error': str(error)})
        except (ConnectionError, TimeoutError):
            pass
        except (sqlite3.Error, OSError):
            self.send(503, {'error': 'Хранилище временно недоступно. Попробуй ещё раз.'})

    do_GET = route
    do_HEAD = route
    do_POST = route
    do_PATCH = route
    do_DELETE = route


def main():
    parser = argparse.ArgumentParser(description='Тайный Трусосанта: регистрация и жеребьёвка.')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--data', type=Path, default=ROOT / '.trusosanta-data' / 'participants.sqlite3')
    parser.add_argument('--public-origin', default='', help='Exact HTTPS origin when placed behind a trusted reverse proxy.')
    args = parser.parse_args()
    if args.public_origin and (not args.public_origin.startswith('https://') or urlsplit(args.public_origin).path):
        parser.error('--public-origin must be an HTTPS origin without a path or trailing slash')
    os.umask(0o077)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.store = Store(args.data)
    server.public_origin = args.public_origin
    print(f'Тайный Трусосанта: http://{args.host}:{args.port}', flush=True)
    print('Для остановки нажми Ctrl+C. Заявки сохранятся.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
