from functools import wraps
from hashlib import sha256
import secrets
import time

from flask import Blueprint, current_app, g, jsonify, request, abort
from werkzeug.security import check_password_hash

from .store import database

bp = Blueprint('auth', __name__)


def resolve_actor():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ')
    if not token or len(token) > 256:
        return
    digest = sha256(token.encode()).hexdigest()
    with database(current_app.extensions['lab']) as db:
        user = db.execute('SELECT users.id,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?', (digest, time.time())).fetchone()
        if user:
            g.actor_id, g.actor_role = user['id'], user['role']
            return
        device = db.execute('SELECT id FROM devices WHERE token_hash=?', (digest,)).fetchone()
        if device:
            g.actor_id, g.actor_role = device['id'], 'device'


def require_roles(*roles):
    def decorate(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if g.actor_role == 'unauthenticated':
                abort(401)
            if g.actor_role not in roles:
                abort(403)
            return function(*args, **kwargs)
        return wrapper
    return decorate


def body_object():
    body = request.get_json()
    if not isinstance(body, dict):
        abort(400, 'Expected a JSON object')
    return body


def text_field(body, key, maximum=128):
    value = body.get(key)
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        abort(400, f'Invalid {key}')
    return value


@bp.post('/api/auth/login')
def login():
    cfg = current_app.extensions['lab']
    body = body_object()
    user = text_field(body, 'username').strip().lower()
    password = text_field(body, 'password', 256)
    g.actor_id = user
    g.action, g.outcome = 'login_failure', 'failure'
    with database(cfg) as db:
        row = db.execute('SELECT * FROM users WHERE id=?', (user,)).fetchone()
        if not row or not check_password_hash(row['password_hash'], password):
            abort(401)
        current_app.extensions['emit']('operation_intent', 'success', 200, {'operation': 'login_success'})
        token = secrets.token_urlsafe(32)
        db.execute('INSERT INTO sessions VALUES (?,?,?)', (sha256(token.encode()).hexdigest(), user, time.time() + cfg.session_ttl_s))
    g.actor_role = row['role']
    g.action, g.outcome = 'login_success', 'success'
    return jsonify(token=token, expires_in=cfg.session_ttl_s)
