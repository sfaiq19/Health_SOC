import sqlite3
import time
from uuid import UUID, uuid4

from flask import Flask, g, request, jsonify
from werkzeug.exceptions import HTTPException

from .audit import AuditWriter
from .auth import bp as auth, resolve_actor
from .clinical import bp as clinical
from .config import LabConfig
from .contracts import AuditEvent
from .documents import bp as documents
from .exports import bp as exports
from .store import validate_runtime, database


def create_app(config: LabConfig) -> Flask:
    validate_runtime(config)
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 128 * 1024
    app.extensions['lab'] = config
    app.extensions['audit'] = AuditWriter(config.root / 'logs/app.jsonl')

    def emit(action, outcome, status, details):
        event = AuditEvent(action, outcome, g.run_id, g.request_id, g.actor_id, g.actor_role,
                           request.remote_addr or 'unknown', status, int((time.monotonic() - g.started) * 1000), details)
        app.extensions['audit'].write(event)
    app.extensions['emit'] = emit

    @app.before_request
    def initialize():
        g.started = time.monotonic()
        g.run_id, g.request_id = str(uuid4()), str(uuid4())
        g.actor_id, g.actor_role = 'anonymous', 'unauthenticated'
        g.action, g.outcome, g.details = 'request_rejected', 'success', {}
        for header, attribute in [('X-Lab-Run-ID', 'run_id'), ('X-Request-ID', 'request_id')]:
            value = request.headers.get(header)
            if not value and request.path == '/health':
                continue
            try:
                if not value or str(UUID(value)) != value:
                    raise ValueError()
            except (ValueError, AttributeError):
                from flask import abort
                abort(400, 'Controlled requests require canonical UUID correlation headers')
            setattr(g, attribute, value)
        resolve_actor()

    @app.after_request
    def audit_response(response):
        outcome = g.outcome if response.status_code < 400 else ('denied' if response.status_code in (401, 403) else 'failure')
        if response.status_code >= 400 and g.action in {'record_read', 'document_update', 'lab_order_created', 'lab_result_created'}:
            g.action = 'request_rejected'
        try:
            emit(g.action, outcome, response.status_code, g.details)
        except (OSError, ValueError):
            # An intent may already exist for a mutation. Never return success without its result audit.
            response = jsonify(error='Audit storage unavailable; operation outcome requires reconciliation')
            response.status_code = 503
        response.headers['X-Request-ID'] = g.request_id
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code

    @app.errorhandler(OSError)
    def storage_error(error):
        return jsonify(error='Storage unavailable; check audit and transaction state'), 503

    @app.errorhandler(sqlite3.Error)
    def database_error(error):
        return jsonify(error='Database operation failed'), 503

    @app.get('/health')
    def health():
        with database(config) as db:
            db.execute('SELECT count(*) FROM patients').fetchone()
        g.action = 'service_heartbeat'
        return jsonify(status='ok', service='hospital-lab', policy_mode=config.policy_mode)

    app.register_blueprint(auth)
    app.register_blueprint(clinical)
    app.register_blueprint(documents)
    app.register_blueprint(exports)
    return app
