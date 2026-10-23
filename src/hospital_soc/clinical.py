import math
import sqlite3
from uuid import uuid4

from flask import Blueprint, abort, current_app, g, jsonify

from .auth import body_object, require_roles, text_field
from .audit import utc_now
from .store import database

bp = Blueprint('clinical', __name__)


def intent(action):
    current_app.extensions['emit']('operation_intent', 'success', 200, {'operation': action})


@bp.get('/api/records/<patient_id>')
@require_roles('clinician', 'nurse')
def record(patient_id):
    cfg = current_app.extensions['lab']
    with database(cfg) as db:
        row = db.execute('SELECT * FROM patients WHERE id=?', (patient_id,)).fetchone()
        if not row:
            abort(404)
        assigned = db.execute('SELECT 1 FROM assignments WHERE user_id=? AND patient_id=?', (g.actor_id, patient_id)).fetchone()
    g.details.update(patient_id=patient_id, care_scope='assigned' if assigned else 'unassigned')
    if not assigned and cfg.policy_mode == 'enforce':
        g.action = 'record_denied'
        abort(403)
    g.action = 'record_read'
    return jsonify(dict(row))


@bp.post('/api/lab/orders')
@require_roles('clinician')
def order():
    body = body_object()
    patient, test = text_field(body, 'patient_id'), text_field(body, 'test')
    identity = str(uuid4())
    with database(current_app.extensions['lab']) as db:
        if not db.execute('SELECT 1 FROM patients WHERE id=?', (patient,)).fetchone():
            abort(404)
        intent('lab_order_created')
        db.execute('INSERT INTO lab_orders VALUES (?,?,?,?)', (identity, patient, test, g.actor_id))
    g.action = 'lab_order_created'
    g.details.update(patient_id=patient, order_id=identity)
    return jsonify(order_id=identity), 201


@bp.post('/api/lab/results')
@require_roles('laboratory')
def result():
    body = body_object()
    order_id, value = text_field(body, 'order_id'), text_field(body, 'value', 512)
    identity = str(uuid4())
    with database(current_app.extensions['lab']) as db:
        if not db.execute('SELECT 1 FROM lab_orders WHERE id=?', (order_id,)).fetchone():
            abort(404)
        if db.execute('SELECT 1 FROM lab_results WHERE order_id=?', (order_id,)).fetchone():
            abort(409)
        intent('lab_result_created')
        db.execute('INSERT INTO lab_results VALUES (?,?,?)', (identity, order_id, value))
    g.action = 'lab_result_created'
    g.details.update(order_id=order_id)
    return jsonify(result_id=identity), 201


@bp.post('/api/devices/<device_id>/telemetry')
@require_roles('device')
def telemetry(device_id):
    if g.actor_id != device_id:
        abort(403)
    body = body_object()
    value = body.get('value')
    if type(value) not in (float, int) or not math.isfinite(value) or not -10000 <= value <= 10000:
        abort(400)
    unit = text_field(body, 'unit', 32)
    with database(current_app.extensions['lab']) as db:
        intent('device_telemetry')
        db.execute('INSERT INTO telemetry(device_id,value,unit,received_at) VALUES (?,?,?,?)', (device_id, value, unit, utc_now()))
    g.action = 'device_telemetry'
    g.details['device_id'] = device_id
    return jsonify(accepted=True), 201
