from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sqlite3

from werkzeug.security import generate_password_hash

from .config import LabConfig

MARKER = '.healthcare-soc-runtime'
ROLES = {'clinician': 'clinician', 'nurse': 'nurse', 'lab-technician': 'laboratory',
         'records-clerk': 'records', 'document-editor': 'document-editor', 'administrator': 'administrator',
         'lab-service': 'laboratory'}


def reject_links(path: Path) -> None:
    for current in [path, *path.parents]:
        if current.is_symlink() or current.is_junction():
            raise ValueError('Runtime and document paths cannot contain links or junctions')
        if current.is_file() and current.stat().st_nlink != 1:
            raise ValueError('Runtime files must not be hard linked')


def validate_runtime(config: LabConfig) -> Path:
    root = config.root
    reject_links(root)
    for name in [MARKER, 'hospital.sqlite', 'secrets.json', 'seed-manifest.json', 'logs', 'logs/app.jsonl']:
        reject_links(root / name)
    if not (root / MARKER).is_file() or (root / MARKER).read_text() != 'healthcare-soc-runtime-v1':
        raise ValueError('Runtime marker missing or invalid')
    return root


@contextmanager
def database(config: LabConfig):
    db = sqlite3.connect(validate_runtime(config) / 'hospital.sqlite', timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        with db:
            yield db
    finally:
        db.close()


def document_seed(document_id: str, seed: int) -> bytes:
    return (f'SYNTHETIC {document_id} seed={seed}\n'.encode() + b'x' * 1024)[:1024]


def seed_lab(config: LabConfig, seed: int) -> dict:
    root = config.root
    reject_links(root)
    repository = Path(__file__).resolve().parents[2]
    if root == Path(root.anchor) or root == Path.home() or root.is_relative_to(repository):
        raise ValueError('Runtime must be a dedicated directory outside source')
    if root.exists() and any(root.iterdir()):
        validate_runtime(config)
        raise ValueError('Existing runtime must be restored explicitly, not reseeded')
    root.mkdir(parents=True, exist_ok=True)
    (root / MARKER).write_text('healthcare-soc-runtime-v1')
    (root / 'documents').mkdir()
    (root / 'logs').mkdir()
    passwords = {user: secrets.token_urlsafe(24) for user in ROLES}
    devices = {f'device-{number:02}': secrets.token_urlsafe(32) for number in range(1, 11)}
    with database(config) as db:
        db.executescript('''
        CREATE TABLE users (id TEXT PRIMARY KEY, role TEXT NOT NULL, password_hash TEXT NOT NULL);
        CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), expires_at REAL);
        CREATE TABLE patients (id TEXT PRIMARY KEY, name TEXT, ward TEXT);
        CREATE TABLE assignments (user_id TEXT REFERENCES users(id), patient_id TEXT REFERENCES patients(id), PRIMARY KEY(user_id,patient_id));
        CREATE TABLE devices (id TEXT PRIMARY KEY, token_hash TEXT, ward TEXT);
        CREATE TABLE telemetry (id INTEGER PRIMARY KEY, device_id TEXT REFERENCES devices(id), value REAL, unit TEXT, received_at TEXT);
        CREATE TABLE lab_orders (id TEXT PRIMARY KEY, patient_id TEXT REFERENCES patients(id), test TEXT, actor_id TEXT);
        CREATE TABLE lab_results (id TEXT PRIMARY KEY, order_id TEXT UNIQUE REFERENCES lab_orders(id), value TEXT);
        ''')
        for user, role in ROLES.items():
            db.execute('INSERT INTO users VALUES (?,?,?)', (user, role, generate_password_hash(passwords[user])))
        for number in range(1, 201):
            patient = f'P{number:04}'
            ward = f'ward-{chr(97 + (number - 1) // 67)}'
            db.execute('INSERT INTO patients VALUES (?,?,?)', (patient, f'Synthetic Patient {number:04}', ward))
            if number <= 67:
                for user in ['clinician', 'nurse']:
                    db.execute('INSERT INTO assignments VALUES (?,?)', (user, patient))
        for device, token in devices.items():
            db.execute('INSERT INTO devices VALUES (?,?,?)', (device, sha256(token.encode()).hexdigest(), 'ward-a'))
    hashes = {}
    for number in range(1, 51):
        identity = f'D{number:03}'
        content = document_seed(identity, seed)
        (root / 'documents' / f'{identity}.txt').write_bytes(content)
        hashes[identity] = sha256(content).hexdigest()
    manifest = {'schema_version': 1, 'seed': seed, 'documents': hashes, 'patients': 200, 'devices': 10}
    (root / 'seed-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    secret_path = root / 'secrets.json'
    secret_path.write_text(json.dumps({'passwords': passwords, 'devices': devices,
                                      'receiver_key': secrets.token_urlsafe(32)}), encoding='utf-8')
    os.chmod(secret_path, 0o600)
    return {'patients': 200, 'devices': 10, 'documents': 50, 'runtime': str(root)}
