"""Run actual loopback workflows, preserve receipts, and explicitly report live evidence gaps."""
from dataclasses import asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import shutil
from threading import Thread

from werkzeug.serving import make_server

from hospital_soc.app import create_app
from hospital_soc.config import LabConfig, Destination
from hospital_soc.documents import restore_documents
from hospital_soc.evaluate import evaluate_run
from hospital_soc.receiver import ReceiverConfig, create_receiver
from hospital_soc.scenarios import run_scenario
from hospital_soc.store import seed_lab
from hospital_soc.workload import run_baseline

logging.getLogger('werkzeug').setLevel(logging.ERROR)
identity = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
folder = Path.home() / 'HealthcareSOCLab' / 'validation' / identity
cfg = LabConfig(root=folder / 'hospital')
seed_lab(cfg, 101)
secret = json.loads((cfg.root / 'secrets.json').read_text())
servers = []
destinations = {}
receivers = {}


def launch(app):
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    servers.append((server, thread))
    return server.server_port


try:
    for name, approved in [('approved-lab', True), ('unapproved-lab', False)]:
        root = folder / name
        port = launch(create_receiver(ReceiverConfig(root, secret['receiver_key'])))
        destinations[name] = Destination('127.0.0.1', port, approved)
        receivers[name] = root
    cfg = replace(cfg, destinations=destinations)
    port = launch(create_app(cfg))
    url = f'http://127.0.0.1:{port}'
    runs = [run_baseline(cfg, 60, 101, base_url=url, output=folder / 'baseline', diagnostic=True, include_exports=True)]
    for name in ['s1', 's2', 's3']:
        runs.append(run_scenario(cfg, name, seed=201, output=folder / name, base_url=url, diagnostic=True))
    results = []
    for run in runs:
        path = folder / run.scenario
        source = [json.loads(line) for line in (cfg.root / 'logs/app.jsonl').read_text().splitlines()]
        selected = [event for event in source if event['run_id'] == run.run_id]
        (path / 'app.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in selected), encoding='utf-8')
        if run.scenario == 's3':
            root = receivers['unapproved-lab']
            shutil.copyfile(root / 'receiver.jsonl', path / 'receiver.jsonl')
            (path / 'received').mkdir()
            for event in selected:
                if event['action'] == 'export_completed':
                    name = event['transfer_id'] + '.bin'
                    shutil.copyfile(root / name, path / 'received' / name)
        metrics = evaluate_run(run, path)
        (path / 'metrics.json').write_text(json.dumps(metrics, indent=2), encoding='utf-8')
        results.append({'scenario': run.scenario, 'run_id': run.run_id, 'generation': run.status,
                        'receipts': len(run.receipts), 'source_events': len(selected),
                        'live_acceptance': metrics['status']})
    if any(row['generation'] != 'generated' or row['live_acceptance'] == 'complete' for row in results):
        raise SystemExit('Unexpected local validation outcome; inspect preserved evidence.')
finally:
    for server, thread in reversed(servers):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

restoration = restore_documents(cfg, json.loads((cfg.root / 'seed-manifest.json').read_text()))
summary = {'environment': 'Windows loopback only', 'timing': 'diagnostic', 'evidence': str(folder),
           'results': results, 'restoration': restoration,
           'limits': ['No Wazuh engine', 'No packet capture', 'No cross-host run', 'No measured timing trial']}
(folder / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(json.dumps(summary, indent=2))
