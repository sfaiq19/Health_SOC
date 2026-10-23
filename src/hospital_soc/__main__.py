import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path

from .config import LabConfig


@contextmanager
def runtime_lock(root: Path, name: str):
    path = root / name
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        fd = None
        yield
    finally:
        if fd is not None:
            os.close(fd)
        path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description='Synthetic Healthcare SOC lab')
    parser.add_argument('--runtime', type=Path, default=Path.home() / 'HealthcareSOCLab' / 'hospital')
    parser.add_argument('--config', type=Path)
    sub = parser.add_subparsers(dest='command', required=True)
    seed = sub.add_parser('seed')
    seed.add_argument('--seed', type=int, default=101)
    serve = sub.add_parser('serve')
    serve.add_argument('--policy', choices=['observe', 'enforce'])
    serve.add_argument('--host', default=None)
    serve.add_argument('--port', type=int)
    sub.add_parser('restore')
    baseline = sub.add_parser('baseline')
    baseline.add_argument('--minutes', type=float, default=30)
    baseline.add_argument('--seed', type=int, default=101)
    scenario = sub.add_parser('scenario')
    scenario.add_argument('scenario', choices=['s1', 's2', 's3'])
    scenario.add_argument('--seed', type=int, default=201)
    for command in [baseline, scenario]:
        command.add_argument('--url', default='http://10.77.0.1:8080')
        command.add_argument('--output', type=Path, required=True)
        command.add_argument('--run-id')
        command.add_argument('--diagnostic', action='store_true')
    baseline.add_argument('--pause-documents', action='store_true')
    baseline.add_argument('--without-exports', action='store_true')
    receiver = sub.add_parser('receiver')
    receiver.add_argument('--host', choices=['127.0.0.1', '10.77.0.10'], default='10.77.0.10')
    receiver.add_argument('--port', type=int, choices=[9080, 9081], required=True)
    evaluate = sub.add_parser('evaluate')
    evaluate.add_argument('--run-dir', type=Path, required=True)
    args = parser.parse_args()
    cfg = LabConfig.load(args.config) if args.config else LabConfig(root=args.runtime)
    if args.command == 'seed':
        from .store import seed_lab
        print(json.dumps(seed_lab(cfg, args.seed)))
    elif args.command == 'restore':
        from .documents import restore_documents
        print(json.dumps(restore_documents(cfg, json.loads((cfg.root / 'seed-manifest.json').read_text()))))
    elif args.command == 'serve':
        from dataclasses import replace
        from .app import create_app
        cfg = replace(cfg, policy_mode=args.policy or cfg.policy_mode, bind_host=args.host or cfg.bind_host,
                      port=args.port or cfg.port)
        app = create_app(cfg)
        with runtime_lock(cfg.root, '.service.lock'):
            app.run(host=cfg.bind_host, port=cfg.port, debug=False, use_reloader=False, threaded=True)
    elif args.command in {'baseline', 'scenario'}:
        options = dict(base_url=args.url, output=args.output, run_id=args.run_id,
                       diagnostic=args.diagnostic, seed=args.seed)
        if args.command == 'baseline':
            from .workload import run_baseline
            result = run_baseline(cfg, max(1, int(args.minutes * 60)),
                                  pause_documents=args.pause_documents, include_exports=not args.without_exports, **options)
        else:
            from .scenarios import run_scenario
            result = run_scenario(cfg, args.scenario, **options)
        print(json.dumps({'run_id': result.run_id, 'status': result.status, 'receipts': len(result.receipts), 'notes': result.notes}))
        return 0 if result.status == 'generated' else 2
    elif args.command == 'receiver':
        from .receiver import ReceiverConfig, create_receiver
        secrets = json.loads((cfg.root / 'secrets.json').read_text())
        app = create_receiver(ReceiverConfig(root=cfg.root / f'receiver-{args.port}', key=secrets['receiver_key'],
                                           bind_host=args.host, port=args.port))
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)
    elif args.command == 'evaluate':
        from .evaluate import evaluate_run
        try:
            manifest = json.loads((args.run_dir / 'manifest.json').read_text(encoding='utf-8'))
            result = evaluate_run(manifest, args.run_dir)
        except (OSError, ValueError) as error:
            result = {'status': 'invalid', 'issues': [f'Cannot evaluate manifest: {error}']}
        (args.run_dir / 'metrics.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'complete' else 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
