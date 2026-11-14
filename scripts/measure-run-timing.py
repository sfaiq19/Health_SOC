"""Collect contemporaneous clock bounds, per-minute guest resources, and concurrent first-index polling."""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import threading
import time
import urllib.error
import urllib.request

from hospital_soc.timing import (
    compute_clock_sample,
    poll_first_index_visibility,
    sample_proc_resources,
    summarize_contemporaneous_clock,
)


def probe_hospital_clock(health_url: str, timeout_s: float = 5.0) -> tuple[bool, dict | None]:
    """Perform one bounded /health GET and bracket server_time with client monotonic/UTC clocks."""
    t0_utc = datetime.now(timezone.utc)
    t0_mono = time.monotonic()
    try:
        with urllib.request.urlopen(health_url, timeout=timeout_s) as response:
            body = json.loads(response.read().decode('utf-8'))
            t1_mono = time.monotonic()
            t1_utc = datetime.now(timezone.utc)
    except (OSError, ValueError):
        return False, None
    peer_raw = body.get('server_time')
    if not isinstance(peer_raw, str):
        return body.get('status') == 'ok', None
    peer_utc = datetime.fromisoformat(peer_raw.replace('Z', '+00:00'))
    sample = compute_clock_sample(t0_utc, t1_utc, peer_utc, rtt_s=(t1_mono - t0_mono))
    return body.get('status') == 'ok', sample


def _build_ssl_context(
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
):
    """Build an SSL context for OpenSearch HTTPS and optional client mTLS authentication."""
    if not (ca_file or cert_file or key_file):
        return None
    if bool(cert_file) != bool(key_file):
        raise ValueError('--cert-file and --key-file must be provided together')
    import ssl

    context = ssl.create_default_context(cafile=ca_file)
    if cert_file and key_file:
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def opensearch_query_event_id(
    index_url: str,
    auth_header: str | None,
    event_id: str,
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    ssl_context=None,
):
    """Query OpenSearch wazuh-archives-* by exact data.event_id."""
    payload = json.dumps({
        'size': 1,
        'query': {'term': {'data.event_id': event_id}},
    }).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    if auth_header:
        headers['Authorization'] = auth_header
    req = urllib.request.Request(
        f"{index_url.rstrip('/')}/wazuh-archives-*/_search",
        data=payload,
        headers=headers,
        method='POST',
    )
    context = ssl_context if ssl_context is not None else _build_ssl_context(
        ca_file=ca_file,
        cert_file=cert_file,
        key_file=key_file,
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0, context=context) as response:
            data = json.loads(response.read().decode('utf-8'))
            hits = data.get('hits', {}).get('total', {})
            total = hits.get('value', 0) if isinstance(hits, dict) else int(hits)
            return int(total), response.status
    except urllib.error.HTTPError as error:
        return 0, error.code
    except (urllib.error.URLError, OSError):
        return 0, 0


def main() -> int:
    parser = argparse.ArgumentParser(description='Task 3 contemporaneous soak timing and index visibility collector')
    parser.add_argument('--output', type=Path, required=True, help='New non-existing directory for timing observations')
    parser.add_argument('--mode', choices=['auto', 'sample', 'poll', 'both'], default='auto')
    parser.add_argument('--health-url', default='http://10.77.0.1:8080/health')
    parser.add_argument('--duration-s', type=float, default=900.0)
    parser.add_argument('--interval-s', type=float, default=60.0)
    parser.add_argument('--index-url', help='OpenSearch base URL to poll for --event-id')
    parser.add_argument('--event-id', help='Source event_id to poll for first-index visibility bound')
    parser.add_argument('--event-time', help='UTC ISO timestamp of --event-id')
    parser.add_argument('--ca-file', help='Optional CA bundle path for HTTPS OpenSearch verification')
    parser.add_argument('--cert-file', help='Optional client certificate PEM for OpenSearch mTLS authentication')
    parser.add_argument('--key-file', help='Optional client private key PEM for OpenSearch mTLS authentication')
    parser.add_argument('--poll-interval-s', type=float, default=1.0)
    parser.add_argument('--poll-timeout-s', type=float, default=60.0)
    args = parser.parse_args()

    poll_args = [args.index_url, args.event_id, args.event_time]
    has_any_poll = any(poll_args)
    has_all_poll = all(poll_args)
    if has_any_poll and not has_all_poll:
        parser.error('--index-url, --event-id, and --event-time must be provided together')
    if args.mode in ('poll', 'both') and not has_all_poll:
        parser.error(f'--mode {args.mode} requires --index-url, --event-id, and --event-time')
    if args.duration_s < 0 or args.interval_s <= 0:
        parser.error('--duration-s must be >= 0 and --interval-s must be > 0')

    polling_enabled = has_all_poll and args.mode != 'sample'
    sampling_enabled = args.mode != 'poll'

    ssl_context = None
    auth_header = None
    source_time = None
    if polling_enabled:
        ssl_context = _build_ssl_context(ca_file=args.ca_file, cert_file=args.cert_file, key_file=args.key_file)
        user = os.environ.get('OPENSEARCH_USER', '')
        password = os.environ.get('OPENSEARCH_PASSWORD', '')
        auth_header = (
            'Basic ' + base64.b64encode(f'{user}:{password}'.encode('utf-8')).decode('ascii')
            if user and password else None
        )
        source_time = datetime.fromisoformat(args.event_time.replace('Z', '+00:00'))

    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    res_path = out / 'guest-resources.jsonl'
    clock_path = out / 'clock-offset.json'

    issues = []
    poll_result_box: dict = {}
    poll_started_event = threading.Event()
    poll_thread = None

    if polling_enabled:
        def _run_poll():
            poll_result_box['started_at_utc'] = datetime.now(timezone.utc).isoformat()
            poll_started_event.set()
            try:
                poll_result_box['result'] = poll_first_index_visibility(
                    lambda eid: opensearch_query_event_id(
                        args.index_url,
                        auth_header,
                        eid,
                        ssl_context=ssl_context,
                    ),
                    args.event_id,
                    source_time,
                    poll_interval_s=args.poll_interval_s,
                    timeout_s=args.poll_timeout_s,
                )
            except Exception as exc:  # pragma: no cover - defensive error capture
                poll_result_box['error'] = str(exc)
            finally:
                poll_result_box['completed_at_utc'] = datetime.now(timezone.utc).isoformat()

        poll_thread = threading.Thread(target=_run_poll, name='visibility-poller', daemon=True)
        poll_thread.start()
        poll_started_event.wait(timeout=5.0)

    samples = []
    window_start = None
    window_end = None
    if sampling_enabled:
        window_start = datetime.now(timezone.utc)
        with res_path.open('a', encoding='utf-8') as stream:
            deadline = time.monotonic() + max(0.0, args.duration_s)
            while True:
                ok, clock_sample = probe_hospital_clock(args.health_url)
                if clock_sample is not None:
                    samples.append(clock_sample)
                resource_row = sample_proc_resources(hospital_health_ok=ok)
                stream.write(json.dumps(resource_row) + '\n')
                stream.flush()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(args.interval_s, remaining))
        window_end = datetime.now(timezone.utc)

        if samples:
            clock_summary = summarize_contemporaneous_clock(samples, window_start, window_end)
            clock_payload = {
                'complete': True,
                'window_start_utc': window_start.isoformat(),
                'window_end_utc': window_end.isoformat(),
                'measured_at_utc': window_end.isoformat(),
                **clock_summary,
                'samples': samples,
            }
        else:
            issues.append('No valid /health server_time clock samples collected')
            clock_payload = {
                'complete': False,
                'window_start_utc': window_start.isoformat(),
                'window_end_utc': window_end.isoformat(),
                'measured_at_utc': window_end.isoformat(),
                'contemporaneous_samples': 0,
                'total_samples': 0,
                'error': 'No valid /health server_time clock samples collected',
                'samples': [],
            }
        clock_path.write_text(json.dumps(clock_payload, indent=2) + '\n', encoding='utf-8')

    vis = None
    if poll_thread is not None:
        poll_thread.join()
        if 'result' in poll_result_box:
            vis = poll_result_box['result']
            (out / 'visibility-polls.json').write_text(json.dumps(vis, indent=2) + '\n', encoding='utf-8')
            if not vis['visible']:
                issues.append('Index visibility polling timed out without confirming event_id')
        else:
            err_msg = poll_result_box.get('error', 'Unknown visibility polling error')
            issues.append(f'Index visibility polling error: {err_msg}')
            (out / 'visibility-polls.json').write_text(
                json.dumps({'visible': False, 'event_id': args.event_id, 'error': err_msg}, indent=2) + '\n',
                encoding='utf-8',
            )

    summary = {
        'status': 'complete' if not issues else 'incomplete',
        'issues': issues,
        'mode': args.mode,
        'sampling_enabled': sampling_enabled,
        'polling_enabled': polling_enabled,
        'concurrent_polling': bool(sampling_enabled and polling_enabled),
        'sampling_started_at_utc': window_start.isoformat() if window_start else None,
        'sampling_completed_at_utc': window_end.isoformat() if window_end else None,
        'clock_samples_collected': len(samples),
        'polling_started_at_utc': poll_result_box.get('started_at_utc'),
        'polling_completed_at_utc': poll_result_box.get('completed_at_utc'),
        'event_id': args.event_id if polling_enabled else None,
        'first_index_visibility_delay_s': vis.get('first_index_visibility_delay_s') if vis else None,
    }
    (out / 'timing-summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')

    if issues:
        for issue in issues:
            print(f'INCOMPLETE: {issue}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
