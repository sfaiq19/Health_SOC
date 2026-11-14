"""Tests for contemporaneous clock bracketing, first-index visibility polling, and resource sampling."""
from datetime import datetime, timedelta, timezone

import pytest

from hospital_soc.timing import (
    compute_clock_sample,
    poll_first_index_visibility,
    sample_proc_resources,
    summarize_contemporaneous_clock,
)


def test_clock_sample_computes_symmetric_uncertainty_and_abs_bound():
    t0 = datetime(2026, 11, 14, 12, 0, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 14, 12, 0, 0, 200_000, tzinfo=timezone.utc)
    peer = datetime(2026, 11, 14, 12, 0, 0, 220_000, tzinfo=timezone.utc)
    sample = compute_clock_sample(t0, t1, peer, rtt_s=0.200)
    assert sample['rtt_ms'] == 200.0
    assert sample['uncertainty_ms'] == 100.0
    assert sample['offset_ms'] == 120.0
    assert sample['abs_bound_ms'] == 220.0


def test_contemporaneous_clock_summary_rejects_post_run_only_samples():
    start = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 11, 14, 12, 15, 0, tzinfo=timezone.utc)
    post_only = [
        compute_clock_sample(
            end + timedelta(seconds=60),
            end + timedelta(seconds=60.1),
            end + timedelta(seconds=60.05),
            rtt_s=0.1,
        )
    ]
    with pytest.raises(ValueError, match='contemporaneous'):
        summarize_contemporaneous_clock(post_only, start, end)

    mid = [
        compute_clock_sample(
            start + timedelta(seconds=300),
            start + timedelta(seconds=300.1),
            start + timedelta(seconds=300.05),
            rtt_s=0.1,
        )
    ]
    summary = summarize_contemporaneous_clock(mid, start, end)
    assert summary['contemporaneous_samples'] == 1
    assert summary['max_abs_bound_ms'] == 50.0


def test_poll_first_index_visibility_records_actual_polls_until_hit():
    base = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    tick = {'n': 0}

    def fake_now():
        return base + timedelta(seconds=tick['n'])

    def fake_sleep(seconds):
        tick['n'] += int(seconds)

    def fake_query(event_id):
        assert event_id == 'evt-123'
        # Hit only arrives at t=+4s
        return (1 if tick['n'] >= 4 else 0), 200

    res = poll_first_index_visibility(
        fake_query,
        'evt-123',
        source_event_time=base,
        poll_interval_s=1.0,
        timeout_s=10.0,
        now_fn=fake_now,
        sleep_fn=fake_sleep,
    )
    assert res['visible'] is True
    assert res['poll_count'] == 5
    assert res['first_index_visibility_delay_s'] == 4.0
    assert [p['hits_total'] for p in res['polls']] == [0, 0, 0, 0, 1]


def test_poll_first_index_visibility_preserves_failure_polls_on_timeout():
    base = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    tick = {'n': 0}
    res = poll_first_index_visibility(
        lambda _id: (0, 200),
        'evt-never',
        source_event_time=base,
        poll_interval_s=1.0,
        timeout_s=2.0,
        now_fn=lambda: base + timedelta(seconds=tick['n']),
        sleep_fn=lambda s: tick.__setitem__('n', tick['n'] + int(s)),
    )
    assert res['visible'] is False
    assert res['first_index_visibility_delay_s'] is None
    assert len(res['polls']) >= 3


def test_sample_proc_resources_parses_linux_metrics_cleanly():
    meminfo = 'MemTotal:        8131264 kB\nMemAvailable:    5200000 kB\nSwapTotal:       4194300 kB\nSwapFree:        4194300 kB\n'
    loadavg = '0.12 0.08 0.04 1/300 1234\n'
    sample = sample_proc_resources(
        meminfo_text=meminfo,
        loadavg_text=loadavg,
        disk_usage=(100 * 1024**3, 70 * 1024**3, 30 * 1024**3),
        hospital_health_ok=True,
    )
    assert sample['mem_total_kb'] == 8131264
    assert sample['mem_available_kb'] == 5200000
    assert sample['swap_free_kb'] == 4194300
    assert sample['loadavg'] == [0.12, 0.08, 0.04]
    assert sample['disk_free_gb'] == 30.0
    assert sample['disk_used_pct'] == 70.0
    assert sample['hospital_health_ok'] is True


def test_measure_run_timing_script_collects_clock_and_visibility_on_local_servers(tmp_path, capsys):
    import json
    import subprocess
    import sys
    from threading import Thread
    from flask import Flask, jsonify, request
    from werkzeug.serving import make_server
    from hospital_soc.config import LabConfig
    from hospital_soc.app import create_app
    from hospital_soc.store import seed_lab

    runtime = tmp_path / 'hospital'
    seed_lab(LabConfig(root=runtime), 101)
    hospital_app = create_app(LabConfig(root=runtime))
    hosp_srv = make_server('127.0.0.1', 0, hospital_app, threaded=True)
    hosp_thread = Thread(target=hosp_srv.serve_forever, daemon=True)
    hosp_thread.start()

    idx_app = Flask('fake_os')
    calls = {'n': 0}

    @idx_app.post('/wazuh-archives-*/_search')
    def search():
        calls['n'] += 1
        assert request.get_json()['query']['term']['data.event_id'] == 'evt-live-1'
        return jsonify(hits={'total': {'value': 1 if calls['n'] >= 2 else 0, 'relation': 'eq'}})

    idx_srv = make_server('127.0.0.1', 0, idx_app, threaded=True)
    idx_thread = Thread(target=idx_srv.serve_forever, daemon=True)
    idx_thread.start()

    out_dir = tmp_path / 'timing-out'
    try:
        ev_time = datetime.now(timezone.utc).isoformat()
        res = subprocess.run(
            [
                sys.executable,
                'scripts/measure-run-timing.py',
                '--output', str(out_dir),
                '--health-url', f'http://127.0.0.1:{hosp_srv.server_port}/health',
                '--duration-s', '0.2',
                '--interval-s', '0.1',
                '--index-url', f'http://127.0.0.1:{idx_srv.server_port}',
                '--event-id', 'evt-live-1',
                '--event-time', ev_time,
                '--poll-interval-s', '0.05',
                '--poll-timeout-s', '5.0',
            ],
            capture_output=True,
            text=True,
            env=__import__('os').environ | {'PYTHONPATH': 'src'},
        )
        assert res.returncode == 0, res.stderr
        clock = json.loads((out_dir / 'clock-offset.json').read_text(encoding='utf-8'))
        assert clock['contemporaneous_samples'] >= 1
        assert len(clock['samples']) >= 1
        vis = json.loads((out_dir / 'visibility-polls.json').read_text(encoding='utf-8'))
        assert vis['visible'] is True
        assert vis['poll_count'] == 2
        assert isinstance(vis['first_index_visibility_delay_s'], float)
        resource_lines = (out_dir / 'guest-resources.jsonl').read_text(encoding='utf-8').splitlines()
        assert len(resource_lines) >= 1
        first_res = json.loads(resource_lines[0])
        assert first_res['hospital_health_ok'] is True
        assert 'proc_available' in first_res
    finally:
        hosp_srv.shutdown()
        hosp_srv.server_close()
        idx_srv.shutdown()
        idx_srv.server_close()
        hosp_thread.join(timeout=5)
        idx_thread.join(timeout=5)


def test_measure_run_timing_build_ssl_context_requires_cert_key_pair(monkeypatch, tmp_path):
    import importlib.util
    import ssl
    from pathlib import Path

    spec = importlib.util.spec_from_file_location('measure_run_timing', Path('scripts/measure-run-timing.py'))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    assert mod._build_ssl_context() is None
    with pytest.raises(ValueError, match='together'):
        mod._build_ssl_context(cert_file='/tmp/client.pem')

    loaded = {}

    class FakeContext:
        def load_cert_chain(self, certfile, keyfile):
            loaded['certfile'] = certfile
            loaded['keyfile'] = keyfile

    ca_seen = {}

    def fake_create_ctx(cafile=None):
        ca_seen['cafile'] = cafile
        return FakeContext()

    monkeypatch.setattr(ssl, 'create_default_context', fake_create_ctx)
    ctx = mod._build_ssl_context(ca_file=str(tmp_path / 'ca.pem'), cert_file='c.pem', key_file='k.pem')
    assert ctx is not None
    assert isinstance(ctx, FakeContext)
    assert ca_seen['cafile'] == str(tmp_path / 'ca.pem')
    assert loaded == {'certfile': 'c.pem', 'keyfile': 'k.pem'}


def test_poll_first_index_visibility_records_query_completion_for_slow_hit():
    base = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    clock_s = {'t': 0.0}

    def fake_now():
        return base + timedelta(seconds=clock_s['t'])

    def fake_sleep(seconds):
        clock_s['t'] += float(seconds)

    def slow_query(event_id):
        assert event_id == 'evt-slow'
        clock_s['t'] += 10.0
        return 1, 200

    res = poll_first_index_visibility(
        slow_query,
        'evt-slow',
        source_event_time=base,
        poll_interval_s=1.0,
        timeout_s=30.0,
        now_fn=fake_now,
        sleep_fn=fake_sleep,
    )
    assert res['visible'] is True
    assert res['poll_count'] == 1
    assert res['first_visible_query_started_utc'] == base.isoformat()
    assert res['first_visible_utc'] == (base + timedelta(seconds=10.0)).isoformat()
    assert res['first_index_visibility_delay_s'] == 10.0
    assert res['polls'][0]['poll_started_at_utc'] == base.isoformat()
    assert res['polls'][0]['poll_completed_at_utc'] == (base + timedelta(seconds=10.0)).isoformat()
    assert res['polls'][0]['polled_at_utc'] == (base + timedelta(seconds=10.0)).isoformat()
    assert res['polls'][0]['query_duration_s'] == 10.0
    assert res['observation_window']['earliest_not_before_utc'] == base.isoformat()
    assert res['observation_window']['confirmed_visible_utc'] == (base + timedelta(seconds=10.0)).isoformat()
    assert res['observation_window']['semantics'] == 'upper_bound_response_completion'


def test_poll_first_index_visibility_stops_when_delayed_negative_query_crosses_timeout():
    base = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    clock_s = {'t': 0.0}
    sleeps = []

    def fake_now():
        return base + timedelta(seconds=clock_s['t'])

    def fake_sleep(seconds):
        sleeps.append(float(seconds))
        clock_s['t'] += float(seconds)

    def delayed_miss(_event_id):
        clock_s['t'] += 3.0
        return 0, 200

    res = poll_first_index_visibility(
        delayed_miss,
        'evt-timeout',
        source_event_time=base,
        poll_interval_s=1.0,
        timeout_s=5.0,
        now_fn=fake_now,
        sleep_fn=fake_sleep,
    )
    # Attempt 1: 0s -> 3s (miss, sleep 1s -> 4s). Attempt 2: 4s -> 7s (miss >= 5s deadline -> stop).
    assert res['visible'] is False
    assert res['poll_count'] == 2
    assert sleeps == [1.0]
    assert [p['query_duration_s'] for p in res['polls']] == [3.0, 3.0]
    assert res['polls'][-1]['poll_completed_at_utc'] == (base + timedelta(seconds=7.0)).isoformat()

    # Single query exceeding timeout stops after 1 attempt without sleeping.
    clock_s['t'] = 0.0
    sleeps.clear()
    res_single = poll_first_index_visibility(
        lambda _eid: (clock_s.__setitem__('t', clock_s['t'] + 6.0) or (0, 200)),
        'evt-single-timeout',
        source_event_time=base,
        poll_interval_s=1.0,
        timeout_s=5.0,
        now_fn=fake_now,
        sleep_fn=fake_sleep,
    )
    assert res_single['visible'] is False
    assert res_single['poll_count'] == 1
    assert sleeps == []


def test_poll_first_index_visibility_negative_to_positive_preserves_timestamps_and_interval():
    base = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    clock_s = {'t': 0.0}
    sleeps = []
    durations = [0.4, 0.6, 1.5]
    idx = {'i': 0}

    def fake_now():
        return base + timedelta(seconds=clock_s['t'])

    def fake_sleep(seconds):
        sleeps.append(float(seconds))
        clock_s['t'] += float(seconds)

    def stepped_query(event_id):
        assert event_id == 'evt-step'
        i = idx['i']
        idx['i'] += 1
        clock_s['t'] += durations[i]
        return (1 if i == 2 else 0), 200

    res = poll_first_index_visibility(
        stepped_query,
        'evt-step',
        source_event_time=base,
        poll_interval_s=1.0,
        timeout_s=10.0,
        now_fn=fake_now,
        sleep_fn=fake_sleep,
    )
    assert res['visible'] is True
    assert sleeps == [1.0, 1.0]
    assert res['poll_count'] == 3
    assert [p['query_duration_s'] for p in res['polls']] == [0.4, 0.6, 1.5]
    assert res['polls'][0]['poll_started_at_utc'] == base.isoformat()
    assert res['polls'][0]['poll_completed_at_utc'] == (base + timedelta(seconds=0.4)).isoformat()
    assert res['polls'][1]['poll_started_at_utc'] == (base + timedelta(seconds=1.4)).isoformat()
    assert res['polls'][1]['poll_completed_at_utc'] == (base + timedelta(seconds=2.0)).isoformat()
    assert res['polls'][2]['poll_started_at_utc'] == (base + timedelta(seconds=3.0)).isoformat()
    assert res['polls'][2]['poll_completed_at_utc'] == (base + timedelta(seconds=4.5)).isoformat()
    assert res['first_visible_query_started_utc'] == (base + timedelta(seconds=3.0)).isoformat()
    assert res['first_visible_utc'] == (base + timedelta(seconds=4.5)).isoformat()
    assert res['first_index_visibility_delay_s'] == 4.5
    assert res['observation_window']['earliest_not_before_utc'] == (base + timedelta(seconds=1.4)).isoformat()
    assert res['observation_window']['last_negative_poll_completed_utc'] == (base + timedelta(seconds=2.0)).isoformat()
    assert res['observation_window']['confirmed_visible_utc'] == (base + timedelta(seconds=4.5)).isoformat()


def test_measure_run_timing_polls_concurrently_while_sampling_continues(tmp_path):
    import json
    import os
    import subprocess
    import sys
    import time
    from threading import Thread
    from flask import Flask, jsonify
    from werkzeug.serving import make_server

    health_app = Flask('fake_hosp')
    health_times = []

    @health_app.get('/health')
    def health():
        health_times.append(time.monotonic())
        return jsonify(status='ok', server_time=datetime.now(timezone.utc).isoformat())

    idx_app = Flask('fake_os_concurrent')
    search_times = []

    @idx_app.post('/wazuh-archives-*/_search')
    def search():
        search_times.append(time.monotonic())
        return jsonify(hits={'total': {'value': 1, 'relation': 'eq'}})

    hosp_srv = make_server('127.0.0.1', 0, health_app, threaded=True)
    idx_srv = make_server('127.0.0.1', 0, idx_app, threaded=True)
    t1 = Thread(target=hosp_srv.serve_forever, daemon=True)
    t2 = Thread(target=idx_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()

    out_dir = tmp_path / 'concurrent-out'
    try:
        ev_time = datetime.now(timezone.utc).isoformat()
        res = subprocess.run(
            [
                sys.executable,
                'scripts/measure-run-timing.py',
                '--output', str(out_dir),
                '--health-url', f'http://127.0.0.1:{hosp_srv.server_port}/health',
                '--duration-s', '0.5',
                '--interval-s', '0.15',
                '--index-url', f'http://127.0.0.1:{idx_srv.server_port}',
                '--event-id', 'evt-concurrent-1',
                '--event-time', ev_time,
                '--poll-interval-s', '0.02',
                '--poll-timeout-s', '5.0',
            ],
            capture_output=True,
            text=True,
            env=os.environ | {'PYTHONPATH': 'src'},
        )
        assert res.returncode == 0, res.stderr
        assert len(health_times) >= 3
        assert len(search_times) >= 1
        # Polling must start immediately while sampling continues, not after sampling finishes.
        assert search_times[0] < health_times[-1]

        summary = json.loads((out_dir / 'timing-summary.json').read_text(encoding='utf-8'))
        assert summary['status'] == 'complete'
        assert summary['issues'] == []
        assert summary['concurrent_polling'] is True

        # Non-overwriting behavior preserved.
        res_dup = subprocess.run(
            [
                sys.executable,
                'scripts/measure-run-timing.py',
                '--output', str(out_dir),
                '--duration-s', '0',
            ],
            capture_output=True,
            text=True,
            env=os.environ | {'PYTHONPATH': 'src'},
        )
        assert res_dup.returncode != 0
    finally:
        hosp_srv.shutdown()
        hosp_srv.server_close()
        idx_srv.shutdown()
        idx_srv.server_close()
        t1.join(timeout=5)
        t2.join(timeout=5)


def test_measure_run_timing_reports_incomplete_on_clock_failure_timeout_or_partial_flags(tmp_path):
    import json
    import os
    import subprocess
    import sys
    from threading import Thread
    from flask import Flask, jsonify
    from werkzeug.serving import make_server

    bad_hosp = Flask('bad_hosp')

    @bad_hosp.get('/health')
    def bad_health():
        return jsonify(status='degraded'), 503

    miss_idx = Flask('miss_os')

    @miss_idx.post('/wazuh-archives-*/_search')
    def miss_search():
        return jsonify(hits={'total': {'value': 0, 'relation': 'eq'}})

    hosp_srv = make_server('127.0.0.1', 0, bad_hosp, threaded=True)
    idx_srv = make_server('127.0.0.1', 0, miss_idx, threaded=True)
    t1 = Thread(target=hosp_srv.serve_forever, daemon=True)
    t2 = Thread(target=idx_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()

    try:
        out_fail = tmp_path / 'fail-out'
        res = subprocess.run(
            [
                sys.executable,
                'scripts/measure-run-timing.py',
                '--output', str(out_fail),
                '--health-url', f'http://127.0.0.1:{hosp_srv.server_port}/health',
                '--duration-s', '0.1',
                '--interval-s', '0.05',
                '--index-url', f'http://127.0.0.1:{idx_srv.server_port}',
                '--event-id', 'evt-miss-1',
                '--event-time', datetime.now(timezone.utc).isoformat(),
                '--poll-interval-s', '0.05',
                '--poll-timeout-s', '0.1',
            ],
            capture_output=True,
            text=True,
            env=os.environ | {'PYTHONPATH': 'src'},
        )
        assert res.returncode == 2
        summary = json.loads((out_fail / 'timing-summary.json').read_text(encoding='utf-8'))
        assert summary['status'] == 'incomplete'
        assert any('clock' in issue.lower() for issue in summary['issues'])
        assert any('visibility' in issue.lower() or 'timed out' in issue.lower() for issue in summary['issues'])
        vis = json.loads((out_fail / 'visibility-polls.json').read_text(encoding='utf-8'))
        assert vis['visible'] is False
        clock = json.loads((out_fail / 'clock-offset.json').read_text(encoding='utf-8'))
        assert clock['contemporaneous_samples'] == 0
        assert clock['complete'] is False

        # Partial polling arguments fail explicitly without silently skipping polling.
        out_partial = tmp_path / 'partial-out'
        res_partial = subprocess.run(
            [
                sys.executable,
                'scripts/measure-run-timing.py',
                '--output', str(out_partial),
                '--index-url', f'http://127.0.0.1:{idx_srv.server_port}',
            ],
            capture_output=True,
            text=True,
            env=os.environ | {'PYTHONPATH': 'src'},
        )
        assert res_partial.returncode != 0
    finally:
        hosp_srv.shutdown()
        hosp_srv.server_close()
        idx_srv.shutdown()
        idx_srv.server_close()
        t1.join(timeout=5)
        t2.join(timeout=5)
