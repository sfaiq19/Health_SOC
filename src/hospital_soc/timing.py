"""Contemporaneous clock uncertainty, genuine OpenSearch visibility polling, and resource sampling."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import time


def _require_aware(stamp: datetime) -> datetime:
    if stamp.tzinfo is None:
        raise ValueError('Timestamp must include UTC/timezone info')
    return stamp.astimezone(timezone.utc)


def compute_clock_sample(t_send_utc: datetime, t_recv_utc: datetime, peer_utc: datetime, rtt_s: float) -> dict:
    """Compute signed offset and symmetric RTT uncertainty bound matching evidence audit checks."""
    send_at = _require_aware(t_send_utc)
    _require_aware(t_recv_utc)
    peer_at = _require_aware(peer_utc)
    if rtt_s < 0:
        raise ValueError('Round-trip time cannot be negative')
    midpoint = send_at + timedelta(seconds=rtt_s / 2.0)
    offset_ms = round((peer_at - midpoint).total_seconds() * 1000.0, 2)
    rtt_ms = round(rtt_s * 1000.0, 2)
    uncertainty_ms = round(rtt_ms / 2.0, 2)
    abs_bound_ms = round(abs(offset_ms) + uncertainty_ms, 2)
    return {
        'sampled_at_utc': midpoint.isoformat(),
        'peer_utc': peer_at.isoformat(),
        'rtt_ms': rtt_ms,
        'offset_ms': offset_ms,
        'uncertainty_ms': uncertainty_ms,
        'abs_bound_ms': abs_bound_ms,
    }


def summarize_contemporaneous_clock(samples: list[dict], window_start: datetime, window_end: datetime) -> dict:
    """Require at least one clock sample inside the active [window_start, window_end] interval."""
    start = _require_aware(window_start)
    end = _require_aware(window_end)
    if end < start:
        raise ValueError('Window end precedes window start')
    inside = [
        sample for sample in samples
        if start <= _require_aware(datetime.fromisoformat(sample['sampled_at_utc'].replace('Z', '+00:00'))) <= end
    ]
    if not inside:
        raise ValueError('No contemporaneous clock samples recorded within the measured interval')
    return {
        'contemporaneous_samples': len(inside),
        'total_samples': len(samples),
        'max_abs_bound_ms': max(float(sample['abs_bound_ms']) for sample in samples),
    }


def poll_first_index_visibility(
    query_fn,
    event_id: str,
    source_event_time: datetime,
    poll_interval_s: float = 1.0,
    timeout_s: float = 60.0,
    now_fn=None,
    sleep_fn=None,
) -> dict:
    """Poll index visibility for a real source event_id using response-completion bounds.

    Each attempt records both query start (``poll_started_at_utc``) and response completion
    (``poll_completed_at_utc``, also reflected in ``polled_at_utc`` and ``first_visible_utc``).
    Polling bounds when the document was confirmed visible rather than measuring internal
    OpenSearch indexing/refresh completion directly; negative-to-positive polls bracket the
    observation interval between ``earliest_not_before_utc`` and ``confirmed_visible_utc``.
    """
    if poll_interval_s <= 0 or timeout_s < 0:
        raise ValueError('Invalid polling schedule parameters')
    source_at = _require_aware(source_event_time)
    get_now = now_fn or (lambda: datetime.now(timezone.utc))
    do_sleep = sleep_fn or time.sleep

    deadline = None
    polls = []
    attempt = 0
    last_negative_started_at = None
    last_negative_completed_at = None

    while True:
        attempt += 1
        query_started_at = _require_aware(get_now())
        if deadline is None:
            deadline = query_started_at + timedelta(seconds=timeout_s)
        hits_total, status_code = query_fn(event_id)
        query_completed_at = _require_aware(get_now())
        query_duration_s = round(max(0.0, (query_completed_at - query_started_at).total_seconds()), 6)
        polls.append({
            'attempt': attempt,
            'poll_started_at_utc': query_started_at.isoformat(),
            'poll_completed_at_utc': query_completed_at.isoformat(),
            'polled_at_utc': query_completed_at.isoformat(),
            'query_duration_s': query_duration_s,
            'status_code': int(status_code),
            'hits_total': int(hits_total),
        })
        if int(hits_total) >= 1:
            return {
                'visible': True,
                'event_id': event_id,
                'source_event_time': source_at.isoformat(),
                'first_visible_query_started_utc': query_started_at.isoformat(),
                'first_visible_utc': query_completed_at.isoformat(),
                'first_index_visibility_delay_s': round((query_completed_at - source_at).total_seconds(), 3),
                'observation_window': {
                    'earliest_not_before_utc': (
                        last_negative_started_at.isoformat()
                        if last_negative_started_at is not None else source_at.isoformat()
                    ),
                    'last_negative_poll_completed_utc': (
                        last_negative_completed_at.isoformat()
                        if last_negative_completed_at is not None else None
                    ),
                    'confirmed_visible_utc': query_completed_at.isoformat(),
                    'semantics': 'upper_bound_response_completion',
                },
                'poll_interval_s': poll_interval_s,
                'poll_count': len(polls),
                'polls': polls,
            }
        last_negative_started_at = query_started_at
        last_negative_completed_at = query_completed_at
        remaining_s = (deadline - query_completed_at).total_seconds()
        if remaining_s <= 0:
            return {
                'visible': False,
                'event_id': event_id,
                'source_event_time': source_at.isoformat(),
                'first_visible_query_started_utc': None,
                'first_visible_utc': None,
                'first_index_visibility_delay_s': None,
                'observation_window': {
                    'last_negative_poll_completed_utc': query_completed_at.isoformat(),
                    'semantics': 'timed_out_before_confirmation',
                },
                'poll_interval_s': poll_interval_s,
                'poll_count': len(polls),
                'polls': polls,
            }
        do_sleep(min(poll_interval_s, remaining_s))


def sample_proc_resources(
    meminfo_text: str | None = None,
    loadavg_text: str | None = None,
    disk_usage: tuple[int, int, int] | None = None,
    hospital_health_ok: bool = False,
) -> dict:
    """Collect normalized guest resource metrics matching calibration/soak JSONL format."""
    meminfo_path = Path('/proc/meminfo')
    loadavg_path = Path('/proc/loadavg')
    mem_raw = (
        meminfo_text if meminfo_text is not None
        else (meminfo_path.read_text(encoding='utf-8') if meminfo_path.is_file() else None)
    )
    load_raw = (
        loadavg_text if loadavg_text is not None
        else (loadavg_path.read_text(encoding='utf-8') if loadavg_path.is_file() else None)
    )
    usage = shutil.disk_usage('/') if disk_usage is None else disk_usage
    total, used, free = usage
    proc_available = mem_raw is not None and load_raw is not None
    if proc_available:
        mem = {}
        for line in mem_raw.splitlines():
            if ':' not in line:
                continue
            key, rest = line.split(':', 1)
            tokens = rest.strip().split()
            if tokens and tokens[0].isdigit():
                mem[key] = int(tokens[0])
        loads = [float(token) for token in load_raw.strip().split()[:3]]
        mem_fields = {
            'proc_available': True,
            'mem_total_kb': mem.get('MemTotal', 0),
            'mem_available_kb': mem.get('MemAvailable', 0),
            'swap_total_kb': mem.get('SwapTotal', 0),
            'swap_free_kb': mem.get('SwapFree', 0),
            'loadavg': loads,
        }
    else:
        mem_fields = {
            'proc_available': False,
            'mem_total_kb': None,
            'mem_available_kb': None,
            'swap_total_kb': None,
            'swap_free_kb': None,
            'loadavg': None,
        }
    return {
        'sampled_at': datetime.now(timezone.utc).isoformat(),
        **mem_fields,
        'disk_free_gb': round(free / (1024 ** 3), 2),
        'disk_used_pct': round((used / total) * 100.0, 2) if total else 0.0,
        'hospital_health_ok': bool(hospital_health_ok),
    }
