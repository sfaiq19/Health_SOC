from datetime import datetime, timezone

from hospital_soc.health import heartbeat_state


def test_heartbeat_is_unknown_when_absent_and_stale_when_expired():
    now = datetime(2026, 10, 22, 0, 2, tzinfo=timezone.utc)
    assert heartbeat_state(None, now)['status'] == 'unknown'
    assert heartbeat_state('2026-10-22T00:00:00Z', now)['status'] == 'stale'
    assert heartbeat_state('2026-10-22T00:01:30Z', now)['status'] == 'fresh'


def test_heartbeat_boundary_and_invalid_clock_are_explicit():
    now = datetime(2026, 10, 22, 0, 2, tzinfo=timezone.utc)
    assert heartbeat_state('2026-10-22T00:00:30Z', now)['status'] == 'fresh'
    assert heartbeat_state('2026-10-22T00:00:29Z', now)['status'] == 'stale'
    assert heartbeat_state('malformed', now)['status'] == 'unknown'
    assert heartbeat_state('2026-10-22T01:00:00Z', now)['status'] == 'unknown'
