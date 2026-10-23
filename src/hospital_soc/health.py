"""Heartbeat freshness based on source event time, not late index arrival."""
from datetime import datetime, timezone


def heartbeat_state(last_seen: str | None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    try:
        seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
        if seen.tzinfo is None:
            raise ValueError('Unknown timezone')
        age = (now - seen).total_seconds()
        if age < -1:
            raise ValueError('Source clock is in the future')
    except (AttributeError, TypeError, ValueError):
        return {'status': 'unknown', 'seconds_old': None}
    return {'status': 'stale' if age > 90 else 'fresh', 'seconds_old': age}
