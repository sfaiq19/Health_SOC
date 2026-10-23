from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from uuid import uuid4

from .contracts import AuditEvent

_locks = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


class AuditWriter:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = _locks.setdefault(str(path), threading.RLock())

    def write(self, event: AuditEvent) -> None:
        value = asdict(event)
        details = value.pop('details')
        if set(details) & set(value):
            raise ValueError('Audit details cannot override identity or action')
        value.update(details)
        value.update(schema_version=1, service='hospital-lab', event_id=str(uuid4()),
                     event_time=utc_now(), actor_key=f'{event.actor_id}|{event.source_ip}')
        line = json.dumps(value, separators=(',', ':'), allow_nan=False) + '\n'
        if len(line.encode('utf-8')) >= 8192:
            raise ValueError('Audit event exceeds size limit')
        with self.lock, self.path.open('a', encoding='utf-8', newline='\n') as output:
            output.write(line)
            output.flush()
            os.fsync(output.fileno())
