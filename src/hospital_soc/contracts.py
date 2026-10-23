from dataclasses import dataclass, field
from typing import Any

from .config import LabConfig


@dataclass
class AuditEvent:
    action: str
    outcome: str
    run_id: str
    request_id: str
    actor_id: str
    actor_role: str
    source_ip: str
    http_status: int
    duration_ms: int
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunManifest:
    run_id: str
    scenario: str
    seed: int
    policy_mode: str
    started_at: str
    ended_at: str = ''
    receipts: list[dict] = field(default_factory=list)
    status: str = 'incomplete'
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
