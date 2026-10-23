from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path


@dataclass(frozen=True)
class Destination:
    host: str
    port: int
    approved: bool

    def __post_init__(self):
        address = ipaddress.ip_address(self.host)
        if not (address.is_loopback or self.host == '10.77.0.10'):
            raise ValueError('Destination must be a registered lab address')
        if type(self.port) is not int or not 1024 <= self.port <= 65535 or type(self.approved) is not bool:
            raise ValueError('Invalid destination')


@dataclass(frozen=True)
class LabConfig:
    root: Path
    policy_mode: str = 'observe'
    bind_host: str = '127.0.0.1'
    port: int = 8080
    session_ttl_s: int = 1800
    destinations: dict[str, Destination] = field(default_factory=lambda: {
        'approved-lab': Destination('10.77.0.10', 9081, True),
        'unapproved-lab': Destination('10.77.0.10', 9080, False),
    })

    def __post_init__(self):
        object.__setattr__(self, 'root', Path(self.root).absolute())
        if self.policy_mode not in {'observe', 'enforce'}:
            raise ValueError('Unknown policy mode')
        if self.bind_host not in {'127.0.0.1', '10.77.0.1'}:
            raise ValueError('Bind only to loopback or the configured host-only address')
        if not 1024 <= self.port <= 65535 or self.session_ttl_s < 1:
            raise ValueError('Invalid port or session duration')

    @classmethod
    def load(cls, path: Path):
        value = json.loads(path.read_text(encoding='utf-8'))
        return cls(root=Path(value['runtime_root']), policy_mode=value.get('policy_mode', 'observe'),
                   bind_host=value.get('hospital_host', '127.0.0.1'), port=value.get('hospital_port', 8080),
                   destinations={key: Destination(**item) for key, item in value['destinations'].items()})
