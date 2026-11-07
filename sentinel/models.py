from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class LoginEvent:
    """One authentication attempt, normalized from any supported log format."""
    timestamp: datetime
    user: str
    ip: str
    success: bool
    invalid_user: bool = False
    method: str = "password"
    host: str = ""
    source: str = ""
    raw: str = ""
    id: int | None = None


@dataclass
class Alert:
    """A detection produced by a rule. Becomes an incident when stored."""
    rule: str
    severity: str  # low | medium | high | critical
    title: str
    description: str
    start: datetime
    end: datetime
    user: str | None = None
    ip: str | None = None
    count: int = 0
    event_ids: list[int] = field(default_factory=list)
    mitre: str = ""

    @property
    def key(self) -> str:
        """Stable de-duplication key so re-running detection doesn't create duplicate incidents."""
        return f"{self.rule}|{self.user or '-'}|{self.ip or '-'}|{self.start.isoformat()}"


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
