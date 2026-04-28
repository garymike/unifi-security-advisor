from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    section: str
    severity: str   # info | low | medium | high | critical
    status: str     # ok | gap | recommendation | unknown
    title: str
    current_state: str
    recommendation: str | None = None
    intent_question: str | None = None
    evidence: dict = field(default_factory=dict)
    maps_to: dict = field(default_factory=dict)
    effort: str = "medium"
    impact: str = "medium"
