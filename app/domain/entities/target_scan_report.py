from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.domain.entities.port_scan_result import PortScanResult
from app.domain.value_objects.risk_level import RiskLevel


@dataclass(frozen=True)
class TargetScanReport:
    """Consolida la información completa de la auditoría de un target específico."""

    target: str
    ip: str
    total_ports_scanned: int
    open_ports_count: int
    closed_ports_count: int
    filtered_ports_count: int
    open_ports: list[PortScanResult]
    risk_score: float
    risk_level: RiskLevel
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    scan_date: datetime = field(default_factory=datetime.now)
    error: str | None = None
