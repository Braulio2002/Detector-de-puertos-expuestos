from dataclasses import dataclass

from app.domain.value_objects.port_status import PortStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.service_category import ServiceCategory


@dataclass(frozen=True)
class PortScanResult:
    """Representa el resultado final de la auditoría de un puerto específico."""

    target: str
    ip: str
    port: int
    status: PortStatus
    service_name: str
    service_category: ServiceCategory
    banner: str | None = None
    risk_level: RiskLevel = RiskLevel.LOW
    recommendation: str | None = None
    error: str | None = None
