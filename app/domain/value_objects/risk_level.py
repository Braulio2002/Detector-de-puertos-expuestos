from enum import Enum


class RiskLevel(Enum):
    """Clasificación del nivel de riesgo asociado a un puerto expuesto."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value
