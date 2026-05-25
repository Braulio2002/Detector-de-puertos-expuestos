from enum import Enum


class PortStatus(Enum):
    """Representa el estado resultante de la verificación de conexión en un puerto TCP."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    ERROR = "ERROR"

    def __str__(self) -> str:
        return self.value
