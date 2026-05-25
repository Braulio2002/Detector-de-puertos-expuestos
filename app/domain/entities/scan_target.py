from dataclasses import dataclass


@dataclass(frozen=True)
class ScanTarget:
    """Representa un objetivo (IP o Dominio) preparado para auditoría."""

    target_original: str
    ip_resuelta: str | None
    tipo: str  # "IP" o "DOMAIN"
