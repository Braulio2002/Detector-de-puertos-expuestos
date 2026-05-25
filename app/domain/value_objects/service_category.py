from enum import Enum


class ServiceCategory(Enum):
    """Categorías funcionales de servicios expuestos."""

    WEB = "WEB"
    ADMIN = "ADMIN"
    DATABASE = "DATABASE"
    FILE_SHARING = "FILE_SHARING"
    CACHE = "CACHE"
    MAIL = "MAIL"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value
