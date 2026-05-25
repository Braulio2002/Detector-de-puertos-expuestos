
from app.domain.value_objects.service_category import ServiceCategory
from app.shared.constants import SERVICE_MAPPINGS


class ServiceIdentifierService:
    """Identifica el nombre del servicio y su categoría a partir de su puerto TCP."""

    def identify(self, port: int) -> tuple[str, ServiceCategory]:
        """Obtiene el nombre de servicio estándar y su categoría funcional para un puerto dado.

        Args:
            port (int): Puerto de red auditado.

        Returns:
            Tuple[str, ServiceCategory]: Par con el nombre de servicio y su categoría correspondiente.
        """
        mapping = SERVICE_MAPPINGS.get(port)
        if mapping:
            return mapping["name"], mapping["category"]

        # Si el puerto no se encuentra en el catálogo mapeador de constantes
        return f"Desconocido ({port})", ServiceCategory.UNKNOWN
