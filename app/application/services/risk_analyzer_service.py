
from app.domain.value_objects.risk_level import RiskLevel
from app.shared.constants import RISK_MAPPINGS


class RiskAnalyzerService:
    """Evalúa los riesgos específicos asociados a la exposición de un puerto TCP abierto."""

    def analyze(self, port: int) -> tuple[RiskLevel, str]:
        """Obtiene el nivel de riesgo y la descripción del riesgo de exposición para un puerto abierto.

        Args:
            port (int): Puerto TCP abierto expuesto.

        Returns:
            Tuple[RiskLevel, str]: Nivel de riesgo asignado y descripción detallada del problema.
        """
        mapping = RISK_MAPPINGS.get(port)
        if mapping:
            return mapping["level"], mapping["description"]

        # Comportamiento por defecto para puertos abiertos desconocidos
        return (
            RiskLevel.LOW,
            "Puerto abierto no estándar expuesto. Monitorear su utilidad en la infraestructura."
        )
