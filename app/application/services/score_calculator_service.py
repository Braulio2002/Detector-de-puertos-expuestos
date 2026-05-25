
from app.domain.entities.port_scan_result import PortScanResult
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.service_category import ServiceCategory


class ScoreCalculatorService:
    """Calcula el score de riesgo acumulado (0-100) e identifica el nivel de riesgo global."""

    def __init__(self, weights: dict[str, float], thresholds: dict[str, range]):
        """Inicializa el calculador con los pesos y umbrales configurados.

        Args:
            weights (Dict[str, float]): Mapeo de categorías a pesos de penalización.
            thresholds (Dict[str, range]): Rangos de puntuación por cada nivel de riesgo.
        """
        self._weights = weights
        self._thresholds = thresholds

    def calculate(self, open_ports: list[PortScanResult]) -> tuple[float, RiskLevel]:
        """Calcula el score total para un target basado en sus puertos abiertos y asigna el nivel de riesgo.

        Args:
            open_ports (List[PortScanResult]): Lista de resultados de puertos que están en estado OPEN.

        Returns:
            tuple[float, RiskLevel]: El score final calculado (capado en 100.0) y su clasificación correspondiente.
        """
        if not open_ports:
            return 0.0, RiskLevel.LOW

        score = 0.0

        for res in open_ports:
            port = res.port
            category = res.service_category

            # Verificar si es protocolo inseguro
            if port in [21, 23]:
                score += self._weights.get("INSECURE", 25.0)
            # Verificar si es web sin HTTPS (puertos 80, 8000, 8080)
            elif port in [80, 8000, 8080]:
                score += self._weights.get("WEB_NO_HTTPS", 15.0)
            # Evaluar por categorías de servicio
            elif category == ServiceCategory.ADMIN or category == ServiceCategory.REMOTE_ACCESS:
                score += self._weights.get("ADMIN", 25.0)
            elif category == ServiceCategory.DATABASE:
                score += self._weights.get("DATABASE", 30.0)
            elif category == ServiceCategory.CACHE:
                score += self._weights.get("CACHE", 25.0)
            else:
                score += self._weights.get("OTHER_OPEN", 10.0)

        # Capar el score en el rango reglamentario de [0.0, 100.0]
        final_score = min(max(score, 0.0), 100.0)

        # Determinar nivel de riesgo
        final_risk = RiskLevel.LOW
        for level_str, r in self._thresholds.items():
            if int(final_score) in r:
                final_risk = RiskLevel[level_str]
                break

        return final_score, final_risk
