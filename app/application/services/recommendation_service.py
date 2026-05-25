from app.shared.constants import RISK_MAPPINGS


class RecommendationService:
    """Genera pautas defensivas de hardening basadas en servicios expuestos."""

    def get_recommendation(self, port: int) -> str:
        """Obtiene la directiva de hardening recomendada para un puerto TCP abierto.

        Args:
            port (int): Puerto de red expuesto.

        Returns:
            str: Recomendación técnica y medidas mitigadoras de hardening.
        """
        mapping = RISK_MAPPINGS.get(port)
        if mapping:
            return mapping["recommendation"]

        # Recomendación genérica por defecto
        return (
            f"Restringir acceso al puerto {port} en el firewall perimetral. "
            f"Validar si es estrictamente requerido su uso público y moverlo detrás de una VPN o túnel SSH."
        )
