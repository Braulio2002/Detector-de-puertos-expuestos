import ipaddress
import re
import socket

from app.domain.entities.scan_target import ScanTarget
from app.domain.exceptions.domain_exceptions import InvalidTargetException


class TargetValidatorService:
    """Valida la sintaxis de IPs/Dominios y realiza la resolución DNS."""

    # Expresión regular simplificada y robusta para validar nombres de host de dominio
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    )

    def validate_and_resolve(self, target: str) -> ScanTarget:
        """Valida que la entrada sea una IP o Dominio válido y resuelve su IP de ser necesario.

        Args:
            target (str): IP o dominio a evaluar.

        Raises:
            InvalidTargetException: Si no cumple con un formato válido o no se puede resolver el DNS.

        Returns:
            ScanTarget: Objeto ScanTarget del dominio con los datos resueltos.
        """
        clean_target = target.strip().lower()

        if not clean_target:
            raise InvalidTargetException(
                target, "El target no puede estar vacío.")

        # Manejar 'localhost' de forma especial
        if clean_target == "localhost":
            return ScanTarget(
                target_original=target,
                ip_resuelta="127.0.0.1",
                tipo="DOMAIN"
            )

        # 1. Intentar validar como dirección IP (v4 o v6)
        try:
            ipaddress.ip_address(clean_target)
            return ScanTarget(
                target_original=target,
                ip_resuelta=clean_target,
                tipo="IP"
            )
        except ValueError:
            # No es una dirección IP sintáctica válida, probar como dominio
            pass

        # 2. Validar sintaxis de Dominio
        if not self.DOMAIN_REGEX.match(clean_target):
            raise InvalidTargetException(
                target, "No tiene formato de dirección IP ni de dominio válido."
            )

        # 3. Resolver Dominio a IP
        try:
            # Obtiene la IP asociada al nombre de host
            ip_resuelta = socket.gethostbyname(clean_target)
            return ScanTarget(
                target_original=target,
                ip_resuelta=ip_resuelta,
                tipo="DOMAIN"
            )
        except socket.gaierror as e:
            raise InvalidTargetException(
                target, f"No se pudo resolver el nombre de dominio a nivel DNS. Error original: {e}"
            )
        except Exception as e:
            raise InvalidTargetException(
                target, f"Error inesperado al resolver DNS: {e}"
            )
