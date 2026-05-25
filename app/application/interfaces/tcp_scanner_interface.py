from abc import ABC, abstractmethod

from app.domain.entities.port_scan_result import PortScanResult


class TcpScannerInterface(ABC):
    """Interfaz abstracta para el motor de escaneo de puertos TCP."""

    @abstractmethod
    def scan_port(
        self,
        target: str,
        ip: str,
        port: int,
        timeout: float,
        grab_banner: bool
    ) -> PortScanResult:
        """Efectúa un intento de conexión TCP Connect sobre un puerto.

        Args:
            target (str): El dominio o IP original ingresado por el usuario.
            ip (str): La dirección IP ya resuelta.
            port (int): El puerto numérico a auditar.
            timeout (float): Límite de tiempo en segundos para establecer conexión.
            grab_banner (bool): Determina si se intentará extraer el banner de forma segura.

        Returns:
            PortScanResult: El resultado de la auditoría del puerto.
        """
        pass
