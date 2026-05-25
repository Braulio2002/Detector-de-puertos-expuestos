import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.application.interfaces.tcp_scanner_interface import TcpScannerInterface
from app.domain.entities.port_scan_result import PortScanResult
from app.domain.value_objects.port_status import PortStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.service_category import ServiceCategory


class PortScannerService:
    """Orquesta el escaneo de una lista de puertos sobre un objetivo específico."""

    def __init__(self, tcp_scanner: TcpScannerInterface):
        """Inyecta el escáner TCP concreto de la capa de infraestructura.

        Args:
            tcp_scanner (TcpScannerInterface): Implementación del escáner de red.
        """
        self._tcp_scanner = tcp_scanner
        self._logger = logging.getLogger("ports_detector")

    def scan(
        self,
        target: str,
        ip: str,
        ports: list[int],
        timeout: float,
        concurrency: int,
        grab_banner: bool
    ) -> list[PortScanResult]:
        """Realiza el escaneo de puertos respetando la concurrencia y timeouts definidos.

        Args:
            target (str): Target original ingresado.
            ip (str): IP resuelta.
            ports (List[int]): Lista de puertos a escanear.
            timeout (float): Timeout por conexión TCP.
            concurrency (int): Máximo de hilos concurrentes. Si es <= 1, se escanea secuencial.
            grab_banner (bool): Determina si se intentará extraer el banner de red.

        Returns:
            List[PortScanResult]: Lista consolidada de resultados individuales de escaneo por puerto.
        """
        results: list[PortScanResult] = []

        if concurrency > 1 and len(ports) > 1:
            self._logger.info(
                f"Iniciando escaneo concurrente de {len(ports)} puertos para {target} (Concurrencia: {concurrency})."
            )
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                # Mapear los futures a cada puerto
                futures = {
                    executor.submit(
                        self._tcp_scanner.scan_port,
                        target,
                        ip,
                        port,
                        timeout,
                        grab_banner
                    ): port
                    for port in ports
                }

                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        res = future.result()
                        results.append(res)
                    except Exception as e:
                        self._logger.error(
                            f"Error crítico al escanear el puerto {port} en {target}: {e}"
                        )
                        results.append(
                            PortScanResult(
                                target=target,
                                ip=ip,
                                port=port,
                                status=PortStatus.ERROR,
                                service_name=f"Error ({port})",
                                service_category=ServiceCategory.UNKNOWN,
                                risk_level=RiskLevel.LOW,
                                error=str(e)
                            )
                        )
        else:
            self._logger.info(
                f"Iniciando escaneo secuencial de {len(ports)} puertos para {target}."
            )
            for port in ports:
                try:
                    res = self._tcp_scanner.scan_port(
                        target, ip, port, timeout, grab_banner
                    )
                    results.append(res)
                except Exception as e:
                    self._logger.error(
                        f"Error crítico al escanear secuencialmente el puerto {port} en {target}: {e}"
                    )
                    results.append(
                        PortScanResult(
                            target=target,
                            ip=ip,
                            port=port,
                            status=PortStatus.ERROR,
                            service_name=f"Error ({port})",
                            service_category=ServiceCategory.UNKNOWN,
                            risk_level=RiskLevel.LOW,
                            error=str(e)
                        )
                    )

        # Ordenar los resultados por puerto para mantener consistencia en reportes
        results.sort(key=lambda r: r.port)
        return results
