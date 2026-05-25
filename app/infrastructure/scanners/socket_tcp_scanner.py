import errno
import socket
import ssl

from app.application.interfaces.tcp_scanner_interface import TcpScannerInterface
from app.domain.entities.port_scan_result import PortScanResult
from app.domain.value_objects.port_status import PortStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.service_category import ServiceCategory


class SocketTcpScanner(TcpScannerInterface):
    """Implementación de bajo nivel del escáner TCP utilizando sockets nativos de Python."""

    def scan_port(
        self,
        target: str,
        ip: str,
        port: int,
        timeout: float,
        grab_banner: bool
    ) -> PortScanResult:
        """Efectúa una conexión TCP Connect básica y segura, extrayendo el banner si el puerto está abierto.

        Args:
            target (str): Target original (IP o Dominio).
            ip (str): IP de red resuelta a escanear.
            port (int): Puerto TCP a consultar.
            timeout (float): Límite de tiempo en segundos.
            grab_banner (bool): Habilitar banner grabbing pasivo y no invasivo.

        Returns:
            PortScanResult: Resultado de auditoría del puerto con clasificación de estado.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        banner = None
        status = PortStatus.CLOSED
        err_msg = None

        try:
            # connect_ex retorna 0 si la conexión se establece (apretón de manos de tres vías completo)
            err = sock.connect_ex((ip, port))

            if err == 0:
                status = PortStatus.OPEN

                # Ejecutar banner grabbing pasivo de forma segura si está configurado
                if grab_banner:
                    banner = self._attempt_banner_grabbing(sock, target, port)
            elif err in (errno.ETIMEDOUT, 10060, errno.EHOSTUNREACH, errno.ENETUNREACH):
                # 10060 es WSAETIMEDOUT en Windows
                status = PortStatus.FILTERED
            elif err in (errno.ECONNREFUSED, 10061):
                # 10061 es WSAECONNREFUSED en Windows
                status = PortStatus.CLOSED
            else:
                status = PortStatus.CLOSED

        except TimeoutError:
            status = PortStatus.FILTERED
        except Exception as e:
            status = PortStatus.ERROR
            err_msg = str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return PortScanResult(
            target=target,
            ip=ip,
            port=port,
            status=status,
            service_name="Desconocido",  # Se enriquecerá en el Caso de Uso / Servicios
            service_category=ServiceCategory.UNKNOWN,
            banner=banner,
            risk_level=RiskLevel.LOW,
            error=err_msg
        )

    def _attempt_banner_grabbing(self, sock: socket.socket, target: str, port: int) -> str | None:
        """Intenta extraer un banner descriptivo del servicio de manera pasiva y segura.

        No altera el estado de la conexión abierta ni realiza pruebas invasivas.
        """
        try:
            # Asignar un timeout extremadamente corto para el banner grabbing para evitar colgar el escaneo
            sock.settimeout(1.5)

            # A. Puertos HTTP Estándar y Alternativos
            if port in (80, 8000, 8080):
                return self._grab_http_banner(sock, target)

            # B. Puertos HTTPS Estándar y Alternativos (requieren encapsulado SSL/TLS)
            if port in (443, 8443):
                return self._grab_https_banner(sock, target)

            # C. Servicios 'Talk-First' (FTP, SSH, SMTP, Telnet envían un banner al conectar)
            return self._grab_default_banner(sock)

        except Exception:
            # Los fallos de banner no deben invalidar que el puerto esté catalogado como OPEN
            pass

        return None

    def _grab_http_banner(self, sock: socket.socket, target: str) -> str | None:
        """Intenta obtener el banner HTTP enviando una petición HEAD."""
        try:
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("utf-8", errors="ignore"))
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            for line in response.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            if response:
                return response.split("\r\n")[0].strip()
        except Exception:
            pass
        return None

    def _grab_https_banner(self, sock: socket.socket, target: str) -> str | None:
        """Intenta obtener el banner HTTPS envolviendo el socket en SSL/TLS de forma segura."""
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode("utf-8", errors="ignore"))
                response = ssock.recv(1024).decode("utf-8", errors="ignore")
                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                if response:
                    return response.split("\r\n")[0].strip()
        except Exception:
            pass
        return None

    def _grab_default_banner(self, sock: socket.socket) -> str | None:
        """Intenta obtener el banner por defecto (para protocolos interactivos 'Talk-First')."""
        try:
            data = sock.recv(512)
            if data:
                banner_str = data.decode("utf-8", errors="ignore").strip()
                return banner_str.replace("\r", "").replace("\n", " ").strip()
        except Exception:
            pass
        return None
