from pathlib import Path

from app.shared.constants import DEFAULT_PORTS


class Settings:
    """Configuraciones globales del Detector de Puertos Expuestos."""

    # Directorios Base
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    INPUT_DIR: Path = BASE_DIR / "datos_entrada"
    OUTPUT_DIR: Path = BASE_DIR / "datos_salida"
    TARGETS_FILE: Path = INPUT_DIR / "targets.txt"

    # Configuración del Escaneo
    DEFAULT_PORTS_TO_SCAN: list[int] = DEFAULT_PORTS
    SOCKET_TIMEOUT: float = 2.0  # en segundos
    MAX_CONCURRENCY: int = 10  # número máximo de hilos en ThreadPoolExecutor (1 = secuencial por defecto)
    ENABLE_BANNER_GRABBING: bool = True

    # Nombres Base de Reportes
    REPORT_EXCEL_NAME: str = "exposed_ports_report"
    REPORT_JSON_NAME: str = "exposed_ports_report"

    # Pesos y Penalizaciones de Riesgo para Scoring
    SCORING_WEIGHTS: dict[str, float] = {
        "ADMIN": 25.0,        # Ej: SSH, Telnet, Docker, RDP expuestos
        "DATABASE": 30.0,     # Ej: MySQL, PostgreSQL, SQL Server expuestos
        "INSECURE": 25.0,     # Ej: Telnet, FTP expuestos en texto plano
        "WEB_NO_HTTPS": 15.0, # Ej: HTTP (puerto 80) sin cifrar expuesto
        "CACHE": 25.0,        # Ej: Redis, Elasticsearch, Memcached expuestos
        "OTHER_OPEN": 10.0    # Cualquier puerto abierto genérico
    }

    # Rangos de Clasificación de Riesgo
    RISK_THRESHOLDS: dict[str, range] = {
        "LOW": range(0, 21),       # 0 a 20
        "MEDIUM": range(21, 51),   # 21 a 50
        "HIGH": range(51, 76),     # 51 a 75
        "CRITICAL": range(76, 101) # 76 a 100
    }
