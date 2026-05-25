from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.target_scan_report import TargetScanReport


class ReportExporterInterface(ABC):
    """Interfaz abstracta que define la serialización y exportación de reportes de auditoría."""

    @abstractmethod
    def export(
        self,
        reports: list[TargetScanReport],
        directory: Path,
        base_filename: str
    ) -> Path:
        """Serializa y guarda la lista de reportes en el formato de destino.

        Args:
            reports (List[TargetScanReport]): Informes consolidados de los objetivos.
            directory (Path): Directorio de salida donde guardar el archivo.
            base_filename (str): Nombre base del archivo a generar.

        Returns:
            Path: Ruta absoluta al archivo generado.
        """
        pass
