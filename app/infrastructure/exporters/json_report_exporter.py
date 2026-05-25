import json
import logging
from pathlib import Path
from typing import Any

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.domain.entities.target_scan_report import TargetScanReport
from app.domain.exceptions.domain_exceptions import ExporterException
from app.shared.filename_utils import get_unique_filename


class JsonReportExporter(ReportExporterInterface):
    """Adaptador de infraestructura para exportar los reportes consolidados a formato estructurado JSON."""

    def __init__(self):
        self._logger = logging.getLogger("ports_detector")

    def export(
        self,
        reports: list[TargetScanReport],
        directory: Path,
        base_filename: str
    ) -> Path:
        """Serializa y guarda la lista de reportes en un archivo JSON.

        Raises:
            ExporterException: Si ocurre un error al procesar o escribir el archivo JSON.
        """
        # 1. Obtener un nombre de archivo único
        file_path = get_unique_filename(directory, base_filename, "json")

        try:
            serialized_reports = []

            for r in reports:
                # Convertir dataclass a diccionario serializable
                report_dict: dict[str, Any] = {
                    "target": r.target,
                    "ip": r.ip,
                    "total_ports_scanned": r.total_ports_scanned,
                    "open_ports_count": r.open_ports_count,
                    "closed_ports_count": r.closed_ports_count,
                    "filtered_ports_count": r.filtered_ports_count,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level.value,
                    "scan_date": r.scan_date.isoformat(),
                    "error": r.error,
                    "open_ports": [],
                    "recommendations": r.recommendations
                }

                # Serializar el detalle de puertos individuales
                for port_res in r.open_ports:
                    report_dict["open_ports"].append({
                        "target": port_res.target,
                        "ip": port_res.ip,
                        "port": port_res.port,
                        "status": port_res.status.value,
                        "service_name": port_res.service_name,
                        "service_category": port_res.service_category.value,
                        "banner": port_res.banner,
                        "risk_level": port_res.risk_level.value,
                        "recommendation": port_res.recommendation,
                        "error": port_res.error
                    })

                serialized_reports.append(report_dict)

            # Escribir el archivo JSON con indentación y encoding UTF-8
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(serialized_reports, f, indent=4, ensure_ascii=False)

            self._logger.info(
                f"Reporte de auditoría JSON escrito con éxito en: {file_path}")
            return file_path

        except Exception as e:
            raise ExporterException(
                f"Ocurrió un fallo no controlado al escribir el reporte JSON: {e}"
            )
