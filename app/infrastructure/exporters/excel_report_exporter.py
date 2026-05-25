import logging
from pathlib import Path

import pandas as pd

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.domain.entities.port_scan_result import PortScanResult
from app.domain.entities.target_scan_report import TargetScanReport
from app.domain.exceptions.domain_exceptions import ExporterException
from app.domain.value_objects.port_status import PortStatus
from app.shared.filename_utils import get_unique_filename


class ExcelReportExporter(ReportExporterInterface):
    """Adaptador de infraestructura para exportar los reportes consolidados a planillas Excel."""

    def __init__(self):
        self._logger = logging.getLogger("ports_detector")

    def export(
        self,
        reports: list[TargetScanReport],
        directory: Path,
        base_filename: str
    ) -> Path:
        """Genera una planilla de cálculo Excel multioja detallada.

        Raises:
            ExporterException: Si ocurre un error al procesar o escribir el archivo Excel.
        """
        # 1. Resolver un nombre de archivo único para evitar sobreescrituras
        file_path = get_unique_filename(directory, base_filename, "xlsx")

        try:
            df_resumen = self._build_resumen_df(reports)
            df_abiertos = self._build_puertos_abiertos_df(reports)
            df_detalle = self._build_detalle_escaneo_df(reports)
            df_recom = self._build_recomendaciones_df(reports)
            df_errores = self._build_errores_df(reports)

            # Escribir el libro Excel multioja
            with pd.ExcelWriter(file_path, engine="openpyxl") as writer:
                df_resumen.to_excel(writer, sheet_name="Resumen", index=False)
                df_abiertos.to_excel(
                    writer, sheet_name="Puertos Abiertos", index=False)
                df_detalle.to_excel(
                    writer, sheet_name="Detalle Escaneo", index=False)
                df_recom.to_excel(
                    writer, sheet_name="Recomendaciones", index=False)
                df_errores.to_excel(writer, sheet_name="Errores", index=False)

            self._logger.info(
                f"Reporte de auditoría Excel escrito con éxito en: {file_path}")
            return file_path

        except Exception as e:
            raise ExporterException(
                f"Ocurrió un error inesperado al compilar el reporte Excel: {e}"
            )

    def _build_resumen_df(self, reports: list[TargetScanReport]) -> pd.DataFrame:
        """Construye el DataFrame para la hoja Resumen."""
        resumen_data = []
        for r in reports:
            resumen_data.append({
                "target": r.target,
                "ip_resuelta": r.ip,
                "total_puertos_escaneados": r.total_ports_scanned,
                "puertos_abiertos": r.open_ports_count,
                "score_riesgo": r.risk_score,
                "nivel_riesgo": r.risk_level.value,
                "estado": "COMPLETADO" if not r.error else "FALLIDO",
                "error": r.error if r.error else "",
                "fecha_analisis": r.scan_date.strftime("%Y-%m-%d %H:%M:%S")
            })
        return pd.DataFrame(
            resumen_data,
            columns=[
                "target", "ip_resuelta", "total_puertos_escaneados",
                "puertos_abiertos", "score_riesgo", "nivel_riesgo",
                "estado", "error", "fecha_analisis"
            ]
        )

    def _build_puertos_abiertos_df(self, reports: list[TargetScanReport]) -> pd.DataFrame:
        """Construye el DataFrame para la hoja Puertos Abiertos."""
        puertos_abiertos_data = []
        for r in reports:
            for port_res in r.open_ports:
                item = self._build_puerto_abierto_dict(port_res)
                if item:
                    puertos_abiertos_data.append(item)
        return pd.DataFrame(
            puertos_abiertos_data,
            columns=[
                "target", "ip_resuelta", "puerto", "servicio",
                "categoria", "banner", "nivel_riesgo",
                "riesgo_detectado", "recomendacion"
            ]
        )

    def _build_puerto_abierto_dict(self, port_res: PortScanResult) -> dict | None:
        """Construye el diccionario de datos para un puerto abierto expuesto."""
        if port_res.status != PortStatus.OPEN:
            return None
        return {
            "target": port_res.target,
            "ip_resuelta": port_res.ip,
            "puerto": port_res.port,
            "servicio": port_res.service_name,
            "categoria": port_res.service_category.value,
            "banner": port_res.banner or "",
            "nivel_riesgo": port_res.risk_level.value,
            "riesgo_detectado": port_res.error or "",
            "recomendacion": port_res.recommendation or ""
        }

    def _build_detalle_escaneo_df(self, reports: list[TargetScanReport]) -> pd.DataFrame:
        """Construye el DataFrame para la hoja Detalle Escaneo."""
        detalle_escaneo_data = []
        for r in reports:
            for port_res in r.open_ports:
                detalle_escaneo_data.append({
                    "target": port_res.target,
                    "ip_resuelta": port_res.ip,
                    "puerto": port_res.port,
                    "estado": port_res.status.value,
                    "servicio": port_res.service_name,
                    "categoria": port_res.service_category.value,
                    "error": port_res.error or "",
                    "fecha_analisis": r.scan_date.strftime("%Y-%m-%d %H:%M:%S")
                })
        return pd.DataFrame(
            detalle_escaneo_data,
            columns=[
                "target", "ip_resuelta", "puerto", "estado",
                "servicio", "categoria", "error", "fecha_analisis"
            ]
        )

    def _build_recomendaciones_df(self, reports: list[TargetScanReport]) -> pd.DataFrame:
        """Construye el DataFrame para la hoja Recomendaciones."""
        recomendaciones_data = []
        for r in reports:
            for rec in r.recommendations:
                recomendaciones_data.append({
                    "target": rec["target"],
                    "puerto": rec["puerto"],
                    "servicio": rec["servicio"],
                    "prioridad": rec["prioridad"],
                    "problema": rec["problema"],
                    "recomendacion": rec["recomendacion"]
                })
        return pd.DataFrame(
            recomendaciones_data,
            columns=[
                "target", "puerto", "servicio",
                "prioridad", "problema", "recomendacion"
            ]
        )

    def _build_errores_df(self, reports: list[TargetScanReport]) -> pd.DataFrame:
        """Construye el DataFrame para la hoja Errores."""
        errores_data = []
        for r in reports:
            if r.error:
                errores_data.append({
                    "target": r.target,
                    "tipo_error": "FALLO_AUDITORIA",
                    "mensaje_error": r.error,
                    "fecha_analisis": r.scan_date.strftime("%Y-%m-%d %H:%M:%S")
                })
        return pd.DataFrame(
            errores_data,
            columns=["target", "tipo_error", "mensaje_error", "fecha_analisis"]
        )
