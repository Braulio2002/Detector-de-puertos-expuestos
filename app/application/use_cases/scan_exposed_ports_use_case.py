import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.application.interfaces.target_reader_interface import TargetReaderInterface
from app.application.services.port_scanner_service import PortScannerService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.risk_analyzer_service import RiskAnalyzerService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.service_identifier_service import ServiceIdentifierService
from app.application.services.target_validator_service import TargetValidatorService
from app.domain.entities.port_scan_result import PortScanResult
from app.domain.entities.target_scan_report import TargetScanReport
from app.domain.exceptions.domain_exceptions import InvalidTargetException
from app.domain.value_objects.port_status import PortStatus
from app.domain.value_objects.risk_level import RiskLevel


class ScanExposedPortsUseCase:
    """Caso de uso principal encargado de orquestar el flujo completo de detección de puertos expuestos."""

    def __init__(
        self,
        directory_manager: Any,
        target_reader: TargetReaderInterface,
        target_validator: TargetValidatorService,
        port_scanner: PortScannerService,
        service_identifier: ServiceIdentifierService,
        risk_analyzer: RiskAnalyzerService,
        score_calculator: ScoreCalculatorService,
        recommendation_service: RecommendationService,
        excel_exporter: ReportExporterInterface,
        json_exporter: ReportExporterInterface
    ):
        """Inyección de dependencias de interfaces y servicios de aplicación."""
        self._directory_manager = directory_manager
        self._target_reader = target_reader
        self._target_validator = target_validator
        self._port_scanner = port_scanner
        self._service_identifier = service_identifier
        self._risk_analyzer = risk_analyzer
        self._score_calculator = score_calculator
        self._recommendation_service = recommendation_service
        self._excel_exporter = excel_exporter
        self._json_exporter = json_exporter
        self._logger = logging.getLogger("ports_detector")

    def execute(
        self,
        ports_to_scan: list[int],
        timeout: float,
        concurrency: int,
        grab_banner: bool,
        output_dir: Path,
        excel_base_name: str,
        json_base_name: str
    ) -> list[TargetScanReport]:
        """Ejecuta el flujo completo de auditoría perimetral de puertos expuestos.

        Returns:
            List[TargetScanReport]: Lista de reportes consolidados por cada target procesado.
        """
        # 1. Asegurar la estructura de directorios en el sistema de archivos
        self._logger.info(
            "Verificando y creando estructura de directorios si es necesario...")
        self._directory_manager.ensure_directories()

        # 2. Leer targets desde el origen de datos
        self._logger.info(
            "Leyendo objetivos de auditoría desde targets.txt...")
        raw_targets = self._target_reader.read_targets()
        self._logger.info(
            f"Objetivos iniciales encontrados en origen: {len(raw_targets)}")

        if not raw_targets:
            self._logger.warning(
                "No se encontraron targets válidos para auditar. El proceso finalizará.")
            return []

        reports: list[TargetScanReport] = []

        # 3. Procesar y auditar cada target
        for target_str in raw_targets:
            report = self._process_target(
                target_str=target_str,
                ports_to_scan=ports_to_scan,
                timeout=timeout,
                concurrency=concurrency,
                grab_banner=grab_banner
            )
            reports.append(report)

        # 4. Exportar reportes generados a Excel y JSON
        self._export_reports_if_any(reports, output_dir, excel_base_name, json_base_name)

        self._logger.info("Proceso finalizado")
        return reports

    def _process_target(
        self,
        target_str: str,
        ports_to_scan: list[int],
        timeout: float,
        concurrency: int,
        grab_banner: bool
    ) -> TargetScanReport:
        """Procesa, escanea y evalúa un único objetivo de auditoría."""
        self._logger.info(f"Iniciando procesamiento de objetivo: {target_str}")
        try:
            # Validar y resolver DNS
            self._logger.info(f"Validando y resolviendo DNS para: {target_str}...")
            scan_target = self._target_validator.validate_and_resolve(target_str)
            self._logger.info(
                f"Objetivo validado con éxito. Tipo: {scan_target.tipo}, IP: {scan_target.ip_resuelta}"
            )

            # Realizar el escaneo de puertos TCP
            self._logger.info(f"Escaneando target: {scan_target.target_original}")
            raw_results = self._port_scanner.scan(
                target=scan_target.target_original,
                ip=scan_target.ip_resuelta,
                ports=ports_to_scan,
                timeout=timeout,
                concurrency=concurrency,
                grab_banner=grab_banner
            )

            # Clasificar y enriquecer los resultados de puertos con lógica de dominio
            enriched_results, open_ports, closed_count, filtered_count, error_count = (
                self._enrich_scan_results(raw_results)
            )

            # Calcular scoring global de riesgo perimetral
            self._logger.info("Calculando score de riesgo global y nivel de criticidad...")
            risk_score, risk_level = self._score_calculator.calculate(open_ports)

            # Compilar recomendaciones
            target_recommendations = self._compile_recommendations(open_ports)

            # Construir reporte consolidado del target
            return TargetScanReport(
                target=scan_target.target_original,
                ip=scan_target.ip_resuelta,
                total_ports_scanned=len(ports_to_scan),
                open_ports_count=len(open_ports),
                closed_ports_count=closed_count,
                filtered_ports_count=filtered_count + error_count,
                open_ports=enriched_results,
                risk_score=risk_score,
                risk_level=risk_level,
                recommendations=target_recommendations,
                scan_date=datetime.now()
            )

        except InvalidTargetException as e:
            self._logger.error(f"Error de validación: {e}")
            return TargetScanReport(
                target=target_str,
                ip="N/A",
                total_ports_scanned=0,
                open_ports_count=0,
                closed_ports_count=0,
                filtered_ports_count=0,
                open_ports=[],
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                scan_date=datetime.now(),
                error=e.reason
            )

        except Exception as e:
            self._logger.error(
                f"Error no controlado al auditar el objetivo '{target_str}': {e}"
            )
            return TargetScanReport(
                target=target_str,
                ip="N/A",
                total_ports_scanned=0,
                open_ports_count=0,
                closed_ports_count=0,
                filtered_ports_count=0,
                open_ports=[],
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                scan_date=datetime.now(),
                error=f"Fallo crítico interno del escáner: {e}"
            )

    def _enrich_scan_results(
        self,
        raw_results: list[PortScanResult]
    ) -> tuple[list[PortScanResult], list[PortScanResult], int, int, int]:
        """Enriquece los puertos escaneados y calcula los contadores de sus estados."""
        enriched_results: list[PortScanResult] = []
        open_ports: list[PortScanResult] = []
        closed_count = 0
        filtered_count = 0
        error_count = 0

        for res in raw_results:
            enriched_res = self._enrich_port_result(res)
            enriched_results.append(enriched_res)

            if res.status == PortStatus.OPEN:
                open_ports.append(enriched_res)
                self._logger.info(
                    f"¡Puerto abierto detectado! {res.port}/{enriched_res.service_name} [{enriched_res.risk_level.value}]"
                )
            elif res.status == PortStatus.CLOSED:
                closed_count += 1
            elif res.status == PortStatus.FILTERED:
                filtered_count += 1
            else:
                error_count += 1

        return enriched_results, open_ports, closed_count, filtered_count, error_count

    def _enrich_port_result(self, res: PortScanResult) -> PortScanResult:
        """Enriquece un único PortScanResult con información de servicio, riesgo y mitigaciones."""
        service_name, service_category = self._service_identifier.identify(res.port)

        if res.status == PortStatus.OPEN:
            risk_level, _ = self._risk_analyzer.analyze(res.port)
            recommendation = self._recommendation_service.get_recommendation(res.port)
            return PortScanResult(
                target=res.target,
                ip=res.ip,
                port=res.port,
                status=res.status,
                service_name=service_name,
                service_category=service_category,
                banner=res.banner,
                risk_level=risk_level,
                recommendation=recommendation,
                error=res.error
            )
        else:
            return PortScanResult(
                target=res.target,
                ip=res.ip,
                port=res.port,
                status=res.status,
                service_name=service_name,
                service_category=service_category,
                banner=None,
                risk_level=RiskLevel.LOW,
                recommendation=None,
                error=res.error
            )

    def _compile_recommendations(self, open_ports: list[PortScanResult]) -> list[dict[str, Any]]:
        """Compila y estructura el informe de recomendaciones técnicas para puertos expuestos."""
        target_recommendations: list[dict[str, Any]] = []
        for open_res in open_ports:
            risk_desc = (
                open_res.error
                if open_res.error
                else self._risk_analyzer.analyze(open_res.port)[1]
            )
            target_recommendations.append(
                {
                    "target": open_res.target,
                    "puerto": open_res.port,
                    "servicio": open_res.service_name,
                    "prioridad": open_res.risk_level.value,
                    "problema": risk_desc,
                    "recomendacion": open_res.recommendation
                }
            )
        return target_recommendations

    def _export_reports_if_any(
        self,
        reports: list[TargetScanReport],
        output_dir: Path,
        excel_base_name: str,
        json_base_name: str
    ) -> None:
        """Orquesta la exportación del consolidado de auditoría a Excel y JSON."""
        if not reports:
            return

        try:
            self._logger.info("Generando reporte estructurado en Excel...")
            excel_path = self._excel_exporter.export(
                reports, output_dir, excel_base_name)
            self._logger.info(
                f"Reporte Excel generado correctamente: {excel_path}")

            self._logger.info("Generando reporte estructurado en JSON...")
            json_path = self._json_exporter.export(
                reports, output_dir, json_base_name)
            self._logger.info(
                f"Reporte JSON generado correctamente: {json_path}")
        except Exception as e:
            self._logger.error(
                f"Fallo al exportar los reportes de auditoría: {e}")
