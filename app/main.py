from app.application.services.port_scanner_service import PortScannerService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.risk_analyzer_service import RiskAnalyzerService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.service_identifier_service import ServiceIdentifierService
from app.application.services.target_validator_service import TargetValidatorService
from app.application.use_cases.scan_exposed_ports_use_case import ScanExposedPortsUseCase
from app.config.settings import Settings
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter
from app.infrastructure.filesystem.directory_manager import DirectoryManager
from app.infrastructure.readers.txt_target_reader import TxtTargetReader
from app.infrastructure.scanners.socket_tcp_scanner import SocketTcpScanner
from app.presentation.cli import CLI
from app.shared.logger import setup_logger


def main() -> None:
    """Función de arranque e inyección de dependencias para el Detector de Puertos Expuestos."""
    # 1. Inicializar Logger
    setup_logger()

    # 2. Inicializar Infraestructura
    directory_manager = DirectoryManager(
        input_dir=Settings.INPUT_DIR,
        output_dir=Settings.OUTPUT_DIR,
        targets_file=Settings.TARGETS_FILE
    )
    target_reader = TxtTargetReader(file_path=Settings.TARGETS_FILE)
    tcp_scanner = SocketTcpScanner()
    excel_exporter = ExcelReportExporter()
    json_exporter = JsonReportExporter()

    # 3. Inicializar Servicios de Aplicación
    target_validator = TargetValidatorService()
    service_identifier = ServiceIdentifierService()
    risk_analyzer = RiskAnalyzerService()
    score_calculator = ScoreCalculatorService(
        weights=Settings.SCORING_WEIGHTS,
        thresholds=Settings.RISK_THRESHOLDS
    )
    recommendation_service = RecommendationService()
    port_scanner = PortScannerService(tcp_scanner=tcp_scanner)

    # 4. Inicializar Caso de Uso Principal (Inyección)
    use_case = ScanExposedPortsUseCase(
        directory_manager=directory_manager,
        target_reader=target_reader,
        target_validator=target_validator,
        port_scanner=port_scanner,
        service_identifier=service_identifier,
        risk_analyzer=risk_analyzer,
        score_calculator=score_calculator,
        recommendation_service=recommendation_service,
        excel_exporter=excel_exporter,
        json_exporter=json_exporter
    )

    # 5. Ejecutar la Capa de Presentación
    cli = CLI(use_case=use_case)
    cli.run()


if __name__ == "__main__":
    main()
