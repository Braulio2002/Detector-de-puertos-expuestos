from pathlib import Path
from unittest.mock import MagicMock

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.application.interfaces.target_reader_interface import TargetReaderInterface
from app.application.services.port_scanner_service import PortScannerService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.risk_analyzer_service import RiskAnalyzerService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.service_identifier_service import ServiceIdentifierService
from app.application.services.target_validator_service import TargetValidatorService
from app.application.use_cases.scan_exposed_ports_use_case import ScanExposedPortsUseCase
from app.config.settings import Settings
from app.domain.entities.port_scan_result import PortScanResult
from app.domain.entities.scan_target import ScanTarget
from app.domain.value_objects.port_status import PortStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.service_category import ServiceCategory


def test_integration_full_scan_flow():
    # 1. Crear mocks de infraestructura
    mock_directory_manager = MagicMock()

    mock_target_reader = MagicMock(spec=TargetReaderInterface)
    mock_target_reader.read_targets.return_value = ["127.0.0.1", "localhost"]

    mock_validator = MagicMock(spec=TargetValidatorService)
    mock_validator.validate_and_resolve.side_effect = [
        ScanTarget(target_original="127.0.0.1", ip_resuelta="127.0.0.1", tipo="IP"),
        ScanTarget(target_original="localhost", ip_resuelta="127.0.0.1", tipo="DOMAIN")
    ]

    # Mockear el escáner TCP para que retorne puertos abiertos
    mock_port_scanner_service = MagicMock(spec=PortScannerService)

    # 127.0.0.1 tendrá el puerto 22 abierto
    mock_port_scanner_service.scan.side_effect = [
        [
            PortScanResult(
                target="127.0.0.1", ip="127.0.0.1", port=22, status=PortStatus.OPEN,
                service_name="Desconocido", service_category=ServiceCategory.UNKNOWN
            ),
            PortScanResult(
                target="127.0.0.1", ip="127.0.0.1", port=80, status=PortStatus.CLOSED,
                service_name="Desconocido", service_category=ServiceCategory.UNKNOWN
            )
        ],
        # localhost tendrá todos cerrados
        [
            PortScanResult(
                target="localhost", ip="127.0.0.1", port=22, status=PortStatus.CLOSED,
                service_name="Desconocido", service_category=ServiceCategory.UNKNOWN
            ),
            PortScanResult(
                target="localhost", ip="127.0.0.1", port=80, status=PortStatus.CLOSED,
                service_name="Desconocido", service_category=ServiceCategory.UNKNOWN
            )
        ]
    ]

    # Inicializar servicios reales
    service_identifier = ServiceIdentifierService()
    risk_analyzer = RiskAnalyzerService()
    score_calculator = ScoreCalculatorService(
        weights=Settings.SCORING_WEIGHTS,
        thresholds=Settings.RISK_THRESHOLDS
    )
    recommendation_service = RecommendationService()

    mock_excel_exporter = MagicMock(spec=ReportExporterInterface)
    mock_excel_exporter.export.return_value = Path("/mock/datos_salida/report.xlsx")

    mock_json_exporter = MagicMock(spec=ReportExporterInterface)
    mock_json_exporter.export.return_value = Path("/mock/datos_salida/report.json")

    # 2. Instanciar caso de uso principal
    use_case = ScanExposedPortsUseCase(
        directory_manager=mock_directory_manager,
        target_reader=mock_target_reader,
        target_validator=mock_validator,
        port_scanner=mock_port_scanner_service,
        service_identifier=service_identifier,
        risk_analyzer=risk_analyzer,
        score_calculator=score_calculator,
        recommendation_service=recommendation_service,
        excel_exporter=mock_excel_exporter,
        json_exporter=mock_json_exporter
    )

    # 3. Ejecutar
    reports = use_case.execute(
        ports_to_scan=[22, 80],
        timeout=1.0,
        concurrency=2,
        grab_banner=False,
        output_dir=Path("/mock/datos_salida"),
        excel_base_name="report",
        json_base_name="report"
    )

    # 4. Validar
    assert len(reports) == 2

    # Reporte 1: 127.0.0.1 (Tiene puerto 22 abierto)
    r1 = reports[0]
    assert r1.target == "127.0.0.1"
    assert r1.ip == "127.0.0.1"
    assert r1.open_ports_count == 1
    assert r1.closed_ports_count == 1
    assert r1.risk_score == 25.0
    assert r1.risk_level == RiskLevel.MEDIUM
    assert len(r1.recommendations) == 1
    assert r1.recommendations[0]["puerto"] == 22

    # Reporte 2: localhost (Todos cerrados)
    r2 = reports[1]
    assert r2.target == "localhost"
    assert r2.ip == "127.0.0.1"
    assert r2.open_ports_count == 0
    assert r2.closed_ports_count == 2
    assert r2.risk_score == 0.0
    assert r2.risk_level == RiskLevel.LOW

    # Verificar que se invocaron los administradores de directorios y los exportadores
    mock_directory_manager.ensure_directories.assert_called_once()
    mock_target_reader.read_targets.assert_called_once()
    mock_excel_exporter.export.assert_called_once()
    mock_json_exporter.export.assert_called_once()
