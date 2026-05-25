from app.application.services.score_calculator_service import ScoreCalculatorService
from app.config.settings import Settings
from app.domain.entities.port_scan_result import PortScanResult
from app.domain.value_objects.port_status import PortStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.service_category import ServiceCategory


def test_calculator_no_open_ports():
    calculator = ScoreCalculatorService(
        weights=Settings.SCORING_WEIGHTS,
        thresholds=Settings.RISK_THRESHOLDS
    )
    score, level = calculator.calculate([])
    assert score == 0.0
    assert level == RiskLevel.LOW


def test_calculator_single_admin_port():
    calculator = ScoreCalculatorService(
        weights=Settings.SCORING_WEIGHTS,
        thresholds=Settings.RISK_THRESHOLDS
    )

    # Puerto 22 (SSH) - ADMIN
    res = PortScanResult(
        target="127.0.0.1",
        ip="127.0.0.1",
        port=22,
        status=PortStatus.OPEN,
        service_name="SSH",
        service_category=ServiceCategory.ADMIN
    )

    score, level = calculator.calculate([res])
    # Peso ADMIN = 25.0
    assert score == 25.0
    assert level == RiskLevel.MEDIUM  # 21 a 50 es MEDIO


def test_calculator_cap_at_100():
    calculator = ScoreCalculatorService(
        weights=Settings.SCORING_WEIGHTS,
        thresholds=Settings.RISK_THRESHOLDS
    )

    # Múltiples puertos de alto riesgo abiertos que exceden 100
    res1 = PortScanResult(
        target="127.0.0.1", ip="127.0.0.1", port=445,
        status=PortStatus.OPEN, service_name="SMB", service_category=ServiceCategory.FILE_SHARING
    )
    res2 = PortScanResult(
        target="127.0.0.1", ip="127.0.0.1", port=3389,
        status=PortStatus.OPEN, service_name="RDP", service_category=ServiceCategory.REMOTE_ACCESS
    )
    res3 = PortScanResult(
        target="127.0.0.1", ip="127.0.0.1", port=3306,
        status=PortStatus.OPEN, service_name="MySQL", service_category=ServiceCategory.DATABASE
    )
    res4 = PortScanResult(
        target="127.0.0.1", ip="127.0.0.1", port=23,
        status=PortStatus.OPEN, service_name="Telnet", service_category=ServiceCategory.ADMIN
    )
    res5 = PortScanResult(
        target="127.0.0.1", ip="127.0.0.1", port=5432,
        status=PortStatus.OPEN, service_name="PostgreSQL", service_category=ServiceCategory.DATABASE
    )

    score, level = calculator.calculate([res1, res2, res3, res4, res5])
    assert score == 100.0
    assert level == RiskLevel.CRITICAL
