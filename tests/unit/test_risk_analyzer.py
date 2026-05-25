from app.application.services.risk_analyzer_service import RiskAnalyzerService
from app.domain.value_objects.risk_level import RiskLevel


def test_analyze_critical_ports():
    analyzer = RiskAnalyzerService()

    # RDP
    level, desc = analyzer.analyze(3389)
    assert level == RiskLevel.CRITICAL
    assert "Escritorio remoto" in desc

    # SMB
    level, desc = analyzer.analyze(445)
    assert level == RiskLevel.CRITICAL
    assert "SMB" in desc or "Windows" in desc


def test_analyze_high_ports():
    analyzer = RiskAnalyzerService()

    # FTP
    level, desc = analyzer.analyze(21)
    assert level == RiskLevel.HIGH
    assert "FTP" in desc or "texto plano" in desc

    # MySQL
    level, desc = analyzer.analyze(3306)
    assert level == RiskLevel.HIGH
    assert "MySQL" in desc or "fuerza bruta" in desc


def test_analyze_unknown_port_risk():
    analyzer = RiskAnalyzerService()

    level, desc = analyzer.analyze(54321)
    assert level == RiskLevel.LOW
    assert "no estándar" in desc
