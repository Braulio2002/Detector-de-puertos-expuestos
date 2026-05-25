from app.application.services.service_identifier_service import ServiceIdentifierService
from app.domain.value_objects.service_category import ServiceCategory


def test_identify_known_ports():
    identifier = ServiceIdentifierService()

    # Test SSH
    name, category = identifier.identify(22)
    assert name == "SSH"
    assert category == ServiceCategory.ADMIN

    # Test HTTP
    name, category = identifier.identify(80)
    assert name == "HTTP"
    assert category == ServiceCategory.WEB

    # Test MySQL
    name, category = identifier.identify(3306)
    assert name == "MySQL"
    assert category == ServiceCategory.DATABASE


def test_identify_unknown_port():
    identifier = ServiceIdentifierService()

    name, category = identifier.identify(65432)
    assert "Desconocido" in name
    assert category == ServiceCategory.UNKNOWN
