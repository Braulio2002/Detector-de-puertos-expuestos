import socket
from unittest.mock import patch

import pytest

from app.application.services.target_validator_service import TargetValidatorService
from app.domain.exceptions.domain_exceptions import InvalidTargetException


def test_validate_valid_ipv4():
    validator = TargetValidatorService()
    target = validator.validate_and_resolve("192.168.1.1")
    assert target.target_original == "192.168.1.1"
    assert target.ip_resuelta == "192.168.1.1"
    assert target.tipo == "IP"


def test_validate_localhost():
    validator = TargetValidatorService()
    target = validator.validate_and_resolve("localhost")
    assert target.target_original == "localhost"
    assert target.ip_resuelta == "127.0.0.1"
    assert target.tipo == "DOMAIN"


@patch("socket.gethostbyname")
def test_validate_valid_domain(mock_gethostbyname):
    mock_gethostbyname.return_value = "93.184.216.34"

    validator = TargetValidatorService()
    target = validator.validate_and_resolve("example.com")

    assert target.target_original == "example.com"
    assert target.ip_resuelta == "93.184.216.34"
    assert target.tipo == "DOMAIN"
    mock_gethostbyname.assert_called_once_with("example.com")


def test_validate_invalid_ip_format():
    validator = TargetValidatorService()
    with pytest.raises(InvalidTargetException) as exc_info:
        validator.validate_and_resolve("999.999.999.999")
    assert "No tiene formato de dirección IP ni de dominio válido" in str(exc_info.value)


@patch("socket.gethostbyname")
def test_validate_unresolvable_domain(mock_gethostbyname):
    mock_gethostbyname.side_effect = socket.gaierror("DNS lookup failed")

    validator = TargetValidatorService()
    with pytest.raises(InvalidTargetException) as exc_info:
        validator.validate_and_resolve("definitely-not-existent-domain-12345.xyz")
    assert "No se pudo resolver el nombre de dominio" in str(exc_info.value)
