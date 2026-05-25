class DomainException(Exception):
    """Clase base para todas las excepciones del dominio."""

    pass


class InvalidTargetException(DomainException):
    """Se lanza cuando un objetivo (IP o Dominio) no cumple con el formato válido."""

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"El objetivo '{target}' no es válido: {reason}")


class PortScanException(DomainException):
    """Excepción para errores generales al realizar el escaneo de puertos."""

    pass


class ReaderException(DomainException):
    """Excepción para fallos al leer la lista de targets de entrada."""

    pass


class ExporterException(DomainException):
    """Excepción para fallos al exportar el reporte final."""

    pass
