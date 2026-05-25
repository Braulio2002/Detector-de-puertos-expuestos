import logging
import sys


def setup_logger(name: str = "ports_detector") -> logging.Logger:
    """Configura e inicializa el logger centralizado del sistema."""
    logger = logging.getLogger(name)

    # Si ya tiene handlers, no duplicarlos
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    # Formato pulido y amigable para el operador
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Handler para salida en consola estándar
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


# Instancia por defecto
logger = setup_logger()
