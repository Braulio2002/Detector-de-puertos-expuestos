import logging
from pathlib import Path


class DirectoryManager:
    """Administra el ciclo de vida y la creación inicial de directorios y archivos de entrada."""

    def __init__(self, input_dir: Path, output_dir: Path, targets_file: Path):
        """Inicializa las rutas requeridas.

        Args:
            input_dir (Path): Directorio de entrada.
            output_dir (Path): Directorio de salida.
            targets_file (Path): Archivo de targets.
        """
        self._input_dir = input_dir
        self._output_dir = output_dir
        self._targets_file = targets_file
        self._logger = logging.getLogger("ports_detector")

    def ensure_directories(self) -> None:
        """Asegura la existencia de las carpetas de entrada y salida, e inicializa targets.txt si es necesario."""
        # 1. Crear carpeta datos_entrada si no existe
        if not self._input_dir.exists():
            self._logger.info(
                f"Creando carpeta datos_entrada en: {self._input_dir}")
            self._input_dir.mkdir(parents=True, exist_ok=True)
            # Crear un archivo .gitkeep para control de versiones
            (self._input_dir / ".gitkeep").touch()

        # 2. Crear carpeta datos_salida si no existe
        if not self._output_dir.exists():
            self._logger.info(
                f"Creando carpeta datos_salida en: {self._output_dir}")
            self._output_dir.mkdir(parents=True, exist_ok=True)
            # Crear un archivo .gitkeep para control de versiones
            (self._output_dir / ".gitkeep").touch()

        # 3. Crear targets.txt con ejemplos comentados si no existe
        if not self._targets_file.exists():
            self._logger.info(
                f"Creando targets.txt con plantilla predeterminada en: {self._targets_file}")
            example_content = (
                "# =========================================================================\n"
                "# Detector de Puertos Expuestos - Archivo de Objetivos de Auditoría\n"
                "# =========================================================================\n"
                "# NOTA LEGAL: Utilice esta herramienta únicamente sobre redes e infraestructura\n"
                "# de su propiedad o para las cuales cuente con autorización formal por escrito.\n"
                "#\n"
                "# Ingrese un target por línea. Se admiten direcciones IP o nombres de dominio.\n"
                "# Las líneas vacías o que comiencen con '#' serán omitidas automáticamente.\n"
                "# =========================================================================\n"
                "\n"
                "# Dirección local (Loopback)\n"
                "127.0.0.1\n"
                "localhost\n"
                "\n"
                "# Ejemplo de dominio y servidor autorizado\n"
                "# midominio.com\n"
                "# 192.168.1.10\n"
            )
            with open(self._targets_file, "w", encoding="utf-8") as f:
                f.write(example_content)
