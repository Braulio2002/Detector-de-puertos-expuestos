from pathlib import Path

from app.application.interfaces.target_reader_interface import TargetReaderInterface
from app.domain.exceptions.domain_exceptions import ReaderException


class TxtTargetReader(TargetReaderInterface):
    """Lector de objetivos de auditoría desde archivos de texto plano (TXT)."""

    def __init__(self, file_path: Path):
        """Inicializa el lector con la ruta del archivo targets.txt.

        Args:
            file_path (Path): Ruta al archivo targets.txt.
        """
        self._file_path = file_path

    def read_targets(self) -> list[str]:
        """Carga, sanitiza y filtra los objetivos contenidos en targets.txt.

        Raises:
            ReaderException: Si el archivo no existe o no es accesible.

        Returns:
            List[str]: Lista de objetivos únicos e individualizados.
        """
        if not self._file_path.exists():
            raise ReaderException(
                f"El archivo de entrada configurado no existe: {self._file_path}"
            )

        targets: list[str] = []
        seen = set()

        try:
            with open(self._file_path, encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()

                    # Omitir líneas vacías y comentarios
                    if not clean_line or clean_line.startswith("#"):
                        continue

                    # Eliminar comentarios inline si existiesen (ej: '127.0.0.1 # local')
                    if " #" in clean_line or "\t#" in clean_line:
                        clean_line = clean_line.split("#")[0].strip()

                    # Evitar duplicados manteniendo orden de inserción
                    if clean_line not in seen:
                        seen.add(clean_line)
                        targets.append(clean_line)

            return targets

        except Exception as e:
            raise ReaderException(
                f"Fallo al leer o interpretar el archivo {self._file_path}: {e}"
            )
