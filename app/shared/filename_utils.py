from pathlib import Path


def get_unique_filename(directory: Path, base_name: str, extension: str) -> Path:
    """Genera un nombre de archivo único para evitar sobreescribir reportes anteriores.

    Si 'exposed_ports_report.xlsx' ya existe en 'datos_salida',
    buscará 'exposed_ports_report_1.xlsx', 'exposed_ports_report_2.xlsx', etc.
    """
    ext = extension.lstrip(".")
    candidate = directory / f"{base_name}.{ext}"

    if not candidate.exists():
        return candidate

    counter = 1
    while True:
        candidate = directory / f"{base_name}_{counter}.{ext}"
        if not candidate.exists():
            return candidate
        counter += 1
