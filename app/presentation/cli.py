import sys

from app.application.use_cases.scan_exposed_ports_use_case import ScanExposedPortsUseCase
from app.config.settings import Settings
from app.domain.entities.target_scan_report import TargetScanReport
from app.domain.value_objects.port_status import PortStatus
from app.domain.value_objects.risk_level import RiskLevel

# Secuencias ANSI para colores en terminal
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"


class CLI:
    """Clase encargada de renderizar la interfaz de usuario en consola para el detector de puertos."""

    def __init__(self, use_case: ScanExposedPortsUseCase):
        """Inyecta el caso de uso orquestador.

        Args:
            use_case (ScanExposedPortsUseCase): Caso de uso principal.
        """
        self._use_case = use_case

    def show_banner(self) -> None:
        """Renderiza un banner de presentación premium con advertencias legales y de uso."""
        banner = f"""
{CYAN}{BOLD}========================================================================
       🛡️  DETECTOR DE PUERTOS EXPUESTOS - HERRAMIENTA DEFENSIVA 🛡️
========================================================================{RESET}
{BOLD}Autor: Desarrollador Python Senior / Ciberseguridad Defensiva
Buenas Prácticas OWASP, Hardening y Auditoría de Red{RESET}

{RED}{BOLD}[⚠️ ADVERTENCIA LEGAL]
Esta herramienta está diseñada EXCLUSIVAMENTE para auditorías internas,
análisis de seguridad defensiva, hardening preventivo y hacking ético
sobre activos de su propiedad o bajo autorización expresa por escrito.
El uso de esta herramienta sobre activos no autorizados es ilegal.{RESET}
{CYAN}========================================================================{RESET}
"""
        print(banner)

    def run(self) -> None:
        """Ejecuta el flujo y renderiza la salida consolidada en consola."""
        self.show_banner()

        print(f"{BOLD}[*] Cargando configuración del sistema...{RESET}")
        print(f"    - Puertos configurados: {len(Settings.DEFAULT_PORTS_TO_SCAN)} comunes")
        print(f"    - Concurrencia máxima: {Settings.MAX_CONCURRENCY} hilos")
        print(f"    - Timeout de conexión: {Settings.SOCKET_TIMEOUT}s")
        print(f"    - Captura de banners: {'Habilitada' if Settings.ENABLE_BANNER_GRABBING else 'Deshabilitada'}")
        print("-" * 72)

        try:
            # Ejecutar el caso de uso
            reports = self._use_case.execute(
                ports_to_scan=Settings.DEFAULT_PORTS_TO_SCAN,
                timeout=Settings.SOCKET_TIMEOUT,
                concurrency=Settings.MAX_CONCURRENCY,
                grab_banner=Settings.ENABLE_BANNER_GRABBING,
                output_dir=Settings.OUTPUT_DIR,
                excel_base_name=Settings.REPORT_EXCEL_NAME,
                json_base_name=Settings.REPORT_JSON_NAME
            )

            if not reports:
                print(f"\n{YELLOW}[!] No se procesaron objetivos o no existen registros en targets.txt.{RESET}")
                return

            self._show_results_summary(reports)

        except Exception as e:
            print(f"\n{RED}[!] Error crítico al ejecutar la auditoría: {e}{RESET}", file=sys.stderr)
            sys.exit(1)

    def _show_results_summary(self, reports: list[TargetScanReport]) -> None:
        """Muestra un resumen estilizado y formateado de los reportes en la consola."""
        print(f"\n{CYAN}{BOLD}" + "=" * 72)
        print("                 RESUMEN FINAL DE LA AUDITORÍA DE RED")
        print("=" * 72 + f"{RESET}\n")

        # 1. Tabla de Resumen por Objetivo
        self._print_targets_table(reports)

        # 2. Detalle de Puertos Abiertos Expuestos
        self._print_exposed_services_detail(reports)

        print(f"\n{GREEN}{BOLD}[✔] Auditoría completada con éxito. Los reportes se exportaron en:{RESET}")
        print("    📂 Excel: datos_salida/exposed_ports_report[_X].xlsx")
        print("    📂 JSON:  datos_salida/exposed_ports_report[_X].json")
        print(f"{CYAN}{BOLD}========================================================================{RESET}\n")

    def _print_targets_table(self, reports: list[TargetScanReport]) -> None:
        """Imprime la tabla consolidada de objetivos en consola."""
        print(f"{BOLD}{'TARGET':<22} | {'IP RESUELTA':<15} | {'PUERTOS ABIERTOS':<16} | {'SCORE':<5} | {'RIESGO':<8}{RESET}")
        print("-" * 72)

        for r in reports:
            risk_color = self._get_risk_color(r.risk_level)
            score_str = f"{r.risk_score:.1f}"
            open_count_str = f"{r.open_count_str if hasattr(r, 'open_count_str') else f'{r.open_ports_count}/{r.total_ports_scanned}'}"

            if r.error:
                print(f"{r.target:<22} | {'FALLIDO':<15} | {'0/0':<16} | {'0.0':<5} | {RED}{'ERROR':<8}{RESET}")
                print(f"   {RED}↳ Error: {r.error}{RESET}")
            else:
                print(f"{r.target:<22} | {r.ip:<15} | {open_count_str:<16} | {score_str:<5} | {risk_color}{r.risk_level.value:<8}{RESET}")

        print("-" * 72)

    def _get_risk_color(self, level: RiskLevel) -> str:
        """Determina la secuencia ANSI del color correspondiente al nivel de riesgo del target."""
        if level == RiskLevel.MEDIUM:
            return YELLOW
        if level == RiskLevel.HIGH:
            return RED
        if level == RiskLevel.CRITICAL:
            return MAGENTA
        return GREEN

    def _print_exposed_services_detail(self, reports: list[TargetScanReport]) -> None:
        """Imprime la sección detallada de puertos abiertos y mitigaciones de hardening."""
        open_ports_found = any(r.open_ports_count > 0 for r in reports)

        if not open_ports_found:
            print(f"\n{GREEN}{BOLD}[✅ PERFECTO] No se detectaron puertos TCP expuestos en los objetivos auditados.{RESET}")
            return

        print(f"\n{RED}{BOLD}[⚠️ DETALLE DE SERVICIOS EXPUESTOS Y MEDIDAS DE HARDENING]{RESET}")
        print("=" * 72)

        for r in reports:
            open_ports_list = [p for p in r.open_ports if p.status == PortStatus.OPEN]
            if not open_ports_list:
                continue

            print(f"\n{BOLD}Objetivo: {r.target} ({r.ip}) | Score: {r.risk_score:.1f} ({r.risk_level.value}){RESET}")
            print("-" * 72)

            for port_res in open_ports_list:
                color_prio = self._get_port_prio_color(port_res.risk_level)
                print(f" {BOLD}▶ Puerto:{RESET} {port_res.port}/TCP  |  {BOLD}Servicio:{RESET} {port_res.service_name}  |  {BOLD}Prioridad:{RESET} {color_prio}{port_res.risk_level.value}{RESET}")
                if port_res.banner:
                    print(f"   {CYAN}Banner capturado:{RESET} {port_res.banner}")
                print(f"   {YELLOW}Hardening:{RESET} {port_res.recommendation}")
                print("   " + "." * 69)

    def _get_port_prio_color(self, level: RiskLevel) -> str:
        """Obtiene la secuencia ANSI de color para la prioridad de mitigación de un puerto expuesto."""
        if level == RiskLevel.MEDIUM:
            return YELLOW
        if level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return RED
        return GREEN
