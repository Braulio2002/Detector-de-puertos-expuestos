from typing import Any

from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.service_category import ServiceCategory

# Lista predeterminada de puertos comunes a escanear
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 6379,
    8000, 8080, 8443, 9200, 9300, 11211, 27017
]

# Mapeo de puertos comunes a sus nombres de servicios y categorías
SERVICE_MAPPINGS: dict[int, dict[str, Any]] = {
    21: {"name": "FTP", "category": ServiceCategory.FILE_SHARING},
    22: {"name": "SSH", "category": ServiceCategory.ADMIN},
    23: {"name": "Telnet", "category": ServiceCategory.ADMIN},
    25: {"name": "SMTP", "category": ServiceCategory.MAIL},
    53: {"name": "DNS", "category": ServiceCategory.ADMIN},
    80: {"name": "HTTP", "category": ServiceCategory.WEB},
    110: {"name": "POP3", "category": ServiceCategory.MAIL},
    143: {"name": "IMAP", "category": ServiceCategory.MAIL},
    443: {"name": "HTTPS", "category": ServiceCategory.WEB},
    445: {"name": "SMB", "category": ServiceCategory.FILE_SHARING},
    465: {"name": "SMTPS", "category": ServiceCategory.MAIL},
    587: {"name": "SMTP Submission", "category": ServiceCategory.MAIL},
    993: {"name": "IMAPS", "category": ServiceCategory.MAIL},
    995: {"name": "POP3S", "category": ServiceCategory.MAIL},
    1433: {"name": "SQL Server", "category": ServiceCategory.DATABASE},
    1521: {"name": "Oracle SQL", "category": ServiceCategory.DATABASE},
    2049: {"name": "NFS", "category": ServiceCategory.FILE_SHARING},
    2375: {"name": "Docker API", "category": ServiceCategory.ADMIN},
    2376: {"name": "Docker TLS", "category": ServiceCategory.ADMIN},
    3306: {"name": "MySQL", "category": ServiceCategory.DATABASE},
    3389: {"name": "RDP", "category": ServiceCategory.REMOTE_ACCESS},
    5432: {"name": "PostgreSQL", "category": ServiceCategory.DATABASE},
    5900: {"name": "VNC", "category": ServiceCategory.REMOTE_ACCESS},
    6379: {"name": "Redis", "category": ServiceCategory.CACHE},
    8000: {"name": "HTTP Alternativo", "category": ServiceCategory.WEB},
    8080: {"name": "HTTP Alternativo", "category": ServiceCategory.WEB},
    8443: {"name": "HTTPS Alternativo", "category": ServiceCategory.WEB},
    9200: {"name": "Elasticsearch API", "category": ServiceCategory.CACHE},
    9300: {"name": "Elasticsearch Cluster", "category": ServiceCategory.CACHE},
    11211: {"name": "Memcached", "category": ServiceCategory.CACHE},
    27017: {"name": "MongoDB", "category": ServiceCategory.DATABASE}
}

# Base de riesgos asociados a puertos abiertos
RISK_MAPPINGS: dict[int, dict[str, Any]] = {
    21: {
        "level": RiskLevel.HIGH,
        "description": "Protocolo inseguro de transmisión de archivos en texto plano. Riesgo de sniffing de credenciales.",
        "recommendation": "Usar SFTP o FTPS, deshabilitar FTP anónimo y restringir IPs de administración."
    },
    22: {
        "level": RiskLevel.MEDIUM,
        "description": "Puerto de administración SSH expuesto. Riesgo de ataques de fuerza bruta dirigidos.",
        "recommendation": "Restringir por IP, usar autenticación por llaves públicas, deshabilitar login de root y usar fail2ban."
    },
    23: {
        "level": RiskLevel.CRITICAL,
        "description": "Protocolo Telnet obsoleto e inseguro. Credenciales y comandos viajan en texto plano.",
        "recommendation": "Deshabilitar Telnet inmediatamente y migrar a SSH."
    },
    25: {
        "level": RiskLevel.MEDIUM,
        "description": "Servicio de correo SMTP expuesto. Posible vector para spam o relay abierto.",
        "recommendation": "Configurar autenticación SASL fuerte, deshabilitar open relay y habilitar cifrado TLS."
    },
    53: {
        "level": RiskLevel.LOW,
        "description": "Servidor de nombres DNS expuesto. Riesgo de envenenamiento de caché o amplificación DDoS.",
        "recommendation": "Deshabilitar transferencias de zona no autorizadas y limitar consultas recursivas al segmento interno."
    },
    80: {
        "level": RiskLevel.MEDIUM,
        "description": "Servidor web HTTP expuesto sin cifrado. Los datos viajan legibles para sniffers en la red.",
        "recommendation": "Redirigir todo el tráfico a HTTPS y configurar cabeceras HSTS y de seguridad."
    },
    110: {
        "level": RiskLevel.HIGH,
        "description": "Acceso al buzón de correo POP3 expuesto sin cifrado. Credenciales de email vulnerables.",
        "recommendation": "Exigir el uso de POP3S (cifrado) en el puerto 995 y deshabilitar POP3 en texto plano."
    },
    143: {
        "level": RiskLevel.HIGH,
        "description": "Acceso al buzón de correo IMAP expuesto sin cifrado. Credenciales de email vulnerables.",
        "recommendation": "Exigir el uso de IMAPS (cifrado) en el puerto 993 y deshabilitar IMAP en texto plano."
    },
    443: {
        "level": RiskLevel.LOW,
        "description": "Servidor web HTTPS seguro expuesto. Configuración TLS estándar.",
        "recommendation": "Validar periódicamente la vigencia del certificado SSL/TLS, forzar TLS 1.2 o 1.3 y deshabilitar cifrados débiles."
    },
    445: {
        "level": RiskLevel.CRITICAL,
        "description": "Compartición de archivos SMB expuesta públicamente. Altamente vulnerable a exploits (ej. EternalBlue).",
        "recommendation": "Bloquear acceso público a este puerto mediante firewall perimetral y habilitar VPN para accesos remotos."
    },
    465: {
        "level": RiskLevel.LOW,
        "description": "Servicio de correo SMTP seguro (SMTPS). Riesgos generales de cifrado.",
        "recommendation": "Garantizar el uso de certificados válidos e implementar autenticación robusta."
    },
    587: {
        "level": RiskLevel.LOW,
        "description": "Servicio de envío de correo SMTP seguro (STARTTLS).",
        "recommendation": "Forzar STARTTLS obligatoriamente y aplicar políticas estrictas de contraseñas."
    },
    993: {
        "level": RiskLevel.LOW,
        "description": "Acceso seguro a correo electrónico IMAPS expuesto.",
        "recommendation": "Configurar TLS moderno, deshabilitando SSLv3, TLS 1.0 y 1.1."
    },
    995: {
        "level": RiskLevel.LOW,
        "description": "Acceso seguro a correo electrónico POP3S expuesto.",
        "recommendation": "Configurar TLS moderno, deshabilitando SSLv3, TLS 1.0 y 1.1."
    },
    1433: {
        "level": RiskLevel.HIGH,
        "description": "Base de datos SQL Server expuesta. Objetivo principal de ataques automatizados de fuerza bruta.",
        "recommendation": "Restringir accesos mediante firewall a IPs autorizadas, usar cuentas de dominio y activar auditorías de logeo."
    },
    1521: {
        "level": RiskLevel.HIGH,
        "description": "Base de datos Oracle SQL expuesta. Riesgo de exfiltración o inyección.",
        "recommendation": "Limitar el acceso perimetral en firewall, aplicar parches de seguridad periódicos y usar VPN."
    },
    2049: {
        "level": RiskLevel.CRITICAL,
        "description": "Servicio de compartición NFS expuesto públicamente. Posibilidad de montar carpetas de forma remota sin auth.",
        "recommendation": "Cerrar acceso externo, restringir exports mediante IPs específicas y habilitar NFSv4 con Kerberos."
    },
    2375: {
        "level": RiskLevel.CRITICAL,
        "description": "API de Docker expuesta de forma no segura. Permite ejecución remota de contenedores con permisos de root.",
        "recommendation": "Deshabilitar puerto público de inmediato. Utilizar socket Unix local o socket seguro con mTLS (puerto 2376)."
    },
    2376: {
        "level": RiskLevel.HIGH,
        "description": "API de Docker protegida por TLS expuesta. Exposición de control de orquestación de contenedores.",
        "recommendation": "Restringir el puerto por firewall a IPs de administración dedicadas y validar mTLS estricto."
    },
    3306: {
        "level": RiskLevel.HIGH,
        "description": "Base de datos MySQL expuesta públicamente. Riesgo latente de fuerza bruta o exfiltración.",
        "recommendation": "Configurar directiva bind-address en 127.0.0.1, limitar privilegios de usuarios y forzar contraseñas robustas."
    },
    3389: {
        "level": RiskLevel.CRITICAL,
        "description": "Escritorio remoto de Windows (RDP) expuesto. Riesgo extremo de ransomware y exploits de ejecución remota (RCE).",
        "recommendation": "Deshabilitar el puerto directo a internet, canalizar via VPN perimetral, forzar NLA y aplicar MFA."
    },
    5432: {
        "level": RiskLevel.HIGH,
        "description": "Base de datos PostgreSQL expuesta públicamente. Riesgo de ataques dirigidos.",
        "recommendation": "Restringir el acceso externo en pg_hba.conf, forzar bindeo a localhost o red privada y exigir SSL."
    },
    5900: {
        "level": RiskLevel.CRITICAL,
        "description": "Acceso de escritorio remoto VNC expuesto. Protocolo propenso a contraseñas débiles y sniffing.",
        "recommendation": "Bloquear puerto 5900 externamente, tunelizar conexiones seguras por SSH y activar autenticación fuerte."
    },
    6379: {
        "level": RiskLevel.HIGH,
        "description": "Base de datos en memoria Redis expuesta. Por defecto carece de autenticación e invita a inyección remota.",
        "recommendation": "Habilitar la directiva requirepass, bindear a red privada local (127.0.0.1) y renombrar comandos críticos."
    },
    8000: {
        "level": RiskLevel.MEDIUM,
        "description": "Servicio web en puerto HTTP alternativo. Tráfico no cifrado.",
        "recommendation": "Habilitar cifrado SSL/TLS, mover a un puerto seguro con HTTPS y aplicar autenticación básica si aplica."
    },
    8080: {
        "level": RiskLevel.MEDIUM,
        "description": "Servicio web en puerto HTTP alternativo. Tráfico no cifrado.",
        "recommendation": "Habilitar cifrado SSL/TLS, mover a un puerto seguro con HTTPS y aplicar autenticación básica si aplica."
    },
    8443: {
        "level": RiskLevel.LOW,
        "description": "Servicio web en puerto HTTPS alternativo.",
        "recommendation": "Asegurar uso de TLS 1.2/1.3 y vigencia correcta de los certificados correspondientes."
    },
    9200: {
        "level": RiskLevel.CRITICAL,
        "description": "API de Elasticsearch expuesta. Fuga de índices completos y posible borrado malintencionado.",
        "recommendation": "Habilitar la seguridad de Elastic (x-pack), forzar autenticación básica, cifrado TLS y cerrar puerto al exterior."
    },
    9300: {
        "level": RiskLevel.HIGH,
        "description": "Puerto de comunicación interna del cluster Elasticsearch expuesto.",
        "recommendation": "Bloquear el puerto externamente, habilitar solo para la subred privada de intercomunicación de nodos."
    },
    11211: {
        "level": RiskLevel.HIGH,
        "description": "Servicio de caché Memcached expuesto. Posible vector para amplificación de ataques DDoS (UDP) y exfiltración de caché.",
        "recommendation": "Bloquear puerto externo en firewall y bindeat servicio a localhost o interfaz local."
    },
    27017: {
        "level": RiskLevel.CRITICAL,
        "description": "Base de datos NoSQL MongoDB expuesta públicamente sin seguridad activa. Altamente vulnerable a secuestro de datos.",
        "recommendation": "Habilitar la autenticación de base de datos, configurar bindIP en red local privada y restringir por firewall."
    }
}
