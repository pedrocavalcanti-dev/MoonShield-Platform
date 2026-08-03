import platform
import socket
from datetime import datetime, timezone


def get_django_version():
    try:
        import django
        return django.__version__
    except Exception:
        return "—"


def format_uptime(seconds: float) -> str:
    days = int(seconds // 86400)
    hrs  = int((seconds % 86400) // 3600)
    mins = int((seconds % 3600) // 60)
    return f"{days}d {hrs}h {mins}m"


def get_os_label():
    return f"{platform.system()} {platform.release()}"


def get_timezone_label():
    try:
        tz = datetime.now().astimezone().tzname()
        if not tz:
            tz = str(datetime.now().astimezone().tzinfo)
        return tz
    except Exception:
        return "—"


def get_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "—"


def get_sysinfo_real(ip_local_principal="—"):
    """
    Coleta dados reais da máquina hospedeira.
    Usa psutil se disponível para RAM e Uptime.
    """
    info = {
        "hostname": get_hostname(),
        "so":       get_os_label(),
        "ip_local": ip_local_principal,
        "timezone": get_timezone_label(),
        "python":   platform.python_version(),
        "django":   get_django_version(),
        "modo":     "prod",
    }

    try:
        import psutil
        mem  = psutil.virtual_memory()
        boot = psutil.boot_time()
        up_sec = datetime.now(timezone.utc).timestamp() - boot
        info["ram"]    = f"{mem.percent:.0f}% usado de {mem.total // (1024**3)} GB"
        info["uptime"] = format_uptime(up_sec)
    except ImportError:
        info["ram"]    = "psutil não instalado"
        info["uptime"] = "—"

    return info