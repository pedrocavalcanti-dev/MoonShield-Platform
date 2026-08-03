import platform
import socket
import ipaddress
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from .models import Dispositivo, ScanRun


# ═══════════════════════════════════════════════════════
#  UTILITÁRIOS DE REDE
# ═══════════════════════════════════════════════════════

def _get_all_ipv4():
    """Retorna todos os IPs reais desta máquina (multi-interface)."""
    ips = []
    for _, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                ip = a.address
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    ips.append(ip)
    return sorted(set(ips))


def _ping(ip: str, timeout_ms: int = 500) -> bool:
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def _arp_table():
    mapping = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and "." in parts[0] and "-" in parts[1]:
                mapping[parts[0]] = parts[1].replace("-", ":").upper()
    except Exception:
        pass
    return mapping


def _check_port(ip: str, port: int, timeout: float = 0.3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return {"port": port, "status": "open"}
    except Exception:
        pass
    return None


def _scan_common_ports(ip: str):
    common_ports = {
        22:   {"service": "SSH",   "proto": "TCP", "risk": "medium"},
        80:   {"service": "HTTP",  "proto": "TCP", "risk": "low"},
        443:  {"service": "HTTPS", "proto": "TCP", "risk": "low"},
        445:  {"service": "SMB",   "proto": "TCP", "risk": "high"},
        3389: {"service": "RDP",   "proto": "TCP", "risk": "high"},
    }
    open_ports = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(_check_port, ip, p) for p in common_ports]
        for f in as_completed(futures):
            res = f.result()
            if res:
                info = common_ports[res["port"]].copy()
                info["port"] = res["port"]
                open_ports.append(info)
    return open_ports


def _guess_device_info(hostname, open_ports):
    os_name, dev_type, icon = "Desconhecido", "Dispositivo", "bi-hdd-network-fill"
    ports = [p["port"] for p in open_ports]
    hn = (hostname or "").lower()

    if 3389 in ports or 445 in ports or "pc" in hn or "len" in hn or "desktop" in hn:
        os_name, dev_type, icon = "Windows", "PC Windows", "bi-pc-display-horizontal"
    elif 22 in ports:
        os_name, dev_type, icon = "Linux / Servidor", "Servidor", "bi-server"
    elif 80 in ports and 443 not in ports:
        os_name, dev_type, icon = "Desconhecido", "IoT / Roteador", "bi-router-fill"

    return os_name, dev_type, icon


def _get_vendor(mac: str):
    if not mac:
        return "Desconhecido"
    vendors = {
        "00:1A:2B": "Cisco",
        "B8:27:EB": "Raspberry",
        "DC:A6:32": "Apple",
        "64:1C:67": "Lenovo",
        "00:FF:30": "OpenVPN",
        "64:32:A8": "Intel",
    }
    return vendors.get(mac[:8], "Genérico")


# ═══════════════════════════════════════════════════════
#  ENDPOINTS
# ═══════════════════════════════════════════════════════

@require_GET
def system_info(request):
    my_ips = _get_all_ipv4()
    return JsonResponse({
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "os_detail": platform.platform(),
        "python": platform.python_version(),
        "ips": my_ips,
        "ip_local": my_ips[0] if my_ips else None,
        "timezone": "America/Sao_Paulo",
    })


@require_GET
def me(request):
    """Retorna identidade desta máquina para o front destacar 'EU'."""
    ips = _get_all_ipv4()
    return JsonResponse({
        "hostname": platform.node(),
        "ips": ips,
        "default_cidr": f"{'.'.join(ips[0].split('.')[:-1])}.0/24" if ips else "192.168.0.0/24",
    })


@require_GET
def network_interfaces(request):
    out = []
    if_addrs = psutil.net_if_addrs()
    if_stats = psutil.net_if_stats()
    for name, addrs in if_addrs.items():
        ipv4 = netmask = mac = None
        for a in addrs:
            if a.family == socket.AF_INET:
                ipv4, netmask = a.address, a.netmask
            elif str(a.family).endswith("AF_LINK") or a.family == getattr(psutil, "AF_LINK", object()):
                mac = a.address.replace("-", ":").upper()
        st = if_stats.get(name)
        out.append({
            "name": name, "ipv4": ipv4, "netmask": netmask,
            "mac": mac, "is_up": bool(st.isup) if st else False,
        })
    return JsonResponse({"interfaces": out})


@csrf_exempt
@require_POST
def network_scan(request):
    """
    Scan da rede com cache SQLite.
    Body JSON (opcional):
      cidr          – ex: "192.168.1.0/24"
      ttl_seconds   – segundos antes de refazer o scan (padrão 120)
      force         – true para ignorar cache
    """
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        body = {}

    ttl    = int(body.get("ttl_seconds", 120))
    force  = bool(body.get("force", False))

    my_ips    = _get_all_ipv4()
    my_ips_set = set(my_ips)
    default_cidr = (
        f"{'.'.join(my_ips[0].split('.')[:-1])}.0/24" if my_ips else "192.168.0.0/24"
    )
    cidr = body.get("cidr") or default_cidr

    # ── Cache: se scan recente existe e não é force, devolve do banco ──
    last = ScanRun.objects.filter(cidr=cidr).order_by("-started_at").first()
    if last and last.finished_at and not force:
        age = (timezone.now() - last.finished_at).total_seconds()
        if age < ttl and last.payload:
            print(f"⚡ [CACHE] Retornando scan de {int(age)}s atrás para {cidr}")
            return JsonResponse(last.payload)

    # ── Novo scan ──
    print(f"\n🚀 [SCAN] Iniciando varredura em {cidr}...")
    scan_run = ScanRun.objects.create(cidr=cidr)

    try:
        net   = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    except ValueError:
        scan_run.delete()
        return JsonResponse({"erro": "CIDR inválido."}, status=400)

    # Ping paralelo
    alive = []
    with ThreadPoolExecutor(max_workers=80) as ex:
        futures = {ex.submit(_ping, ip, 500): ip for ip in hosts}
        for f in as_completed(futures):
            if f.result():
                alive.append(futures[f])

    arp = _arp_table()
    now = timezone.now()
    devices_payload = []

    for ip in sorted(alive, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac      = arp.get(ip)
        is_me    = ip in my_ips_set

        # Busca ou cria registro no banco
        obj, created = Dispositivo.objects.get_or_create(ip=ip)

        # Hostname: respeita custom_name → hostname salvo → plataforma (se for eu) → fallback
        if obj.custom_name:
            hostname = obj.custom_name
        elif obj.hostname:
            hostname = obj.hostname
        elif is_me:
            hostname = platform.node()
        else:
            hostname = f"Host-{ip.split('.')[-1]}"

        open_ports           = _scan_common_ports(ip)
        os_name, dev_type, icon = _guess_device_info(hostname, open_ports)
        vendor               = _get_vendor(mac)

        risk = 10
        if any(p["risk"] == "high"   for p in open_ports): risk += 40
        if any(p["risk"] == "medium" for p in open_ports): risk += 20

        # Atualiza banco
        obj.mac       = mac or obj.mac
        obj.hostname  = hostname
        obj.vendor    = vendor
        obj.os        = os_name
        obj.tipo      = dev_type
        obj.icon      = icon
        obj.status    = "online"
        obj.risk_score = min(100, risk)
        obj.last_seen  = now
        obj.last_scan  = now
        obj.save()

        devices_payload.append({
            "ip":         ip,
            "hostname":   obj.display_name(),
            "mac":        mac or "Desconhecido",
            "vendor":     vendor,
            "os":         os_name,
            "type":       dev_type,
            "icon":       icon,
            "status":     "online",
            "open_ports": open_ports,
            "risk_score": min(100, risk),
            "first_seen": obj.first_seen.isoformat(),
            "last_seen":  now.isoformat(),
            "is_me":      is_me,
        })

    me_info = {
        "hostname": platform.node(),
        "ips":      my_ips,
        "default_cidr": default_cidr,
    }

    result = {
        "cidr":    cidr,
        "found":   len(devices_payload),
        "devices": devices_payload,
        "me":      me_info,
        "scanned_at": now.isoformat(),
    }

    scan_run.found      = len(devices_payload)
    scan_run.finished_at = now
    scan_run.payload    = result
    scan_run.save()

    print(f"🎉 [SCAN] Finalizado. {len(devices_payload)} dispositivos em {cidr}.")
    return JsonResponse(result)


@csrf_exempt
@require_POST
def rename_device(request):
    """Persiste custom_name no banco."""
    try:
        body     = json.loads(request.body.decode("utf-8"))
        ip       = body.get("ip", "").strip()
        new_name = body.get("new_name", "").strip()

        if not ip or not new_name:
            return JsonResponse({"erro": "Dados incompletos"}, status=400)

        obj, _ = Dispositivo.objects.get_or_create(ip=ip)
        obj.custom_name = new_name
        obj.save(update_fields=["custom_name"])

        print(f"🏷️  [{ip}] renomeado → {new_name}")
        return JsonResponse({"sucesso": True, "ip": ip, "new_name": new_name})

    except Exception as e:
        return JsonResponse({"erro": str(e)}, status=500)