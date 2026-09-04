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

def _get_ipv4_interfaces():
    """
    Retorna interfaces IPv4 válidas da máquina.
    Cada item contém interface, IPv4, máscara e CIDR conectado.
    """
    interfaces = []

    for name, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        if stats and not stats.isup:
            continue

        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue

            ip = addr.address
            if (
                not ip
                or ip.startswith("127.")
                or ip.startswith("169.254.")
            ):
                continue

            netmask = addr.netmask or "255.255.255.0"

            try:
                network = ipaddress.ip_network(
                    f"{ip}/{netmask}",
                    strict=False,
                )
            except ValueError:
                continue

            interfaces.append({
                "name": name,
                "ip": ip,
                "netmask": netmask,
                "network": network,
                "cidr": str(network),
                "private": ipaddress.ip_address(ip).is_private,
            })

    return interfaces


def _get_all_ipv4():
    """Retorna todos os IPv4 reais desta máquina."""
    return sorted({
        item["ip"]
        for item in _get_ipv4_interfaces()
    })


def _get_scan_targets():
    """
    Retorna todas as redes IPv4 diretamente conectadas às interfaces ativas.

    - ignora loopback/link-local (já filtrados em _get_ipv4_interfaces);
    - remove redes CIDR duplicadas;
    - mantém quais interfaces/IPs pertencem a cada rede.
    """
    grouped = {}

    for item in _get_ipv4_interfaces():
        cidr = item["cidr"]

        target = grouped.setdefault(
            cidr,
            {
                "cidr": cidr,
                "network": item["network"],
                "interfaces": [],
                "ips": [],
                "netmasks": [],
                "private": item["private"],
            },
        )

        if item["name"] not in target["interfaces"]:
            target["interfaces"].append(item["name"])

        if item["ip"] not in target["ips"]:
            target["ips"].append(item["ip"])

        if item["netmask"] not in target["netmasks"]:
            target["netmasks"].append(item["netmask"])

    return sorted(
        grouped.values(),
        key=lambda target: (
            int(target["network"].network_address),
            target["network"].prefixlen,
        ),
    )


def _default_route_interface():
    """
    Linux: descobre a interface usada pela rota default.
    Windows/outros: retorna None.
    """
    if platform.system().lower() != "linux":
        return None

    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        for line in (result.stdout or "").splitlines():
            parts = line.split()
            if "dev" in parts:
                index = parts.index("dev")
                if index + 1 < len(parts):
                    return parts[index + 1]
    except Exception:
        pass

    return None


def _choose_scan_network():
    """
    Escolhe a rede LAN mais provável sem hardcode de interface.

    Prioridade:
    1. rede privada que NÃO seja a interface de rota default;
    2. interface cujo IP seja o primeiro host da sub-rede (.1 em /24);
    3. menor rede conectada disponível;
    4. fallback para a primeira interface válida.

    Isso evita selecionar automaticamente a WAN/NAT quando o MoonShield
    possui WAN + MGMT + LAN.
    """
    interfaces = _get_ipv4_interfaces()

    if not interfaces:
        return {
            "name": None,
            "ip": None,
            "netmask": "255.255.255.0",
            "network": ipaddress.ip_network("192.168.0.0/24"),
            "cidr": "192.168.0.0/24",
            "private": True,
        }

    default_if = _default_route_interface()

    private = [
        item
        for item in interfaces
        if item["private"]
    ]

    candidates = [
        item
        for item in private
        if item["name"] != default_if
    ] or private or interfaces

    def score(item):
        network = item["network"]

        try:
            first_host = next(network.hosts())
            is_gateway_like = (
                ipaddress.ip_address(item["ip"]) == first_host
            )
        except StopIteration:
            is_gateway_like = False

        # Maior score = melhor candidato.
        return (
            1 if is_gateway_like else 0,
            1 if item["name"] != default_if else 0,
            network.prefixlen,
        )

    return sorted(
        candidates,
        key=score,
        reverse=True,
    )[0]


def _ping(ip: str, timeout_ms: int = 700) -> bool:
    """
    Ping compatível com Linux e Windows.

    O código antigo usava os parâmetros do ping do Windows em Linux:
    `ping -n 1 -w 500`.
    No Linux `-w 500` representa um deadline enorme, deixando o endpoint
    /scan/ pendente por muito tempo.
    """
    system = platform.system().lower()

    if system == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(timeout_ms),
            ip,
        ]
        process_timeout = max(2, (timeout_ms / 1000) + 1)
    else:
        timeout_seconds = max(
            1,
            int((timeout_ms + 999) / 1000),
        )
        command = [
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            str(timeout_seconds),
            ip,
        ]
        process_timeout = timeout_seconds + 1

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=process_timeout,
        )
        return result.returncode == 0
    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        OSError,
    ):
        return False


def _arp_table():
    """
    Retorna IP -> MAC.

    Linux usa `ip neigh`; Windows mantém `arp -a`.
    """
    mapping = {}
    system = platform.system().lower()

    try:
        if system == "linux":
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )

            for line in (result.stdout or "").splitlines():
                parts = line.split()

                if not parts:
                    continue

                ip = parts[0]

                if "lladdr" not in parts:
                    continue

                index = parts.index("lladdr")

                if index + 1 >= len(parts):
                    continue

                mac = parts[index + 1]

                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue

                mapping[ip] = mac.replace(
                    "-",
                    ":",
                ).upper()

        else:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )

            for line in (result.stdout or "").splitlines():
                parts = line.split()

                if len(parts) < 2:
                    continue

                ip = parts[0]
                mac = parts[1]

                if "." not in ip:
                    continue

                if "-" not in mac and ":" not in mac:
                    continue

                mapping[ip] = mac.replace(
                    "-",
                    ":",
                ).upper()

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
    scan_if = _choose_scan_network()
    targets = _get_scan_targets()

    return JsonResponse({
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "os_detail": platform.platform(),
        "python": platform.python_version(),
        "ips": my_ips,
        "ip_local": scan_if.get("ip") or (
            my_ips[0] if my_ips else None
        ),
        "scan_interface": scan_if.get("name"),
        "scan_cidr": scan_if.get("cidr"),
        "scan_networks": [
            {
                "cidr": target["cidr"],
                "interfaces": target["interfaces"],
                "ips": target["ips"],
            }
            for target in targets
        ],
        "timezone": "America/Sao_Paulo",
    })


@require_GET
def me(request):
    """Retorna identidade desta máquina para o front destacar 'EU'."""
    ips = _get_all_ipv4()
    scan_if = _choose_scan_network()
    targets = _get_scan_targets()

    return JsonResponse({
        "hostname": platform.node(),
        "ips": ips,
        "default_cidr": scan_if["cidr"],
        "scan_interface": scan_if.get("name"),
        "scan_ip": scan_if.get("ip"),
        "scan_networks": [
            {
                "cidr": target["cidr"],
                "interfaces": target["interfaces"],
                "ips": target["ips"],
            }
            for target in targets
        ],
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
        cidr = None
        if ipv4 and netmask:
            try:
                cidr = str(
                    ipaddress.ip_network(
                        f"{ipv4}/{netmask}",
                        strict=False,
                    )
                )
            except ValueError:
                pass

        out.append({
            "name": name,
            "ipv4": ipv4,
            "netmask": netmask,
            "cidr": cidr,
            "mac": mac,
            "is_up": bool(st.isup) if st else False,
        })
    return JsonResponse({"interfaces": out})


@csrf_exempt
@require_POST
def network_scan(request):
    """
    Varre TODAS as redes IPv4 diretamente conectadas às interfaces ativas.

    Comportamento padrão:
      - WAN, LAN, MGMT, DMZ e demais interfaces IPv4 ativas;
      - redes duplicadas são varridas apenas uma vez;
      - cada rede mantém cache próprio em ScanRun;
      - resultados são agregados e deduplicados por IP.

    Body JSON (opcional):
      cidr          – se informado, varre apenas esse CIDR;
      ttl_seconds   – cache por rede, padrão 120s;
      force         – ignora cache;
    """
    try:
        body = json.loads(
            request.body.decode("utf-8") or "{}"
        )
    except Exception:
        body = {}

    try:
        ttl = max(
            0,
            int(body.get("ttl_seconds", 120)),
        )
    except (TypeError, ValueError):
        ttl = 120

    force = bool(body.get("force", False))
    requested_cidr = (
        str(body.get("cidr") or "").strip()
        or None
    )

    interfaces = _get_ipv4_interfaces()
    my_ips = sorted({
        item["ip"]
        for item in interfaces
    })
    my_ips_set = set(my_ips)

    if requested_cidr:
        try:
            requested_network = ipaddress.ip_network(
                requested_cidr,
                strict=False,
            )

            if requested_network.version != 4:
                raise ValueError

        except ValueError:
            return JsonResponse(
                {"erro": "CIDR IPv4 inválido."},
                status=400,
            )

        matching_interfaces = [
            item
            for item in interfaces
            if ipaddress.ip_address(item["ip"])
            in requested_network
        ]

        targets = [{
            "cidr": str(requested_network),
            "network": requested_network,
            "interfaces": [
                item["name"]
                for item in matching_interfaces
            ],
            "ips": [
                item["ip"]
                for item in matching_interfaces
            ],
            "netmasks": [
                item["netmask"]
                for item in matching_interfaces
            ],
            "private": requested_network.is_private,
        }]

    else:
        targets = _get_scan_targets()

    if not targets:
        return JsonResponse(
            {
                "erro": (
                    "Nenhuma interface IPv4 ativa foi encontrada "
                    "para realizar a varredura."
                )
            },
            status=400,
        )

    arp = _arp_table()
    now = timezone.now()

    all_devices = {}
    network_results = []
    skipped_networks = []

    def scan_one_target(target):
        cidr = target["cidr"]
        net = target["network"]

        # Limite evita /16 ou /8 acidental na WAN.
        if net.num_addresses > 1024:
            return {
                "cidr": cidr,
                "interfaces": target["interfaces"],
                "ips": target["ips"],
                "found": 0,
                "devices": [],
                "cached": False,
                "skipped": True,
                "reason": (
                    "Rede maior que 1024 endereços; "
                    "varredura automática ignorada."
                ),
            }

        # Cache individual por CIDR.
        last = (
            ScanRun.objects
            .filter(cidr=cidr)
            .order_by("-started_at")
            .first()
        )

        if (
            last
            and last.finished_at
            and not force
            and last.payload
        ):
            age = (
                timezone.now() - last.finished_at
            ).total_seconds()

            if age < ttl:
                cached_payload = dict(last.payload)
                cached_payload["cached"] = True
                cached_payload["interfaces"] = (
                    target["interfaces"]
                )
                cached_payload["interface_ips"] = (
                    target["ips"]
                )
                cached_payload["skipped"] = False

                print(
                    f"⚡ [CACHE] {cidr} "
                    f"({', '.join(target['interfaces']) or 'sem interface'}) "
                    f"— {int(age)}s"
                )

                return cached_payload

        print(
            f"\n🚀 [SCAN] Iniciando {cidr} "
            f"via {', '.join(target['interfaces']) or 'CIDR manual'}..."
        )

        scan_run = ScanRun.objects.create(
            cidr=cidr
        )

        hosts = [
            str(ip)
            for ip in net.hosts()
        ]

        alive = set()

        # ICMP paralelo.
        with ThreadPoolExecutor(
            max_workers=min(
                96,
                max(1, len(hosts)),
            )
        ) as executor:
            futures = {
                executor.submit(
                    _ping,
                    ip,
                    700,
                ): ip
                for ip in hosts
            }

            for future in as_completed(futures):
                try:
                    if future.result():
                        alive.add(
                            futures[future]
                        )
                except Exception:
                    pass

        # Complementa com vizinhos já conhecidos pelo kernel.
        for ip in arp:
            try:
                if ipaddress.ip_address(ip) in net:
                    alive.add(ip)
            except ValueError:
                pass

        devices_payload = []

        for ip in sorted(
            alive,
            key=lambda value: tuple(
                int(part)
                for part in value.split(".")
            ),
        ):
            mac = arp.get(ip)
            is_me = ip in my_ips_set

            obj, _ = Dispositivo.objects.get_or_create(
                ip=ip
            )

            if obj.custom_name:
                hostname = obj.custom_name
            elif obj.hostname:
                hostname = obj.hostname
            elif is_me:
                hostname = platform.node()
            else:
                hostname = (
                    f"Host-{ip.split('.')[-1]}"
                )

            open_ports = _scan_common_ports(ip)
            os_name, dev_type, icon = (
                _guess_device_info(
                    hostname,
                    open_ports,
                )
            )
            vendor = _get_vendor(mac)

            risk = 10

            if any(
                port["risk"] == "high"
                for port in open_ports
            ):
                risk += 40

            if any(
                port["risk"] == "medium"
                for port in open_ports
            ):
                risk += 20

            risk = min(
                100,
                risk,
            )

            obj.mac = mac or obj.mac
            obj.hostname = hostname
            obj.vendor = vendor
            obj.os = os_name
            obj.tipo = dev_type
            obj.icon = icon
            obj.status = "online"
            obj.risk_score = risk
            obj.last_seen = now
            obj.last_scan = now
            obj.save()

            devices_payload.append({
                "ip": ip,
                "hostname": obj.display_name(),
                "mac": mac or "Desconhecido",
                "vendor": vendor,
                "os": os_name,
                "type": dev_type,
                "icon": icon,
                "status": "online",
                "open_ports": open_ports,
                "risk_score": risk,
                "first_seen": obj.first_seen.isoformat(),
                "last_seen": now.isoformat(),
                "is_me": is_me,
                "network": cidr,
                "interfaces": target["interfaces"],
            })

        payload = {
            "cidr": cidr,
            "interfaces": target["interfaces"],
            "interface_ips": target["ips"],
            "found": len(devices_payload),
            "devices": devices_payload,
            "scanned_at": now.isoformat(),
            "cached": False,
            "skipped": False,
        }

        scan_run.found = len(
            devices_payload
        )
        scan_run.finished_at = now
        scan_run.payload = payload
        scan_run.save()

        print(
            f"🎉 [SCAN] {cidr}: "
            f"{len(devices_payload)} dispositivo(s)."
        )

        return payload

    # Varre cada rede diretamente conectada.
    # Redes são processadas uma por vez para evitar criar centenas
    # de subprocessos simultâneos quando existem várias NICs.
    for target in targets:
        result = scan_one_target(target)

        if result.get("skipped"):
            skipped_networks.append({
                "cidr": result["cidr"],
                "interfaces": result.get(
                    "interfaces",
                    [],
                ),
                "reason": result.get(
                    "reason",
                    "",
                ),
            })

        network_results.append({
            "cidr": result["cidr"],
            "interfaces": result.get(
                "interfaces",
                [],
            ),
            "interface_ips": result.get(
                "interface_ips",
                target.get("ips", []),
            ),
            "found": result.get(
                "found",
                0,
            ),
            "cached": bool(
                result.get("cached")
            ),
            "skipped": bool(
                result.get("skipped")
            ),
            "reason": result.get(
                "reason",
            ),
        })

        for device in result.get(
            "devices",
            [],
        ):
            ip = device.get("ip")

            if not ip:
                continue

            existing = all_devices.get(ip)

            if existing is None:
                all_devices[ip] = device
                continue

            # Caso duas interfaces cubram redes sobrepostas,
            # preserva todas as origens sem duplicar o dispositivo.
            existing_interfaces = set(
                existing.get(
                    "interfaces",
                    [],
                )
            )
            existing_interfaces.update(
                device.get(
                    "interfaces",
                    [],
                )
            )
            existing["interfaces"] = sorted(
                existing_interfaces
            )

    devices_payload = sorted(
        all_devices.values(),
        key=lambda device: tuple(
            int(part)
            for part in device["ip"].split(".")
        ),
    )

    preferred = _choose_scan_network()

    me_info = {
        "hostname": platform.node(),
        "ips": my_ips,
        "default_cidr": preferred["cidr"],
        "scan_interface": preferred.get(
            "name"
        ),
        "scan_ip": preferred.get(
            "ip"
        ),
        "scan_networks": network_results,
    }

    result = {
        # Compatibilidade com o frontend antigo.
        "cidr": (
            network_results[0]["cidr"]
            if network_results
            else None
        ),
        "scan_interface": (
            network_results[0]["interfaces"][0]
            if network_results
            and network_results[0]["interfaces"]
            else None
        ),

        # Formato novo multi-interface.
        "cidrs": [
            item["cidr"]
            for item in network_results
            if not item["skipped"]
        ],
        "scan_interfaces": sorted({
            interface
            for item in network_results
            for interface in item["interfaces"]
        }),
        "networks": network_results,
        "skipped_networks": skipped_networks,
        "found": len(devices_payload),
        "devices": devices_payload,
        "me": me_info,
        "scanned_at": now.isoformat(),
    }

    print(
        "\n✅ [SCAN GERAL] "
        f"{len(devices_payload)} dispositivo(s) em "
        f"{len(network_results)} rede(s)."
    )

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