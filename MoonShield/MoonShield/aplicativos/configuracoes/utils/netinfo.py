import socket
import ipaddress
import subprocess

def _netmask_to_prefix_int(netmask: str) -> int:
    try:
        return sum(bin(int(x)).count("1") for x in netmask.split("."))
    except Exception:
        return 0

def _get_mac(addr_list):
    for a in addr_list:
        if getattr(socket, "AF_PACKET", None) and a.family == socket.AF_PACKET:
            return a.address
        if hasattr(socket, "AF_LINK") and a.family == socket.AF_LINK:
            return a.address
    try:
        import psutil
        for a in addr_list:
            if a.family == psutil.AF_LINK:
                return a.address
    except Exception:
        pass
    return "00:00:00:00:00:00"

def _get_default_gateway_windows():
    """
    Fallback blindado para Windows. Roda `route print -4` 
    e tenta achar a linha 0.0.0.0.
    Retorna uma tupla (gateway_ip, interface_ip).
    """
    try:
        out = subprocess.check_output(["route", "print", "-4"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            # Uma rota padrão no windows parece com:
            # 0.0.0.0          0.0.0.0      192.168.0.1      192.168.0.42     35
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gw_ip = parts[2]
                iface_ip = parts[3]
                return gw_ip, iface_ip
    except Exception:
        pass
    return None, None

def _get_default_gateway_crossplatform():
    """
    Tenta primeiro netifaces. Se falhar ou vier vazio (comum no Windows),
    tenta o fallback pelo CMD.
    """
    try:
        import netifaces
        gws = netifaces.gateways()
        gw_ip = gws.get("default", {}).get(netifaces.AF_INET, (None, None))[0]
        if gw_ip:
            return gw_ip
    except ImportError:
        pass
    
    # Se netifaces falhou ou não está instalado, tenta via CMD no Windows
    import platform
    if platform.system() == "Windows":
        gw_ip, _ = _get_default_gateway_windows()
        return gw_ip
        
    return None


def get_interfaces():
    """Retorna a lista limpa e real de interfaces, calculando CIDR e Gateway."""
    import psutil
    
    default_gw_ip = _get_default_gateway_crossplatform()
    
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    out = []
    
    for name, addr_list in addrs.items():
        ipv4 = next((a for a in addr_list if a.family == socket.AF_INET), None)
        
        # Ignora interfaces sem IPv4, loopbacks ou APIPA
        if not ipv4 or ipv4.address.startswith("127.") or ipv4.address.startswith("169.254."):
            continue

        is_up = bool(stats.get(name) and stats[name].isup)
        prefix = _netmask_to_prefix_int(ipv4.netmask) if ipv4.netmask else None
        
        cidr = None
        is_principal = False
        
        if prefix is not None and ipv4.address:
            try:
                # Usa ipaddress para calcular a rede com exatidão
                net = ipaddress.IPv4Network(f"{ipv4.address}/{ipv4.netmask}", strict=False)
                cidr = str(net)
                
                # Regra de Ouro: Se o Gateway padrão couber nesta rede, esta é a interface principal
                if default_gw_ip and ipaddress.IPv4Address(default_gw_ip) in net:
                    is_principal = True
            except Exception:
                pass

        out.append({
            "name": name,
            "ip": ipv4.address,
            "netmask": ipv4.netmask or "",
            "prefix": prefix or 0,
            "cidr": cidr or "",
            "mac": _get_mac(addr_list),
            "gateway": default_gw_ip if is_principal else "—",
            "status": "up" if is_up else "down",
            "principal": is_principal,
        })

    # Fallback se nenhuma foi marcada como principal (pega a primeira que estiver UP)
    if out and not any(i["principal"] for i in out):
        for i in out:
            if i["status"] == "up":
                i["principal"] = True
                break

    # Ordenação final: Principal 1º > Depois as Ativas > Nome alfabético
    out.sort(key=lambda i: (not i["principal"], i["status"] != "up", i["name"].lower()))
    return out


def auto_discover():
    """Retorna o pacote de dados do Auto-Discover para o frontend."""
    ifaces = get_interfaces()
    
    # Acha a principal (ou a primeira da lista)
    iface = next((i for i in ifaces if i["principal"]), ifaces[0] if ifaces else None)
    
    if not iface:
        return {"ok": False, "erro": "Nenhuma interface detectada."}
        
    return {
        "ok": True,
        "iface": iface["name"],
        "ip": iface["ip"],
        "cidr": iface["cidr"],
        "gateway": iface["gateway"] if iface["gateway"] != "—" else "",
        "mac": iface["mac"],
    }