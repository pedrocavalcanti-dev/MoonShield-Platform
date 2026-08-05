"""
Serviço para detecção, análise e validação de interfaces de rede e topologia.
Focado no provisionamento seguro dos parâmetros base para configuração do IDS,
suportando inferência inteligente (WAN, LAN, MGMT) e leitura via comandos seguros.
"""

import os
import re
import socket
import logging
import ipaddress
from typing import Any
from pathlib import Path

from .tipos import (
    InterfaceRede,
    TopologiaRede,
    ResultadoEtapa,
    StatusEtapa,
    NivelLog,
    DiagnosticoItem,
    ConfiguracaoSuricataDados,
    ModoCaptura,
)
from .comandos import executar_comando, comando_existe
from .ambiente import eh_linux, eh_windows

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

INTERFACES_IGNORADAS = {
    "lo",
    "docker0",
    "podman0",
    "virbr0",
}

PREFIXOS_IGNORADOS = (
    "br-",
    "veth",
    "tun",
    "tap",
    "wg",
    "docker",
    "virbr",
    "vmnet",
    "zt",
)

PREFIXOS_VIRTUAIS = (
    "br-",
    "veth",
    "tun",
    "tap",
    "wg",
    "docker",
    "virbr",
    "vmnet",
    "zt",
    "tailscale",
)

ESTADOS_ATIVOS = {
    "up",
    "unknown",
}


# ==============================================================================
# VALIDAÇÃO BASE
# ==============================================================================

def validar_nome_interface(nome: str) -> bool:
    """Verifica se o nome da interface contém apenas caracteres seguros do SO."""
    if not isinstance(nome, str) or not nome:
        return False
    if len(nome) > 64:
        return False
    # Proíbe diretórios, null bytes e espaços
    if re.search(r"[/\\ \x00]", nome):
        return False
    # Permite apenas alfanuméricos e caracteres especiais comuns de rede
    if not re.match(r"^[a-zA-Z0-9.\-_:@]+$", nome):
        return False
    return True


def interface_ignorada(nome: str) -> bool:
    """Decide se a interface deve ser ocultada do escopo padrão de monitoramento."""
    if not nome:
        return True
    nome_lower = nome.lower()
    if nome_lower in INTERFACES_IGNORADAS:
        return True
    if any(nome_lower.startswith(pref) for pref in PREFIXOS_IGNORADOS):
        return True
    return False


def interface_virtual(nome: str) -> bool:
    """Identifica interfaces que não representam hardware físico de rede."""
    if not nome:
        return False
    nome_lower = nome.lower()
    if nome_lower == "lo":
        return True
    if any(nome_lower.startswith(pref) for pref in PREFIXOS_VIRTUAIS):
        return True
    return False


def calcular_rede_cidr(cidr: str) -> str:
    """Extrai o identificador de rede (ex: 10.0.0.0/24) a partir de um IP/CIDR."""
    if not cidr or "/" not in cidr:
        raise ValueError(f"Formato CIDR inválido: {cidr}")
    try:
        iface = ipaddress.IPv4Interface(cidr)
        return str(iface.network)
    except ValueError as e:
        raise ValueError(f"Falha ao interpretar CIDR IPv4 ({cidr}): {e}")


# ==============================================================================
# LEITURA DO SYSFS (LINUX)
# ==============================================================================

def obter_estado_interface(nome: str) -> str:
    """Lê de forma segura o status de link da interface via sysfs."""
    if not validar_nome_interface(nome):
        return "desconhecido"
    if eh_windows():
        return "desconhecido"
        
    caminho = Path(f"/sys/class/net/{nome}/operstate")
    try:
        return caminho.read_text(encoding="utf-8", errors="ignore").strip().lower()
    except (PermissionError, OSError):
        return "desconhecido"


def obter_mac_interface(nome: str) -> str:
    """Extrai o endereço MAC de hardware via sysfs."""
    if not validar_nome_interface(nome):
        return ""
    if eh_windows():
        return ""
        
    caminho = Path(f"/sys/class/net/{nome}/address")
    try:
        return caminho.read_text(encoding="utf-8", errors="ignore").strip().lower()
    except (PermissionError, OSError):
        return ""


def obter_mtu_interface(nome: str) -> int | None:
    """Extrai a configuração do Maximum Transmission Unit (MTU)."""
    if not validar_nome_interface(nome):
        return None
    if eh_windows():
        return None
        
    caminho = Path(f"/sys/class/net/{nome}/mtu")
    try:
        conteudo = caminho.read_text(encoding="utf-8", errors="ignore").strip()
        return int(conteudo)
    except (PermissionError, OSError, ValueError):
        return None


def obter_velocidade_interface(nome: str) -> int | None:
    """Extrai a velocidade da interface em Mbps (quando aplicável/negociada)."""
    if not validar_nome_interface(nome):
        return None
    if eh_windows():
        return None
        
    caminho = Path(f"/sys/class/net/{nome}/speed")
    try:
        conteudo = caminho.read_text(encoding="utf-8", errors="ignore").strip()
        vel = int(conteudo)
        return vel if vel > 0 else None
    except (PermissionError, OSError, ValueError):
        return None


def obter_contadores_interface(nome: str) -> dict[str, int]:
    """Coleta métricas de pacotes RX/TX da interface."""
    stats = {
        "rx_pkts": 0,
        "tx_pkts": 0,
        "rx_bytes": 0,
        "tx_bytes": 0,
    }
    
    if not validar_nome_interface(nome) or eh_windows():
        return stats
        
    sysfs_dir = Path(f"/sys/class/net/{nome}/statistics")
    
    arquivos_alvo = {
        "rx_pkts": "rx_packets",
        "tx_pkts": "tx_packets",
        "rx_bytes": "rx_bytes",
        "tx_bytes": "tx_bytes",
    }
    
    for chave, arquivo in arquivos_alvo.items():
        try:
            conteudo = (sysfs_dir / arquivo).read_text(encoding="utf-8", errors="ignore").strip()
            val = int(conteudo)
            stats[chave] = max(0, val)
        except (PermissionError, OSError, ValueError):
            pass
            
    return stats


# ==============================================================================
# COLETORES COMANDOS/SOCKET (LINUX E WINDOWS)
# ==============================================================================

def listar_nomes_interfaces_sistema() -> list[str]:
    """Lista primária de interfaces disponíveis sem aplicar filtros lógicos."""
    nomes = []
    
    if eh_linux():
        sysfs = Path("/sys/class/net")
        if sysfs.is_dir():
            try:
                for entry in sysfs.iterdir():
                    if entry.is_symlink() or entry.is_dir():
                        nome = entry.name
                        if nome and validar_nome_interface(nome):
                            nomes.append(nome)
            except OSError:
                pass
    else:
        # Windows fallback (quando socket.if_nameindex está disponível)
        if hasattr(socket, "if_nameindex"):
            try:
                for idx, nome in socket.if_nameindex():
                    if nome and validar_nome_interface(nome):
                        nomes.append(nome)
            except OSError:
                pass
                
    return sorted(nomes)


def detectar_wan() -> str:
    """Busca ativamente a rota padrão da máquina (gateway/internet)."""
    if not eh_linux():
        return ""
        
    resultado = executar_comando(["ip", "route", "show", "default"], timeout=10.0)
    if not resultado.sucesso or not resultado.saida:
        return ""
        
    tokens = resultado.saida.split()
    for i, t in enumerate(tokens):
        if t == "dev" and (i + 1) < len(tokens):
            nome_iface = tokens[i + 1].strip()
            if validar_nome_interface(nome_iface):
                return nome_iface
                
    return ""


def _listar_enderecos_ipv4_linux() -> list[dict[str, str]]:
    """Helper que extrai IP e máscara usando comando nativo 'ip' no Linux."""
    resultado = executar_comando(["ip", "-o", "-4", "addr", "show"], timeout=15.0)
    if not resultado.sucesso:
        return []
        
    enderecos = []
    vistos = set()
    
    for linha in resultado.saida.splitlines():
        partes = linha.split()
        if len(partes) < 4:
            continue
            
        nome_iface = partes[1].rstrip(":")
        
        # Limpa o sufixo numérico de aliases (ex: eth0:1 -> eth0)
        nome_real = nome_iface.split(":")[0]
        
        if interface_ignorada(nome_real) or not validar_nome_interface(nome_real):
            continue
            
        try:
            idx = partes.index("inet")
            ip_cidr = partes[idx + 1]
            ip_puro = ip_cidr.split("/")[0]
            
            # Validação via ipaddress
            _ = ipaddress.IPv4Interface(ip_cidr)
            
            # Bloqueia IPs de loopback
            if ipaddress.IPv4Address(ip_puro).is_loopback:
                continue
                
            chave_unica = f"{nome_real}-{ip_cidr}"
            if chave_unica in vistos:
                continue
                
            vistos.add(chave_unica)
            enderecos.append({
                "nome": nome_real,
                "ip": ip_puro,
                "cidr": ip_cidr,
            })
        except (ValueError, IndexError):
            continue
            
    return enderecos


def _listar_enderecos_ipv4_windows() -> list[dict[str, str]]:
    """Helper para mock/desenvolvimento que tenta capturar o IPv4 local padrão."""
    try:
        # Tenta obter o hostname e associar um IP local.
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        
        if not ip or ip.startswith("127."):
            # Fallback forçado caso DNS local retorne loopback
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            
        if ip and not ip.startswith("127."):
            try:
                _ = ipaddress.IPv4Address(ip)
                return [{
                    "nome": "Ethernet0",
                    "ip": ip,
                    "cidr": f"{ip}/32",
                }]
            except ValueError:
                pass
    except Exception:
        pass
        
    return []


# ==============================================================================
# COMPOSIÇÃO DE TOPOLOGIA
# ==============================================================================

def listar_interfaces(
    incluir_virtuais: bool = False,
    incluir_sem_ipv4: bool = False,
) -> list[InterfaceRede]:
    """Gera a matriz base com o perfil de todas as interfaces ativas da máquina."""
    resultado: list[InterfaceRede] = []
    
    if eh_linux():
        dados_ip = _listar_enderecos_ipv4_linux()
        wan_detectada = detectar_wan()
        
        # Consolida interfaces encontradas via IP
        nomes_com_ip = {d["nome"] for d in dados_ip}
        
        # Puxa interfaces sem IP se solicitado
        if incluir_sem_ipv4:
            todos_nomes = listar_nomes_interfaces_sistema()
            for nome in todos_nomes:
                if nome not in nomes_com_ip and not interface_ignorada(nome):
                    if incluir_virtuais or not interface_virtual(nome):
                        dados_ip.append({
                            "nome": nome,
                            "ip": "",
                            "cidr": "",
                        })

        for info in dados_ip:
            nome = info["nome"]
            cidr = info.get("cidr", "")
            
            if not incluir_virtuais and interface_virtual(nome):
                continue
                
            try:
                rede = calcular_rede_cidr(cidr) if cidr else ""
            except ValueError:
                rede = ""
                
            stats = obter_contadores_interface(nome)
            
            resultado.append(InterfaceRede(
                nome=nome,
                ip=info.get("ip", ""),
                cidr=cidr,
                rede=rede,
                estado=obter_estado_interface(nome),
                rx_pkts=stats["rx_pkts"],
                tx_pkts=stats["tx_pkts"],
                rota_padrao=(nome == wan_detectada),
                virtual=interface_virtual(nome),
                loopback=(nome.lower() == "lo"),
                mac=obter_mac_interface(nome),
                mtu=obter_mtu_interface(nome),
                velocidade_mbps=obter_velocidade_interface(nome),
            ))

    else:
        # Fallback Windows
        dados_ip = _listar_enderecos_ipv4_windows()
        for info in dados_ip:
            nome = info["nome"]
            cidr = info.get("cidr", "")
            try:
                rede = calcular_rede_cidr(cidr) if cidr else ""
            except ValueError:
                rede = ""
                
            resultado.append(InterfaceRede(
                nome=nome,
                ip=info.get("ip", ""),
                cidr=cidr,
                rede=rede,
                rota_padrao=True,
                virtual=False,
            ))

    # Remove duplicatas lógicas (caso existam IPs múltiplos na mesma IF)
    unicas = {}
    for r in resultado:
        if r.nome not in unicas:
            unicas[r.nome] = r
            
    lista_final = list(unicas.values())
    
    # Ordenação da saída: Rota padrão > Ativas > RX Pkts > Nome
    lista_final.sort(key=lambda i: (
        not i.rota_padrao,
        not i.ativa,
        -i.rx_pkts,
        i.nome
    ))
    
    return lista_final


def obter_interface_por_nome(nome: str, interfaces: list[InterfaceRede] | None = None) -> InterfaceRede | None:
    """Filtro utilitário exato."""
    if interfaces is None:
        interfaces = listar_interfaces()
    for iface in interfaces:
        if iface.nome == nome:
            return iface
    return None


def sugerir_lan(interfaces: list[InterfaceRede], wan: str = "") -> str:
    """Busca o melhor candidato local da máquina para classificar como infraestrutura interna."""
    candidatos = []
    
    for iface in interfaces:
        if iface.nome == wan:
            continue
        if iface.loopback:
            continue
        if iface.virtual:
            continue
            
        candidatos.append(iface)

    if not candidatos:
        return ""
        
    candidatos.sort(key=lambda i: (
        not i.ativa,
        not i.possui_ipv4,
        -i.rx_pkts,
        i.nome
    ))
    
    return candidatos[0].nome


def sugerir_mgmt(interfaces: list[InterfaceRede], wan: str = "", lan: str = "") -> str:
    """Sugerir uma interface separada de gerenciamento (OOB)."""
    candidatos = []
    
    for iface in interfaces:
        if iface.nome in (wan, lan):
            continue
        if iface.loopback:
            continue
            
        candidatos.append(iface)

    if not candidatos:
        return ""
        
    candidatos.sort(key=lambda i: (
        not i.ativa,
        not i.possui_ipv4,
        i.rx_pkts, # MGMT costuma ter muito menos tráfego do que redes operacionais
        i.nome
    ))
    
    return candidatos[0].nome


def obter_topologia_detectada(incluir_virtuais: bool = False) -> TopologiaRede:
    """Gera a árvore completa preenchendo as predições de topologia de rede local."""
    avisos = []
    ifaces = listar_interfaces(incluir_virtuais=incluir_virtuais, incluir_sem_ipv4=True)
    
    if not ifaces:
        avisos.append("Nenhuma interface de rede foi encontrada.")
        
    wan_str = detectar_wan()
    lan_str = sugerir_lan(ifaces, wan=wan_str)
    mgmt_str = sugerir_mgmt(ifaces, wan=wan_str, lan=lan_str)
    
    if not wan_str and eh_linux():
        avisos.append("A interface conectada à internet (WAN/Rota padrão) não pôde ser detectada.")
        
    if not lan_str and ifaces:
        avisos.append("Não foi possível inferir automaticamente qual interface representa a rede local (LAN).")
        
    if len(ifaces) == 1:
        avisos.append("Apenas uma interface útil foi detectada (modo In-Line único).")
        
    if eh_windows():
        avisos.append("Executando em Windows. Detecção de redes fortemente limitada.")

    return TopologiaRede(
        interfaces=ifaces,
        wan_sugerida=wan_str,
        lan_sugerida=lan_str,
        interface_mgmt_sugerida=mgmt_str,
        rota_padrao_encontrada=bool(wan_str),
        avisos=avisos,
    )


# ==============================================================================
# VALIDAÇÃO DO ASSISTENTE
# ==============================================================================

def montar_configuracao_sugerida(topologia: TopologiaRede | None = None) -> ConfiguracaoSuricataDados:
    """Injeta as sugestões do ambiente no DTO de Configuração base do MoonShield."""
    if not topologia:
        topologia = obter_topologia_detectada()
        
    cfg = ConfiguracaoSuricataDados()
    cfg.interface_wan = topologia.wan_sugerida
    cfg.interface_lan = topologia.lan_sugerida
    cfg.interface_mgmt = topologia.interface_mgmt_sugerida
    
    # Estratégia do Modo
    if topologia.wan_sugerida and topologia.lan_sugerida:
        cfg.modo_captura = ModoCaptura.LAN_WAN
        cfg.interfaces_monitoradas = [topologia.lan_sugerida, topologia.wan_sugerida]
    elif topologia.lan_sugerida:
        cfg.modo_captura = ModoCaptura.SOMENTE_LAN
        cfg.interfaces_monitoradas = [topologia.lan_sugerida]
        
    if topologia.lan_sugerida:
        iface_lan_obj = topologia.obter_interface(topologia.lan_sugerida)
        if iface_lan_obj:
            if iface_lan_obj.rede:
                cfg.home_net = [iface_lan_obj.rede]
            if iface_lan_obj.ip:
                cfg.dns_interno = iface_lan_obj.ip
                
    return cfg


def validar_topologia(configuracao: ConfiguracaoSuricataDados, interfaces: list[InterfaceRede] | None = None) -> list[str]:
    """Avalia criticamente as intenções de arquitetura de rede solicitadas."""
    mensagens = configuracao.validar()
    
    if interfaces is None:
        interfaces = listar_interfaces(incluir_virtuais=True, incluir_sem_ipv4=True)
        
    nomes_existentes = {i.nome for i in interfaces}
    
    # 1. Validação de existência física/virtual
    if configuracao.interface_wan and configuracao.interface_wan not in nomes_existentes:
        mensagens.append(f"A interface WAN definida ({configuracao.interface_wan}) não existe no sistema.")
        
    if configuracao.interface_lan and configuracao.interface_lan not in nomes_existentes:
        mensagens.append(f"A interface LAN definida ({configuracao.interface_lan}) não existe no sistema.")
        
    if configuracao.interface_mgmt and configuracao.interface_mgmt not in nomes_existentes:
        mensagens.append(f"A interface de gerência (MGMT) definida ({configuracao.interface_mgmt}) não existe no sistema.")
        
    for iface_mon in configuracao.interfaces_monitoradas:
        if iface_mon not in nomes_existentes:
            mensagens.append(f"A interface selecionada para monitoramento ({iface_mon}) não existe.")
            
    # 2. Conflitos Diretos
    if configuracao.interface_mgmt:
        if configuracao.interface_mgmt == configuracao.interface_wan:
            mensagens.append("A interface MGMT não pode ser a mesma que a WAN.")
        if configuracao.interface_mgmt == configuracao.interface_lan:
            mensagens.append("A interface MGMT não pode ser a mesma que a LAN.")
        if configuracao.interface_mgmt in configuracao.interfaces_monitoradas:
            mensagens.append("A interface de gerência (MGMT) não deve ser monitorada ativamente pelo IDS.")
            
    # 3. Validação IP/Subnet do HOME_NET
    vistos_homenet = set()
    for rede in configuracao.home_net:
        if rede in vistos_homenet:
            mensagens.append(f"A rede {rede} está duplicada no HOME_NET.")
            continue
        vistos_homenet.add(rede)
        
        try:
            _ = ipaddress.IPv4Network(rede, strict=False)
        except ValueError:
            mensagens.append(f"A rede fornecida ({rede}) possui um formato IPv4/CIDR inválido.")

    # 4. Modos vs Interfaces
    if configuracao.modo_captura == ModoCaptura.SOMENTE_LAN:
        if configuracao.interface_wan in configuracao.interfaces_monitoradas:
            mensagens.append("No modo SOMENTE_LAN, a WAN não deveria estar na lista de monitoramento.")
    elif configuracao.modo_captura == ModoCaptura.LAN_WAN:
        pass # Regras de inclusão básica cobertas pelo validador base do DTO
            
    return mensagens


def gerar_checks_interfaces(configuracao: ConfiguracaoSuricataDados | None = None) -> list[DiagnosticoItem]:
    """Transfere a saúde de rede detectada e/ou configurada para itens de diagnóstico estruturado."""
    itens = []
    topo = obter_topologia_detectada(incluir_virtuais=True)
    
    tem_interfaces = len(topo.interfaces) > 0
    itens.append(DiagnosticoItem(
        id="interfaces_detectadas",
        grupo="Interfaces",
        titulo="Detecção de Interfaces de Rede",
        ok=tem_interfaces,
        detalhe=f"{len(topo.interfaces)} detectadas." if tem_interfaces else "Nenhuma detectada.",
        acao="Verifique problemas de driver na placa de rede do servidor." if not tem_interfaces else "",
        critico=True,
    ))

    # WAN / LAN Detection
    tem_wan = bool(topo.wan_sugerida)
    itens.append(DiagnosticoItem(
        id="wan_detectada",
        grupo="Topologia",
        titulo="Interface de Saída (WAN)",
        ok=tem_wan,
        detalhe=f"Detectada na rota padrão: {topo.wan_sugerida}" if tem_wan else "Ausente (Sem rota padrão default).",
        acao="Em ambientes fechados uma WAN não é obrigatória, mas impede atualização de regras do IDS." if not tem_wan else "",
        critico=False,
    ))

    tem_lan = bool(topo.lan_sugerida)
    itens.append(DiagnosticoItem(
        id="lan_detectada",
        grupo="Topologia",
        titulo="Interface Interna (LAN)",
        ok=tem_lan,
        detalhe=f"Melhor candidata: {topo.lan_sugerida}" if tem_lan else "Ausente (Sem infraestrutura interna elegível).",
        acao="Defina a interface que espelha sua rede interna." if not tem_lan else "",
        critico=True,
    ))

    if configuracao:
        # Interfaces Monitoradas Selecionadas
        ifaces_inexistentes = []
        ifaces_down = []
        
        for mon in configuracao.interfaces_monitoradas:
            info = topo.obter_interface(mon)
            if not info:
                ifaces_inexistentes.append(mon)
            elif not info.ativa:
                ifaces_down.append(mon)

        ok_mon = len(ifaces_inexistentes) == 0 and len(configuracao.interfaces_monitoradas) > 0
        itens.append(DiagnosticoItem(
            id="interfaces_monitoradas_existem",
            grupo="Interfaces",
            titulo="Integridade das Interfaces do Suricata",
            ok=ok_mon,
            detalhe="Todas as interfaces de captura existem." if ok_mon else f"Inexistentes: {', '.join(ifaces_inexistentes)}",
            acao="Volte a configuração e selecione interfaces válidas." if not ok_mon else "",
            critico=True,
        ))

        ok_up = len(ifaces_down) == 0
        itens.append(DiagnosticoItem(
            id="interfaces_monitoradas_ativas",
            grupo="Interfaces",
            titulo="Estado do Link Físico/Virtual (UP/DOWN)",
            ok=ok_up,
            detalhe="Links OK." if ok_up else f"Offline: {', '.join(ifaces_down)}",
            acao="Execute 'ip link set <nome> up' ou cheque os cabos físicos das placas." if not ok_up else "",
            critico=False, # Aviso (A placa pode subir depois)
        ))

        # Check de Mgmt
        ok_mgmt = configuracao.interface_mgmt not in configuracao.interfaces_monitoradas
        itens.append(DiagnosticoItem(
            id="mgmt_fora_monitoramento",
            grupo="Topologia",
            titulo="Isolamento do canal de Gerência (MGMT)",
            ok=ok_mgmt,
            detalhe="Gerência segregada e protegida do Suricata." if ok_mgmt else "A interface de gerência está no af-packet do IDS.",
            acao="Remova a MGMT da lista de monitoramento para não derrubar sua sessão SSH ou degradar painel web com regras Drop." if not ok_mgmt else "",
            critico=False,
        ))

        # Check Homenet
        erros_homenet = False
        for net in configuracao.home_net:
            try:
                _ = ipaddress.IPv4Network(net, strict=False)
            except ValueError:
                erros_homenet = True
        
        ok_home = len(configuracao.home_net) > 0 and not erros_homenet
        itens.append(DiagnosticoItem(
            id="home_net_valido",
            grupo="Topologia",
            titulo="Arquitetura de Variáveis (HOME_NET)",
            ok=ok_home,
            detalhe="Redes internas protegidas válidas." if ok_home else "Vazio ou Contém formato de sub-rede inválido.",
            acao="Corrija a sub-rede. O Suricata usará HOME_NET para determinar a direção de Ataque nas assinaturas." if not ok_home else "",
            critico=True,
        ))

    return itens