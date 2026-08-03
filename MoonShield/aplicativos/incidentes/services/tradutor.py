# =============================================================================
# incidentes/services/tradutor.py  v3.2
#
# Mudanças v3.2:
#   ✓ Todos os nome_interno JG_ → MS_ (MoonShield)
#   ✓ Adicionados grupos faltantes no REGRAS_BUILTIN:
#       - Grupo A2 ext  (9900061–9900068)
#       - Grupo B2 ext  (9900069–9900076)
#       - Grupo J ext   (9900057–9900058)
#       - Grupo K       (9900077–9900086)
#       - Grupo L       (9900091–9900098)
#       - SIDs avulsos  (9900059, 9900060, 9900096, 9900097, 9900098)
# Mudanças v3.1:
#   ✓ Prefixos JG_ em REGRAS_BUILTIN renomeados para MS_ (MoonShield).
# Mudanças v3:
#   ✓ traduzir() sempre retorna 'categoria_jg' no dict de saída
#   ✓ _montar_saida() padronizado com todos os campos esperados pelo consumidor
# =============================================================================

import logging
import re
from typing import Optional

from django.utils import timezone

logger = logging.getLogger(__name__)

_cache_regras:      list | None = None
_cache_supressoes:  list | None = None
_cache_ts:          float = 0.0
_CACHE_TTL_SEGUNDOS = 60

# ─────────────────────────────────────────────────────────────────────────────
# FALLBACK POR CLASSTYPE / CATEGORIA
# ─────────────────────────────────────────────────────────────────────────────

_FALLBACK_CLASSTYPE: dict = {
    'attempted-recon':           ('Varredura ou reconhecimento de rede',   'recon',    'medio'),
    'attempted-admin':           ('Tentativa de acesso administrativo',     'auth',     'alto'),
    'attempted-user':            ('Tentativa de acesso a usuário',          'auth',     'medio'),
    'web-application-attack':    ('Ataque a aplicação web',                 'web',      'alto'),
    'trojan-activity':           ('Atividade de malware / trojan',          'malware',  'critico'),
    'bad-unknown':               ('Tráfego malicioso desconhecido',         'anomalia', 'alto'),
    'suspicious-traffic':        ('Tráfego suspeito detectado',             'anomalia', 'medio'),
    'policy-violation':          ('Violação de política de rede',           'p2p',      'medio'),
    'misc-attack':               ('Ataque genérico detectado',              'anomalia', 'medio'),
    'misc-activity':             ('Atividade de rede incomum',              'info',     'baixo'),
    'not-suspicious':            ('Atividade de rede normal',               'info',     'baixo'),
    'protocol-command-decode':   ('Decodificação de protocolo',             'info',     'baixo'),
    'network-scan':              ('Varredura de rede',                      'recon',    'medio'),
    'denial-of-service':         ('Possível ataque de negação de serviço',  'anomalia', 'alto'),
    'unknown':                   ('Alerta de rede não categorizado',        'info',     'baixo'),
}

_FALLBACK_CATEGORIA_SURICATA: dict = {
    'dns':     ('Atividade DNS suspeita',           'dns',      'baixo'),
    'http':    ('Requisição HTTP suspeita',         'web',      'medio'),
    'tls':     ('Tráfego TLS suspeito',             'tls',      'baixo'),
    'smtp':    ('Atividade de e-mail suspeita',     'anomalia', 'medio'),
    'ftp':     ('Atividade FTP detectada',          'auth',     'baixo'),
    'ssh':     ('Atividade SSH detectada',          'auth',     'medio'),
    'smb':     ('Atividade SMB detectada',          'lateral',  'medio'),
    'rdp':     ('Atividade RDP detectada',          'auth',     'medio'),
    'sql':     ('Atividade de banco de dados',      'lateral',  'medio'),
    'info':    ('Informação de rede coletada',      'info',     'baixo'),
    'policy':  ('Violação de política detectada',   'p2p',      'medio'),
    'malware': ('Indicador de malware detectado',   'malware',  'alto'),
    'exploit': ('Tentativa de exploração',          'malware',  'critico'),
}

_FALLBACK_PADRAO = ('Alerta de segurança detectado', 'info', 'baixo')

# ─────────────────────────────────────────────────────────────────────────────
# REGRAS BUILTIN — cobertura completa SIDs 9900001–9900098
# ─────────────────────────────────────────────────────────────────────────────

REGRAS_BUILTIN: list = [

    # ── Grupo A — Recon / Varredura Interna (9900001–9900008) ────────────────
    {
        'nome_interno':  'MS_RECON_PORT_SCAN_SYN',
        'tipo_match':    'sid', 'valor_match': '9900001',
        'titulo_jg':     'Varredura de portas (port scan SYN)',
        'resumo_jg':     'Origem tentando mapear portas abertas na rede',
        'categoria_jg':  'recon', 'severidade_jg': 'medio',
        'tags_jg':       ['scan', 'recon'],
        'recomendacoes': ['Identificar a origem do scan', 'Verificar se é um scanner autorizado', 'Bloquear no firewall se externo'],
    },
    {
        'nome_interno':  'MS_RECON_PING_SWEEP',
        'tipo_match':    'sid', 'valor_match': '9900002',
        'titulo_jg':     'Varredura de hosts ativos (ping sweep)',
        'resumo_jg':     'Origem enviando ICMP para múltiplos hosts — mapeamento de rede',
        'categoria_jg':  'recon', 'severidade_jg': 'medio',
        'tags_jg':       ['icmp', 'sweep', 'recon'],
        'recomendacoes': ['Verificar a origem', 'Verificar se é ferramenta de monitoramento legítima'],
    },
    {
        'nome_interno':  'MS_RECON_HOST_SWEEP_TCP',
        'tipo_match':    'sid', 'valor_match': '9900003',
        'titulo_jg':     'Varredura de hosts via TCP (host sweep)',
        'resumo_jg':     'Origem conectando TCP em múltiplos destinos — reconhecimento agressivo',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['sweep', 'recon', 'tcp'],
        'recomendacoes': ['Isolar origem imediatamente', 'Verificar comprometimento'],
    },
    {
        'nome_interno':  'MS_RECON_SNMP_SCAN',
        'tipo_match':    'sid', 'valor_match': '9900004',
        'titulo_jg':     'Scan SNMP (coleta de informações de rede)',
        'resumo_jg':     'Consultas SNMP em massa — possível coleta de topologia de rede',
        'categoria_jg':  'recon', 'severidade_jg': 'medio',
        'tags_jg':       ['snmp', 'recon'],
        'recomendacoes': ['Verificar se origem tem permissão SNMP', 'Desabilitar SNMP se não utilizado'],
    },
    {
        'nome_interno':  'MS_RECON_WEB_PANEL_SCAN',
        'tipo_match':    'sid', 'valor_match': '9900005',
        'titulo_jg':     'Varredura de painéis de administração web',
        'resumo_jg':     'Origem tentando acessar múltiplas portas web — busca de painéis admin',
        'categoria_jg':  'recon', 'severidade_jg': 'medio',
        'tags_jg':       ['scan', 'web', 'admin-panel'],
        'recomendacoes': ['Bloquear origem no WAF/firewall', 'Revisar exposição de painéis admin'],
    },
    {
        'nome_interno':  'MS_RECON_UDP_PORTSCAN',
        'tipo_match':    'sid', 'valor_match': '9900006',
        'titulo_jg':     'Varredura de portas UDP',
        'resumo_jg':     'Scan UDP em múltiplas portas — reconhecimento de serviços UDP',
        'categoria_jg':  'recon', 'severidade_jg': 'medio',
        'tags_jg':       ['scan', 'udp'],
        'recomendacoes': ['Verificar origem', 'Bloquear no firewall se não autorizado'],
    },
    {
        'nome_interno':  'MS_RECON_ARP_EXCESSIVO',
        'tipo_match':    'sid', 'valor_match': '9900007',
        'titulo_jg':     'Volume anormal de requisições ARP',
        'resumo_jg':     'Excesso de ARP — possível scan na camada 2 ou dispositivo com problema',
        'categoria_jg':  'recon', 'severidade_jg': 'baixo',
        'tags_jg':       ['arp', 'recon'],
        'recomendacoes': ['Identificar o dispositivo', 'Verificar se é ARP poisoning'],
    },
    {
        'nome_interno':  'MS_RECON_FINGERPRINT_PORTS',
        'tipo_match':    'sid', 'valor_match': '9900008',
        'titulo_jg':     'Conexão em portas de fingerprinting (backdoor/hacker)',
        'resumo_jg':     'Acesso a portas 1337/4444/12345/31337 — associadas a ferramentas de ataque',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['fingerprint', 'c2-ports'],
        'recomendacoes': ['Investigar a conexão imediatamente', 'Verificar se existe serviço legítimo nessas portas'],
    },

    # ── Grupo B — Brute Force Interno (9900009–9900016) ──────────────────────
    {
        'nome_interno':  'MS_AUTH_BRUTE_SSH',
        'tipo_match':    'sid', 'valor_match': '9900009',
        'titulo_jg':     'Brute force SSH interno detectado',
        'resumo_jg':     'Múltiplas tentativas de autenticação SSH em pouco tempo (origem interna)',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'ssh'],
        'recomendacoes': ['Bloquear IP de origem no firewall', 'Habilitar fail2ban', 'Verificar se algum acesso foi bem-sucedido', 'Considerar mover SSH para porta não padrão'],
    },
    {
        'nome_interno':  'MS_AUTH_BRUTE_RDP',
        'tipo_match':    'sid', 'valor_match': '9900010',
        'titulo_jg':     'Brute force RDP interno detectado',
        'resumo_jg':     'Múltiplas tentativas de login RDP (área de trabalho remota) — origem interna',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'rdp', 'windows'],
        'recomendacoes': ['Bloquear IP de origem', 'Habilitar NLA no RDP', 'Considerar VPN para acesso remoto', 'Verificar logs de acesso Windows'],
    },
    {
        'nome_interno':  'MS_AUTH_BRUTE_FTP',
        'tipo_match':    'sid', 'valor_match': '9900011',
        'titulo_jg':     'Brute force FTP interno detectado',
        'resumo_jg':     'Tentativas repetidas de login FTP (origem interna)',
        'categoria_jg':  'auth', 'severidade_jg': 'alto',
        'tags_jg':       ['brute-force', 'ftp'],
        'recomendacoes': ['Bloquear IP de origem', 'Considerar desabilitar FTP e usar SFTP'],
    },
    {
        'nome_interno':  'MS_AUTH_BRUTE_SMB',
        'tipo_match':    'sid', 'valor_match': '9900012',
        'titulo_jg':     'Brute force SMB / compartilhamento de rede',
        'resumo_jg':     'Tentativas repetidas de autenticação SMB (compartilhamento Windows)',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'smb', 'lateral'],
        'recomendacoes': ['Bloquear IP de origem', 'Revisar compartilhamentos', 'Verificar se há movimento lateral'],
    },
    {
        'nome_interno':  'MS_AUTH_BRUTE_WINRM',
        'tipo_match':    'sid', 'valor_match': '9900013',
        'titulo_jg':     'Brute force WinRM (administração remota Windows)',
        'resumo_jg':     'Tentativas de login no Windows Remote Management',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'winrm', 'windows'],
        'recomendacoes': ['Bloquear IP de origem', 'Restringir WinRM por IP', 'Verificar logs de evento Windows'],
    },
    {
        'nome_interno':  'MS_AUTH_BRUTE_WINRM_HTTPS',
        'tipo_match':    'sid', 'valor_match': '9900014',
        'titulo_jg':     'Brute force WinRM HTTPS (porta 5986)',
        'resumo_jg':     'Tentativas de login no WinRM via HTTPS',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'winrm', 'windows'],
        'recomendacoes': ['Bloquear IP de origem', 'Restringir WinRM por IP'],
    },
    {
        'nome_interno':  'MS_AUTH_BRUTE_TELNET',
        'tipo_match':    'sid', 'valor_match': '9900015',
        'titulo_jg':     'Brute force Telnet interno detectado',
        'resumo_jg':     'Tentativas repetidas de login via Telnet (protocolo inseguro)',
        'categoria_jg':  'auth', 'severidade_jg': 'alto',
        'tags_jg':       ['brute-force', 'telnet'],
        'recomendacoes': ['Bloquear IP de origem', 'Desabilitar Telnet e usar SSH'],
    },
    {
        'nome_interno':  'MS_AUTH_BRUTE_WEB',
        'tipo_match':    'sid', 'valor_match': '9900016',
        'titulo_jg':     'Brute force em painel web (interno)',
        'resumo_jg':     'Múltiplas requisições HTTP — possível ataque de força bruta em formulário de login',
        'categoria_jg':  'auth', 'severidade_jg': 'alto',
        'tags_jg':       ['brute-force', 'web'],
        'recomendacoes': ['Bloquear IP no WAF', 'Ativar CAPTCHA', 'Habilitar 2FA no painel'],
    },

    # ── Grupo C — Movimento Lateral (9900017–9900022) ─────────────────────────
    {
        'nome_interno':  'MS_LATERAL_RPC',
        'tipo_match':    'sid', 'valor_match': '9900017',
        'titulo_jg':     'Varredura RPC (movimento lateral)',
        'resumo_jg':     'Conexões RPC para múltiplos hosts — possível propagação de malware',
        'categoria_jg':  'lateral', 'severidade_jg': 'alto',
        'tags_jg':       ['lateral', 'rpc', 'windows'],
        'recomendacoes': ['Isolar host de origem', 'Verificar comprometimento', 'Verificar antivírus'],
    },
    {
        'nome_interno':  'MS_LATERAL_NETBIOS',
        'tipo_match':    'sid', 'valor_match': '9900018',
        'titulo_jg':     'Varredura NetBIOS (movimento lateral)',
        'resumo_jg':     'Consultas NetBIOS para múltiplos hosts na rede',
        'categoria_jg':  'lateral', 'severidade_jg': 'medio',
        'tags_jg':       ['lateral', 'netbios', 'windows'],
        'recomendacoes': ['Verificar se host é legítimo', 'Bloquear NetBIOS no segmento se não necessário'],
    },
    {
        'nome_interno':  'MS_LATERAL_SMB_SWEEP',
        'tipo_match':    'sid', 'valor_match': '9900019',
        'titulo_jg':     'Varredura SMB em múltiplos hosts (movimento lateral)',
        'resumo_jg':     'Conexões SMB para muitos hosts — sinal clássico de worm ou ransomware',
        'categoria_jg':  'lateral', 'severidade_jg': 'critico',
        'tags_jg':       ['lateral', 'smb', 'ransomware', 'worm'],
        'recomendacoes': ['Isolar host IMEDIATAMENTE', 'Verificar presença de ransomware', 'Revisar backups'],
    },
    {
        'nome_interno':  'MS_LATERAL_MSSQL',
        'tipo_match':    'sid', 'valor_match': '9900020',
        'titulo_jg':     'Acesso lateral a SQL Server',
        'resumo_jg':     'Conexões SQL Server para múltiplos hosts — possível movimento lateral via BD',
        'categoria_jg':  'lateral', 'severidade_jg': 'alto',
        'tags_jg':       ['lateral', 'sql', 'mssql'],
        'recomendacoes': ['Verificar credenciais SQL', 'Restringir acesso ao SQL Server por IP'],
    },
    {
        'nome_interno':  'MS_LATERAL_MYSQL',
        'tipo_match':    'sid', 'valor_match': '9900021',
        'titulo_jg':     'Acesso lateral a MySQL',
        'resumo_jg':     'Conexões MySQL para múltiplos hosts',
        'categoria_jg':  'lateral', 'severidade_jg': 'alto',
        'tags_jg':       ['lateral', 'sql', 'mysql'],
        'recomendacoes': ['Verificar credenciais MySQL', 'Restringir bind-address no MySQL'],
    },
    {
        'nome_interno':  'MS_LATERAL_POSTGRESQL',
        'tipo_match':    'sid', 'valor_match': '9900022',
        'titulo_jg':     'Acesso lateral a PostgreSQL',
        'resumo_jg':     'Conexões PostgreSQL para múltiplos hosts',
        'categoria_jg':  'lateral', 'severidade_jg': 'alto',
        'tags_jg':       ['lateral', 'sql', 'postgresql'],
        'recomendacoes': ['Verificar pg_hba.conf', 'Restringir acesso ao PostgreSQL por IP'],
    },

    # ── Grupo D — DNS / Policy (9900023–9900032 + 9900059) ───────────────────
    {
        'nome_interno':  'MS_DNS_BYPASS_GOOGLE',
        'tipo_match':    'sid', 'valor_match': '9900023',
        'titulo_jg':     'Cliente usando DNS público (Google DNS — bypass)',
        'resumo_jg':     'Dispositivo consultando 8.8.8.x diretamente — bypassa o AdGuard',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['bypass-dns', 'policy', 'adguard'],
        'recomendacoes': ['Bloquear 8.8.8.8/8.8.4.4 no firewall (UDP/TCP 53)', 'Forçar DNS para o AdGuard interno', 'Identificar o dispositivo infrator'],
    },
    {
        'nome_interno':  'MS_DNS_BYPASS_CLOUDFLARE',
        'tipo_match':    'sid', 'valor_match': '9900024',
        'titulo_jg':     'Cliente usando DNS público (Cloudflare — bypass)',
        'resumo_jg':     'Dispositivo consultando 1.1.1.x diretamente — bypassa o AdGuard',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['bypass-dns', 'policy', 'adguard'],
        'recomendacoes': ['Bloquear 1.1.1.1/1.0.0.1 no firewall (UDP/TCP 53)', 'Forçar DNS para o AdGuard interno'],
    },
    {
        'nome_interno':  'MS_DNS_BYPASS_QUAD9',
        'tipo_match':    'sid', 'valor_match': '9900025',
        'titulo_jg':     'Cliente usando DNS público (Quad9 — bypass)',
        'resumo_jg':     'Dispositivo consultando 9.9.9.x diretamente — bypassa o AdGuard',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['bypass-dns', 'policy', 'adguard'],
        'recomendacoes': ['Bloquear 9.9.9.9 no firewall (UDP/TCP 53)', 'Forçar DNS para o AdGuard interno'],
    },
    {
        'nome_interno':  'MS_DNS_VOLUME_ALTO',
        'tipo_match':    'sid', 'valor_match': '9900026',
        'titulo_jg':     'Volume anormalmente alto de consultas DNS externas',
        'resumo_jg':     'Dispositivo fazendo muitas consultas DNS — possível data exfiltration via DNS',
        'categoria_jg':  'dns', 'severidade_jg': 'alto',
        'tags_jg':       ['dns-tunneling', 'exfil'],
        'recomendacoes': ['Capturar e analisar as queries DNS', 'Verificar se os domínios são suspeitos', 'Verificar data exfiltration via DNS'],
    },
    {
        'nome_interno':  'MS_DNS_NXDOMAIN_MASSA',
        'tipo_match':    'sid', 'valor_match': '9900027',
        'titulo_jg':     'Excesso de domínios inválidos (NXDOMAIN) — possível malware DGA',
        'resumo_jg':     'Muitas resoluções de domínios inexistentes — padrão clássico de malware com DGA',
        'categoria_jg':  'dns', 'severidade_jg': 'alto',
        'tags_jg':       ['dga', 'malware', 'dns'],
        'recomendacoes': ['Isolar o dispositivo', 'Verificar presença de malware', 'Analisar os domínios NXDOMAIN'],
    },
    {
        'nome_interno':  'MS_DNS_IPAPI_LOOKUP',
        'tipo_match':    'sid', 'valor_match': '9900028',
        'titulo_jg':     'Consulta a ip-api.com (descoberta de IP público)',
        'resumo_jg':     'Acesso a ip-api.com — comum em malware e ferramentas de reconhecimento',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['external-ip-lookup', 'policy'],
        'recomendacoes': ['Identificar o dispositivo e o processo que fez a consulta', 'Verificar se é aplicativo legítimo ou malware'],
    },
    {
        'nome_interno':  'MS_DNS_IFCONFIG_LOOKUP',
        'tipo_match':    'sid', 'valor_match': '9900029',
        'titulo_jg':     'Consulta a ifconfig.me (descoberta de IP público)',
        'resumo_jg':     'Acesso a ifconfig.me — comum em scripts de reconhecimento e malware',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['external-ip-lookup', 'policy'],
        'recomendacoes': ['Identificar o dispositivo e o processo que fez a consulta'],
    },
    {
        'nome_interno':  'MS_DNS_IPIFY_LOOKUP',
        'tipo_match':    'sid', 'valor_match': '9900030',
        'titulo_jg':     'Consulta a api.ipify.org (descoberta de IP público)',
        'resumo_jg':     'Acesso a api.ipify.org — serviço de IP lookup usado por malware',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['external-ip-lookup', 'policy'],
        'recomendacoes': ['Identificar o dispositivo e o processo que fez a consulta'],
    },
    {
        'nome_interno':  'MS_DNS_CHECKIP_LOOKUP',
        'tipo_match':    'sid', 'valor_match': '9900031',
        'titulo_jg':     'Consulta a checkip.amazonaws.com (descoberta de IP público)',
        'resumo_jg':     'Acesso a checkip.amazonaws.com — pode indicar reconhecimento de IP externo',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['external-ip-lookup', 'policy'],
        'recomendacoes': ['Identificar o dispositivo e o processo que fez a consulta'],
    },
    {
        'nome_interno':  'MS_DNS_WHATISMYIP_LOOKUP',
        'tipo_match':    'sid', 'valor_match': '9900032',
        'titulo_jg':     'Consulta a serviço whatismyip (descoberta de IP público)',
        'resumo_jg':     'Acesso a serviço whatismyip — reconhecimento de IP externo',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['external-ip-lookup', 'policy'],
        'recomendacoes': ['Identificar o dispositivo e o processo que fez a consulta'],
    },
    {
        'nome_interno':  'MS_DNS_ICANHAZIP_LOOKUP',
        'tipo_match':    'sid', 'valor_match': '9900059',
        'titulo_jg':     'Consulta a serviço icanhazip (descoberta de IP público)',
        'resumo_jg':     'Acesso a icanhazip — serviço de IP lookup externo',
        'categoria_jg':  'dns', 'severidade_jg': 'medio',
        'tags_jg':       ['external-ip-lookup', 'policy'],
        'recomendacoes': ['Identificar o dispositivo e o processo que fez a consulta'],
    },

    # ── Grupo E — P2P / Mineração (9900033–9900038 + 9900060 + 9900096) ──────
    {
        'nome_interno':  'MS_P2P_BITTORRENT_HANDSHAKE',
        'tipo_match':    'sid', 'valor_match': '9900033',
        'titulo_jg':     'BitTorrent detectado na rede',
        'resumo_jg':     'Handshake BitTorrent identificado — uso de P2P na rede',
        'categoria_jg':  'p2p', 'severidade_jg': 'medio',
        'tags_jg':       ['p2p', 'bittorrent', 'policy'],
        'recomendacoes': ['Identificar o dispositivo', 'Aplicar política de uso aceitável', 'Bloquear portas BitTorrent no firewall'],
    },
    {
        'nome_interno':  'MS_P2P_BITTORRENT_TRACKER',
        'tipo_match':    'sid', 'valor_match': '9900034',
        'titulo_jg':     'Cliente BitTorrent conectando a tracker',
        'resumo_jg':     'Requisição HTTP para tracker torrent detectada',
        'categoria_jg':  'p2p', 'severidade_jg': 'medio',
        'tags_jg':       ['p2p', 'bittorrent', 'policy'],
        'recomendacoes': ['Identificar o dispositivo', 'Bloquear tracker URLs no proxy'],
    },
    {
        'nome_interno':  'MS_MINING_STRATUM_SUBSCRIBE',
        'tipo_match':    'sid', 'valor_match': '9900035',
        'titulo_jg':     'Mineração de criptomoedas detectada (mining.subscribe)',
        'resumo_jg':     'Conexão ao protocolo Stratum (mining.subscribe) — máquina pode estar minerando',
        'categoria_jg':  'p2p', 'severidade_jg': 'alto',
        'tags_jg':       ['mining', 'cryptominer', 'policy'],
        'recomendacoes': ['Identificar e isolar o dispositivo', 'Verificar se é cryptojacking (malware minerador)', 'Bloquear portas Stratum no firewall'],
    },
    {
        'nome_interno':  'MS_MINING_STRATUM_AUTH',
        'tipo_match':    'sid', 'valor_match': '9900036',
        'titulo_jg':     'Mineração de criptomoedas detectada (mining.authorize)',
        'resumo_jg':     'Conexão ao protocolo Stratum (mining.authorize) — autenticação em pool de mineração',
        'categoria_jg':  'p2p', 'severidade_jg': 'alto',
        'tags_jg':       ['mining', 'cryptominer', 'policy'],
        'recomendacoes': ['Identificar e isolar o dispositivo', 'Bloquear portas Stratum no firewall'],
    },
    {
        'nome_interno':  'MS_MINING_DNS_XMR',
        'tipo_match':    'sid', 'valor_match': '9900037',
        'titulo_jg':     'Consulta DNS a pool de mineração (XMR)',
        'resumo_jg':     'Resolução de domínio com "xmr" — indicativo de mineração Monero',
        'categoria_jg':  'p2p', 'severidade_jg': 'alto',
        'tags_jg':       ['mining', 'cryptominer', 'dns'],
        'recomendacoes': ['Identificar e isolar o dispositivo', 'Bloquear domínios de mining no AdGuard'],
    },
    {
        'nome_interno':  'MS_TOR_PORTS_38',
        'tipo_match':    'sid', 'valor_match': '9900038',
        'titulo_jg':     'Conexão a portas Tor (proxy/anonimizador)',
        'resumo_jg':     'Tráfego para portas Tor confirmadas — possível evasão de controles de rede',
        'categoria_jg':  'p2p', 'severidade_jg': 'alto',
        'tags_jg':       ['tor', 'policy', 'proxy'],
        'recomendacoes': ['Identificar o dispositivo', 'Bloquear portas Tor no firewall'],
    },
    {
        'nome_interno':  'MS_MINING_DNS_MONERO',
        'tipo_match':    'sid', 'valor_match': '9900060',
        'titulo_jg':     'Consulta DNS a pool de mineração (Monero)',
        'resumo_jg':     'Resolução de domínio com "monero" — indicativo de mineração de criptomoeda',
        'categoria_jg':  'p2p', 'severidade_jg': 'alto',
        'tags_jg':       ['mining', 'cryptominer', 'dns'],
        'recomendacoes': ['Identificar e isolar o dispositivo', 'Bloquear domínios de mining no AdGuard'],
    },
    {
        'nome_interno':  'MS_MINING_DNS_NICEHASH',
        'tipo_match':    'sid', 'valor_match': '9900096',
        'titulo_jg':     'Consulta DNS a pool de mineração (NiceHash)',
        'resumo_jg':     'Resolução de domínio com "nicehash" — indicativo de mineração de criptomoeda',
        'categoria_jg':  'p2p', 'severidade_jg': 'alto',
        'tags_jg':       ['mining', 'cryptominer', 'dns'],
        'recomendacoes': ['Identificar e isolar o dispositivo', 'Bloquear domínios de mining no AdGuard'],
    },

    # ── Grupo F — Anomalia / Bot (9900039–9900046) ────────────────────────────
    {
        'nome_interno':  'MS_BOT_TCP_EXTERNO_MASSA',
        'tipo_match':    'sid', 'valor_match': '9900039',
        'titulo_jg':     'Volume anormal de conexões TCP externas (possível bot)',
        'resumo_jg':     'Dispositivo iniciando centenas de conexões TCP externas — comportamento de botnet',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['botnet', 'c2', 'anomalia'],
        'recomendacoes': ['Isolar o dispositivo imediatamente', 'Verificar processos em execução', 'Fazer scan de malware'],
    },
    {
        'nome_interno':  'MS_ANOMALIA_ICMP_TUNNEL',
        'tipo_match':    'sid', 'valor_match': '9900040',
        'titulo_jg':     'Volume alto de ICMP externo (possível ICMP tunnel)',
        'resumo_jg':     'Muitos pings para destinos externos — pode ser exfiltração de dados via ICMP',
        'categoria_jg':  'exfil', 'severidade_jg': 'alto',
        'tags_jg':       ['icmp-tunnel', 'exfil', 'evasion'],
        'recomendacoes': ['Bloquear ICMP externo no firewall', 'Analisar payload dos pacotes ICMP'],
    },
    {
        'nome_interno':  'MS_TLS_BEACONING',
        'tipo_match':    'sid', 'valor_match': '9900041',
        'titulo_jg':     'TLS beaconing detectado (possível C2)',
        'resumo_jg':     'Conexões TLS repetitivas ao mesmo SNI — padrão de C2 de malware',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['beaconing', 'c2', 'tls', 'malware'],
        'recomendacoes': ['Isolar dispositivo', 'Analisar o SNI/domínio destino', 'Verificar processo responsável', 'Fazer scan completo'],
    },
    {
        'nome_interno':  'MS_DNS_BEACONING',
        'tipo_match':    'sid', 'valor_match': '9900042',
        'titulo_jg':     'DNS beaconing detectado (possível C2 via DNS)',
        'resumo_jg':     'Consultas DNS repetitivas ao mesmo domínio — padrão de C2 via DNS',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['beaconing', 'c2', 'dns', 'malware'],
        'recomendacoes': ['Isolar dispositivo', 'Bloquear domínio no AdGuard', 'Analisar processo responsável'],
    },
    {
        'nome_interno':  'MS_C2_PORTS_CONHECIDOS',
        'tipo_match':    'sid', 'valor_match': '9900043',
        'titulo_jg':     'Conexão a portas associadas a C2 / backdoors',
        'resumo_jg':     'Acesso a portas 1337/4444/6667/31337 — conhecidas por ferramentas de ataque',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['c2', 'backdoor', 'malware'],
        'recomendacoes': ['Isolar dispositivo imediatamente', 'Verificar processos e conexões ativas', 'Investigar se há backdoor instalado'],
    },
    {
        'nome_interno':  'MS_HTTP_UA_VAZIO',
        'tipo_match':    'sid', 'valor_match': '9900044',
        'titulo_jg':     'Requisição HTTP sem User-Agent (comportamento de malware)',
        'resumo_jg':     'HTTP sem User-Agent é incomum em browsers legítimos — associado a malware e scanners',
        'categoria_jg':  'malware', 'severidade_jg': 'medio',
        'tags_jg':       ['http', 'malware', 'scanner'],
        'recomendacoes': ['Verificar o destino da requisição', 'Identificar o processo responsável no dispositivo'],
    },
    {
        'nome_interno':  'MS_HTTP_DOWNLOAD_EXE',
        'tipo_match':    'sid', 'valor_match': '9900045',
        'titulo_jg':     'Download de executável via HTTP (sem criptografia)',
        'resumo_jg':     'Arquivo .exe baixado por HTTP — risco de malware ou atualização não segura',
        'categoria_jg':  'malware', 'severidade_jg': 'alto',
        'tags_jg':       ['http', 'download', 'exe', 'malware'],
        'recomendacoes': ['Verificar o arquivo baixado', 'Executar antivírus', 'Bloquear downloads HTTP no proxy'],
    },
    {
        'nome_interno':  'MS_DNS_DGA_REGEX',
        'tipo_match':    'sid', 'valor_match': '9900046',
        'titulo_jg':     'Consulta DNS a domínio aleatório (padrão DGA)',
        'resumo_jg':     'Domínio com 18+ caracteres aleatórios — característico de malware com Domain Generation Algorithm',
        'categoria_jg':  'malware', 'severidade_jg': 'alto',
        'tags_jg':       ['dga', 'malware', 'dns'],
        'recomendacoes': ['Isolar dispositivo', 'Verificar presença de malware', 'Bloquear domínio no AdGuard'],
    },

    # ── Grupo G — TLS / QUIC (9900047–9900050) ────────────────────────────────
    {
        'nome_interno':  'MS_QUIC_INFORMATIVO',
        'tipo_match':    'sid', 'valor_match': '9900047',
        'titulo_jg':     'Tráfego QUIC detectado (HTTP/3)',
        'resumo_jg':     'Uso do protocolo QUIC (UDP/443) — pode dificultar inspeção de tráfego',
        'categoria_jg':  'tls', 'severidade_jg': 'informativo',
        'tags_jg':       ['quic', 'http3', 'info'],
        'recomendacoes': ['Considerar bloquear QUIC no firewall se inspeção TLS for necessária'],
    },
    {
        'nome_interno':  'MS_TLS_SNI_NUMERICO',
        'tipo_match':    'sid', 'valor_match': '9900048',
        'titulo_jg':     'TLS com SNI numérico suspeito (possível CDN C2 ou DGA)',
        'resumo_jg':     'SNI com subdomínio totalmente numérico — incomum em serviços legítimos',
        'categoria_jg':  'tls', 'severidade_jg': 'medio',
        'tags_jg':       ['tls', 'sni', 'dga', 'c2'],
        'recomendacoes': ['Verificar o SNI destino', 'Investigar o processo responsável'],
    },
    {
        'nome_interno':  'MS_TLS_SEM_SNI',
        'tipo_match':    'sid', 'valor_match': '9900049',
        'titulo_jg':     'Conexão TLS sem SNI (acesso direto por IP)',
        'resumo_jg':     'TLS sem indicação de hostname — comum em malware e ferramentas de ataque',
        'categoria_jg':  'tls', 'severidade_jg': 'medio',
        'tags_jg':       ['tls', 'no-sni', 'suspeito'],
        'recomendacoes': ['Verificar o IP destino', 'Investigar o processo responsável'],
    },
    {
        'nome_interno':  'MS_QUIC_VOLUME_ALTO',
        'tipo_match':    'sid', 'valor_match': '9900050',
        'titulo_jg':     'Volume alto de QUIC (possível bypass de inspeção / exfiltração)',
        'resumo_jg':     'Muito tráfego QUIC de uma origem — pode estar evadindo inspeção TLS',
        'categoria_jg':  'exfil', 'severidade_jg': 'medio',
        'tags_jg':       ['quic', 'evasion', 'exfil'],
        'recomendacoes': ['Considerar bloquear QUIC no firewall', 'Investigar origem do tráfego'],
    },

    # ── Grupo H — Nmap / OS Fingerprint Interno (9900051–9900053) ────────────
    {
        'nome_interno':  'MS_RECON_NMAP_NULL',
        'tipo_match':    'sid', 'valor_match': '9900051',
        'titulo_jg':     'Nmap NULL scan detectado (interno)',
        'resumo_jg':     'Pacote TCP sem nenhuma flag — técnica de fingerprint usada exclusivamente pelo Nmap e scanners',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['nmap', 'scan', 'fingerprint', 'recon'],
        'recomendacoes': ['Identificar e bloquear a origem no firewall', 'Verificar se é scanner de segurança autorizado', 'Analisar outros alertas do mesmo IP nas últimas 24h'],
    },
    {
        'nome_interno':  'MS_RECON_NMAP_XMAS',
        'tipo_match':    'sid', 'valor_match': '9900052',
        'titulo_jg':     'Nmap XMAS scan detectado (interno)',
        'resumo_jg':     'Pacote TCP com flags FIN+PSH+URG — combinação impossível em tráfego legítimo, exclusiva de scanners',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['nmap', 'scan', 'xmas', 'fingerprint'],
        'recomendacoes': ['Bloquear a origem imediatamente', 'Verificar se há outros scans ativos do mesmo IP', 'Auditar serviços expostos varridos'],
    },
    {
        'nome_interno':  'MS_RECON_NMAP_SYN_FIN',
        'tipo_match':    'sid', 'valor_match': '9900053',
        'titulo_jg':     'Flag TCP anômala SYN+FIN (fingerprint de OS / Nmap)',
        'resumo_jg':     'Combinação SYN+FIN é inválida no RFC 793 — usada apenas por ferramentas de fingerprint como Nmap',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['nmap', 'fingerprint', 'os-detection'],
        'recomendacoes': ['Bloquear a origem no firewall', 'Verificar outros alertas do IP nas últimas horas', 'Confirmar se é scan autorizado de segurança'],
    },

    # ── Grupo I — DNS Tunneling (9900054–9900055) ─────────────────────────────
    {
        'nome_interno':  'MS_DNS_TUNNEL_PAYLOAD',
        'tipo_match':    'sid', 'valor_match': '9900054',
        'titulo_jg':     'Payload DNS excessivamente grande (possível tunelamento)',
        'resumo_jg':     'Pacote UDP/DNS com mais de 150 bytes — consultas DNS legítimas raramente ultrapassam 60 bytes',
        'categoria_jg':  'dns', 'severidade_jg': 'alto',
        'tags_jg':       ['dns-tunneling', 'exfil', 'evasion'],
        'recomendacoes': ['Capturar e analisar o conteúdo das queries DNS do host', 'Verificar se o domínio destino é suspeito', 'Bloquear DNS externo e forçar uso do resolver interno', 'Investigar processo responsável pelo tráfego DNS'],
    },
    {
        'nome_interno':  'MS_DNS_TUNNEL_LABEL',
        'tipo_match':    'sid', 'valor_match': '9900055',
        'titulo_jg':     'Label DNS muito longo (possível tunelamento / DGA)',
        'resumo_jg':     'Subdomínio com 50+ caracteres na query — padrão de tunelamento DNS para exfiltração de dados',
        'categoria_jg':  'dns', 'severidade_jg': 'alto',
        'tags_jg':       ['dns-tunneling', 'exfil', 'dga'],
        'recomendacoes': ['Analisar os domínios completos consultados pelo host', 'Verificar se dados estão sendo codificados em subdomínios', 'Considerar bloqueio de subdomínios muito longos no DNS resolver', 'Isolar o dispositivo se confirmado'],
    },

    # ── Grupo J — Host Sweep (9900056–9900058) ────────────────────────────────
    {
        'nome_interno':  'MS_LATERAL_HOST_SWEEP_AGRESSIVO',
        'tipo_match':    'sid', 'valor_match': '9900056',
        'titulo_jg':     'Varredura interna agressiva (host sweep rápido)',
        'resumo_jg':     '50 SYNs em 10 segundos para destinos internos — atividade agressiva de reconhecimento',
        'categoria_jg':  'lateral', 'severidade_jg': 'critico',
        'tags_jg':       ['sweep', 'lateral', 'recon', 'interno'],
        'recomendacoes': ['Isolar o host de origem imediatamente', 'Verificar se há worm ou malware propagando na rede', 'Analisar processos ativos no host de origem', 'Revisar logs de autenticação dos hosts destino'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_HOST_SWEEP_AGRESSIVO',
        'tipo_match':    'sid', 'valor_match': '9900057',
        'titulo_jg':     'Host sweep externo agressivo',
        'resumo_jg':     'Origem externa enviando 30+ SYNs em 10 segundos — varredura agressiva de hosts internos',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['sweep', 'recon', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no firewall imediatamente', 'Verificar serviços expostos varridos', 'Verificar se houve acesso bem-sucedido após o scan'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_PING_SWEEP_AGRESSIVO',
        'tipo_match':    'sid', 'valor_match': '9900058',
        'titulo_jg':     'Ping sweep externo agressivo',
        'resumo_jg':     'Origem externa enviando 15+ pings em 10 segundos — mapeamento de hosts ativos',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['icmp', 'sweep', 'recon', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no firewall', 'Bloquear ICMP externo se não necessário'],
    },

    # ── Grupo A2 — Recon Externo (9900061–9900068) ────────────────────────────
    {
        'nome_interno':  'MS_RECON_EXT_PORT_SCAN_SYN',
        'tipo_match':    'sid', 'valor_match': '9900061',
        'titulo_jg':     'Port scan SYN de origem externa',
        'resumo_jg':     'Origem externa mapeando portas da rede interna — reconhecimento ativo',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['scan', 'recon', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no firewall', 'Verificar serviços expostos', 'Monitorar por tentativas de exploração subsequentes'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_PING_SWEEP',
        'tipo_match':    'sid', 'valor_match': '9900062',
        'titulo_jg':     'Ping sweep ICMP de origem externa',
        'resumo_jg':     'Origem externa enviando ICMP para múltiplos hosts — mapeamento de hosts ativos',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['icmp', 'sweep', 'recon', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem', 'Considerar bloquear ICMP externo no firewall'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_HOST_SWEEP_TCP',
        'tipo_match':    'sid', 'valor_match': '9900063',
        'titulo_jg':     'Host sweep TCP de origem externa',
        'resumo_jg':     'Origem externa conectando TCP em múltiplos hosts internos — reconhecimento agressivo',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['sweep', 'recon', 'tcp', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no firewall', 'Revisar exposição de serviços'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_SNMP_SCAN',
        'tipo_match':    'sid', 'valor_match': '9900064',
        'titulo_jg':     'Varredura SNMP de origem externa',
        'resumo_jg':     'Consultas SNMP externas — tentativa de coleta de topologia de rede',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['snmp', 'recon', 'inbound'],
        'recomendacoes': ['Bloquear porta SNMP (UDP/161) no firewall perimetral', 'SNMP nunca deve ser exposto externamente'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_WEB_PANEL_SCAN',
        'tipo_match':    'sid', 'valor_match': '9900065',
        'titulo_jg':     'Varredura de painéis web admin de origem externa',
        'resumo_jg':     'Origem externa varrendo portas web (80/443/8080/8443) — busca de painéis de administração',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['scan', 'web', 'admin-panel', 'inbound'],
        'recomendacoes': ['Bloquear origem no WAF/firewall', 'Revisar quais painéis estão expostos externamente', 'Adicionar autenticação forte nos painéis expostos'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_SUSPEITO_PORTS',
        'tipo_match':    'sid', 'valor_match': '9900066',
        'titulo_jg':     'Conexão externa para porta suspeita (backdoor/C2)',
        'resumo_jg':     'Origem externa tentando conectar em portas 1337/4444/12345/31337 — portas de backdoor',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['fingerprint', 'c2-ports', 'inbound'],
        'recomendacoes': ['Bloquear imediatamente no firewall', 'Verificar se há serviço escutando nessas portas internamente'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_NMAP_NULL',
        'tipo_match':    'sid', 'valor_match': '9900067',
        'titulo_jg':     'Nmap NULL scan de origem externa',
        'resumo_jg':     'Pacote TCP sem flags de origem externa — técnica de fingerprint do Nmap para evadir firewalls',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['nmap', 'scan', 'fingerprint', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no firewall', 'Verificar se firewall perimetral está bloqueando flags TCP inválidas'],
    },
    {
        'nome_interno':  'MS_RECON_EXT_NMAP_XMAS',
        'tipo_match':    'sid', 'valor_match': '9900068',
        'titulo_jg':     'Nmap XMAS scan de origem externa',
        'resumo_jg':     'Pacote TCP FIN+PSH+URG de origem externa — técnica de evasão do Nmap',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['nmap', 'scan', 'xmas', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no firewall', 'Verificar se firewall perimetral filtra flags TCP anômalas'],
    },

    # ── Grupo B2 — Brute Force Externo (9900069–9900076) ─────────────────────
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_SSH',
        'tipo_match':    'sid', 'valor_match': '9900069',
        'titulo_jg':     'Brute force SSH de origem externa',
        'resumo_jg':     'Múltiplas tentativas de autenticação SSH vindo de IP externo',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'ssh', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no firewall perimetral', 'Habilitar fail2ban', 'Restringir SSH por IP de origem ou usar VPN', 'Verificar se algum login foi bem-sucedido'],
    },
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_RDP',
        'tipo_match':    'sid', 'valor_match': '9900070',
        'titulo_jg':     'Brute force RDP de origem externa',
        'resumo_jg':     'Múltiplas tentativas de login RDP vindo de IP externo — RDP nunca deve ser exposto diretamente',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'rdp', 'windows', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem', 'Fechar RDP para internet — usar VPN', 'Habilitar NLA no RDP', 'Verificar logs de acesso Windows'],
    },
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_FTP',
        'tipo_match':    'sid', 'valor_match': '9900071',
        'titulo_jg':     'Brute force FTP de origem externa',
        'resumo_jg':     'Tentativas repetidas de login FTP vindo de IP externo',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'ftp', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem', 'Desabilitar FTP e migrar para SFTP', 'Restringir FTP por IP de origem'],
    },
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_SMB',
        'tipo_match':    'sid', 'valor_match': '9900072',
        'titulo_jg':     'Tentativas SMB de origem externa',
        'resumo_jg':     'Conexões SMB (porta 445) vindas de IP externo — SMB nunca deve estar exposto na internet',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['smb', 'inbound', 'exploit'],
        'recomendacoes': ['Bloquear porta 445 no firewall perimetral imediatamente', 'SMB exposto é vetor de EternalBlue/WannaCry', 'Verificar se houve acesso bem-sucedido'],
    },
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_TELNET',
        'tipo_match':    'sid', 'valor_match': '9900073',
        'titulo_jg':     'Brute force Telnet de origem externa',
        'resumo_jg':     'Tentativas de login Telnet vindo de IP externo — protocolo inseguro e obsoleto',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'telnet', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem', 'Desabilitar Telnet globalmente', 'Substituir por SSH'],
    },
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_WINRM',
        'tipo_match':    'sid', 'valor_match': '9900074',
        'titulo_jg':     'Brute force WinRM de origem externa',
        'resumo_jg':     'Tentativas de login no Windows Remote Management vindas de IP externo',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'winrm', 'windows', 'inbound'],
        'recomendacoes': ['Bloquear porta 5985/5986 no firewall perimetral', 'Restringir WinRM por IP', 'Usar VPN para administração remota'],
    },
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_WEB',
        'tipo_match':    'sid', 'valor_match': '9900075',
        'titulo_jg':     'Brute force em painel web de origem externa',
        'resumo_jg':     'Múltiplas requisições HTTP externas — força bruta em formulário de login',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'web', 'inbound'],
        'recomendacoes': ['Bloquear IP no WAF', 'Ativar CAPTCHA', 'Habilitar 2FA', 'Implementar rate limiting no login'],
    },
    {
        'nome_interno':  'MS_AUTH_EXT_BRUTE_DB',
        'tipo_match':    'sid', 'valor_match': '9900076',
        'titulo_jg':     'Tentativas em banco de dados de origem externa',
        'resumo_jg':     'Conexões externas em portas de banco de dados (MSSQL/MySQL/PostgreSQL/MongoDB/Redis)',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'database', 'inbound'],
        'recomendacoes': ['Bloquear portas de BD no firewall perimetral imediatamente', 'Bancos de dados nunca devem estar expostos diretamente na internet', 'Verificar se houve acesso bem-sucedido'],
    },

    # ── Grupo K — Exploits / Vulnerabilidades (9900077–9900086) ──────────────
    {
        'nome_interno':  'MS_EXPLOIT_ETERNALBLUE',
        'tipo_match':    'sid', 'valor_match': '9900077',
        'titulo_jg':     'Possível exploit EternalBlue/SMB detectado',
        'resumo_jg':     'Padrão de payload SMB compatível com EternalBlue (CVE-2017-0144) — vetor do WannaCry/NotPetya',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['exploit', 'eternalblue', 'smb', 'inbound'],
        'recomendacoes': ['Isolar o host alvo imediatamente', 'Aplicar patch MS17-010 urgente', 'Bloquear porta 445 externamente', 'Verificar comprometimento do host'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_SQLI',
        'tipo_match':    'sid', 'valor_match': '9900078',
        'titulo_jg':     'Possível SQL Injection via HTTP',
        'resumo_jg':     'URI com padrões de SQL Injection (UNION SELECT, DROP TABLE, etc.) detectada',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['sqli', 'web', 'exploit', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no WAF', 'Verificar logs de banco de dados por queries maliciosas', 'Auditar código da aplicação web', 'Implementar WAF com regras anti-SQLi'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_XSS',
        'tipo_match':    'sid', 'valor_match': '9900079',
        'titulo_jg':     'Possível XSS (Cross-Site Scripting) via HTTP',
        'resumo_jg':     'URI com tag <script> detectada — tentativa de injeção de JavaScript',
        'categoria_jg':  'malware', 'severidade_jg': 'alto',
        'tags_jg':       ['xss', 'web', 'exploit', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no WAF', 'Implementar Content Security Policy (CSP)', 'Auditar sanitização de input na aplicação'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_PATH_TRAVERSAL',
        'tipo_match':    'sid', 'valor_match': '9900080',
        'titulo_jg':     'Possível Path Traversal via HTTP',
        'resumo_jg':     'URI com "../" detectada — tentativa de acessar arquivos fora do webroot',
        'categoria_jg':  'malware', 'severidade_jg': 'alto',
        'tags_jg':       ['path-traversal', 'web', 'exploit', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no WAF', 'Verificar se arquivos sensíveis foram acessados nos logs', 'Sanitizar paths na aplicação web'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_CMDI',
        'tipo_match':    'sid', 'valor_match': '9900081',
        'titulo_jg':     'Possível Command Injection via HTTP (whoami)',
        'resumo_jg':     'URI contendo "whoami" — tentativa clássica de injeção de comandos do sistema',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['cmdi', 'web', 'exploit', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem no WAF imediatamente', 'Verificar logs de sistema por execução de comandos', 'Auditar validação de parâmetros na aplicação'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_SSH_EXT',
        'tipo_match':    'sid', 'valor_match': '9900082',
        'titulo_jg':     'Conexão SSH estabelecida de IP externo',
        'resumo_jg':     'Conexão SSH bem-estabelecida de origem externa — verificar se é acesso legítimo',
        'categoria_jg':  'auth', 'severidade_jg': 'alto',
        'tags_jg':       ['ssh', 'inbound', 'external-access'],
        'recomendacoes': ['Verificar se o acesso é de usuário/IP autorizado', 'Auditar comandos executados na sessão', 'Considerar restringir SSH por IP de origem'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_RDP_EXT',
        'tipo_match':    'sid', 'valor_match': '9900083',
        'titulo_jg':     'Conexão RDP estabelecida de origem externa',
        'resumo_jg':     'Conexão RDP de IP externo estabelecida — RDP não deve estar exposto diretamente',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['rdp', 'inbound', 'windows', 'external-access'],
        'recomendacoes': ['Verificar imediatamente se o acesso é legítimo', 'Fechar RDP para internet e usar VPN', 'Auditar atividade do usuário conectado'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_DNS_AMPLIFICATION',
        'tipo_match':    'sid', 'valor_match': '9900084',
        'titulo_jg':     'Possível amplificação DNS de origem externa',
        'resumo_jg':     'Volume alto de consultas DNS externas — possível abuso para amplificação DDoS',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['dns-amplification', 'ddos', 'inbound'],
        'recomendacoes': ['Verificar se servidor DNS é open resolver', 'Bloquear consultas DNS recursivas externas', 'Implementar rate limiting no DNS'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_SYN_FIN_EXT',
        'tipo_match':    'sid', 'valor_match': '9900085',
        'titulo_jg':     'Flag TCP SYN+FIN externa (probe/fingerprint)',
        'resumo_jg':     'Combinação SYN+FIN inválida de origem externa — técnica de fingerprint do Nmap para mapear firewall',
        'categoria_jg':  'recon', 'severidade_jg': 'critico',
        'tags_jg':       ['nmap', 'fingerprint', 'inbound'],
        'recomendacoes': ['Bloquear IP de origem', 'Verificar se firewall está descartando flags TCP inválidas'],
    },
    {
        'nome_interno':  'MS_EXPLOIT_EXPOSED_SERVICE',
        'tipo_match':    'sid', 'valor_match': '9900086',
        'titulo_jg':     'Tentativa de acesso a serviço exposto (Redis/MongoDB/Elasticsearch/Docker)',
        'resumo_jg':     'Conexão externa para Redis/MongoDB/ES/Docker — serviços críticos sem autenticação expostos',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['exposed-service', 'redis', 'mongodb', 'docker', 'inbound'],
        'recomendacoes': ['Bloquear portas no firewall perimetral IMEDIATAMENTE', 'Esses serviços não devem estar expostos na internet', 'Verificar se houve acesso ou exfiltração de dados'],
    },

    # ── Grupo L — Exfiltração / C2 Externo (9900091–9900098) ─────────────────
    {
        'nome_interno':  'MS_EXFIL_VOLUME_ALTO',
        'tipo_match':    'sid', 'valor_match': '9900091',
        'titulo_jg':     'Volume alto de dados saindo (possível exfiltração)',
        'resumo_jg':     'Dispositivo estabelecendo muitas conexões externas — possível exfiltração de dados em massa',
        'categoria_jg':  'exfil', 'severidade_jg': 'alto',
        'tags_jg':       ['exfil', 'anomalia'],
        'recomendacoes': ['Identificar o processo responsável pelas conexões', 'Verificar o volume de dados transferidos', 'Isolar o dispositivo se confirmado'],
    },
    {
        'nome_interno':  'MS_EXFIL_HTTP_POST',
        'tipo_match':    'sid', 'valor_match': '9900092',
        'titulo_jg':     'Requisição POST HTTP saindo (possível exfiltração)',
        'resumo_jg':     'Método POST saindo para destino externo — pode estar enviando dados para servidor C2',
        'categoria_jg':  'exfil', 'severidade_jg': 'medio',
        'tags_jg':       ['exfil', 'http', 'post'],
        'recomendacoes': ['Verificar o destino e o conteúdo da requisição POST', 'Correlacionar com outros alertas do mesmo IP', 'Monitorar padrão de envio (periódico = beaconing)'],
    },
    {
        'nome_interno':  'MS_C2_TOR_ONION_DNS',
        'tipo_match':    'sid', 'valor_match': '9900093',
        'titulo_jg':     'Consulta DNS para domínio .onion (Tor)',
        'resumo_jg':     'Resolução de domínio .onion via DNS — dispositivo tentando se comunicar pela rede Tor',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['tor', 'c2', 'dns', 'malware'],
        'recomendacoes': ['Isolar dispositivo imediatamente', 'Bloquear .onion no DNS resolver', 'Investigar processo responsável', 'Verificar presença de malware'],
    },
    {
        'nome_interno':  'MS_C2_PORTAS_CONHECIDAS',
        'tipo_match':    'sid', 'valor_match': '9900094',
        'titulo_jg':     'Conexão para porta C2 comum (saída)',
        'resumo_jg':     'Dispositivo interno conectando em portas 4444/5555/8888/9999/6666 — portas frequentes em C2',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['c2', 'malware', 'outbound'],
        'recomendacoes': ['Isolar dispositivo imediatamente', 'Verificar processos em execução', 'Identificar o destino da conexão', 'Fazer scan completo de malware'],
    },
    {
        'nome_interno':  'MS_C2_UA_SQLMAP',
        'tipo_match':    'sid', 'valor_match': '9900095',
        'titulo_jg':     'User-Agent sqlmap detectado (ferramenta de ataque)',
        'resumo_jg':     'Requisição HTTP com User-Agent "sqlmap" — ferramenta de SQL injection sendo usada',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['attack-tool', 'sqlmap', 'sqli'],
        'recomendacoes': ['Identificar se a origem é interna (comprometimento) ou externa', 'Bloquear no WAF', 'Verificar logs de banco de dados por queries suspeitas'],
    },
    {
        'nome_interno':  'MS_C2_UA_NIKTO',
        'tipo_match':    'sid', 'valor_match': '9900097',
        'titulo_jg':     'User-Agent Nikto detectado (scanner de vulnerabilidades)',
        'resumo_jg':     'Requisição HTTP com User-Agent "Nikto" — scanner de vulnerabilidades web em uso',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['attack-tool', 'nikto', 'scanner'],
        'recomendacoes': ['Identificar se é scan autorizado', 'Bloquear no WAF se não autorizado', 'Verificar o alvo do scan'],
    },
    {
        'nome_interno':  'MS_C2_UA_MASSCAN',
        'tipo_match':    'sid', 'valor_match': '9900098',
        'titulo_jg':     'User-Agent masscan detectado (scanner de portas)',
        'resumo_jg':     'Requisição HTTP com User-Agent "masscan" — scanner de portas de alta velocidade em uso',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['attack-tool', 'masscan', 'scanner'],
        'recomendacoes': ['Identificar se é scan autorizado de segurança', 'Bloquear no WAF/firewall se não autorizado'],
    },

    # ── ET Open — Regras por regex ────────────────────────────────────────────
    {
        'nome_interno':  'ET_BRUTE_SSH',
        'tipo_match':    'regex', 'valor_match': r'ET BRUTE.FORCE SSH',
        'titulo_jg':     'Força Bruta SSH Detectada',
        'resumo_jg':     'Múltiplas tentativas de login SSH em sequência — ataque de dicionário ou força bruta em andamento.',
        'categoria_jg':  'auth', 'severidade_jg': 'critico',
        'tags_jg':       ['brute-force', 'ssh', 'credenciais'],
        'recomendacoes': ['Bloqueie o IP de origem no firewall', 'Ative fail2ban', 'Desabilite login por senha no SSH', 'Mova SSH para porta não padrão'],
    },
    {
        'nome_interno':  'ET_SCAN_NMAP',
        'tipo_match':    'regex', 'valor_match': r'ET SCAN.*(Nmap|nmap)',
        'titulo_jg':     'Varredura Nmap Detectada',
        'resumo_jg':     'Ferramenta de reconhecimento Nmap identificada — mapeamento ativo de portas e serviços na rede.',
        'categoria_jg':  'recon', 'severidade_jg': 'alto',
        'tags_jg':       ['nmap', 'scan', 'reconhecimento'],
        'recomendacoes': ['Bloqueie o IP de origem', 'Verifique se é scanner autorizado', 'Revise regras de firewall'],
    },
    {
        'nome_interno':  'ET_MALWARE_TLS_C2',
        'tipo_match':    'regex', 'valor_match': r'ET MALWARE.*(TLS|tls).*(C2|Beacon|beacon)',
        'titulo_jg':     'Comunicação C2 via TLS Detectada',
        'resumo_jg':     'Tráfego TLS com padrão de beaconing — dispositivo possivelmente infectado comunicando com servidor de controle.',
        'categoria_jg':  'malware', 'severidade_jg': 'critico',
        'tags_jg':       ['c2', 'beaconing', 'malware', 'tls'],
        'recomendacoes': ['Isole o dispositivo imediatamente', 'Execute scan antivírus completo', 'Analise processos em execução', 'Preserve evidências antes de remediar'],
    },
    {
        'nome_interno':  'ET_DNS_TUNNELING',
        'tipo_match':    'regex', 'valor_match': r'ET DNS.*(Tunnel|tunnel|Tuneling)',
        'titulo_jg':     'Tunelamento DNS Suspeito',
        'resumo_jg':     'Padrão de exfiltração de dados via DNS detectado — subdomínios codificados sendo usados para transmitir dados.',
        'categoria_jg':  'dns', 'severidade_jg': 'alto',
        'tags_jg':       ['dns-tunneling', 'exfiltração'],
        'recomendacoes': ['Bloqueie consultas DNS com subdomínios longos', 'Analise histórico DNS do host', 'Considere DNS filtering mais restritivo'],
    },
    {
        'nome_interno':  'ET_SCAN_GENERIC',
        'tipo_match':    'regex', 'valor_match': r'^ET SCAN',
        'titulo_jg':     'Varredura de Rede Detectada',
        'resumo_jg':     'Atividade de reconhecimento ativo identificada — origem mapeando a rede.',
        'categoria_jg':  'recon', 'severidade_jg': 'medio',
        'tags_jg':       ['scan', 'reconhecimento'],
        'recomendacoes': ['Identifique a origem', 'Bloqueie se externo', 'Verifique se é scanner autorizado'],
    },
    {
        'nome_interno':  'ET_MALWARE_GENERIC',
        'tipo_match':    'regex', 'valor_match': r'^ET MALWARE',
        'titulo_jg':     'Indicador de Malware Detectado',
        'resumo_jg':     'Assinatura de malware identificada pelo IDS — comportamento suspeito na rede.',
        'categoria_jg':  'malware', 'severidade_jg': 'alto',
        'tags_jg':       ['malware'],
        'recomendacoes': ['Investigue o host de origem', 'Execute scan antivírus', 'Verifique processos em execução'],
    },
    {
        'nome_interno':  'ET_BRUTE_GENERIC',
        'tipo_match':    'regex', 'valor_match': r'^ET BRUTE.FORCE',
        'titulo_jg':     'Ataque de Força Bruta Detectado',
        'resumo_jg':     'Múltiplas tentativas de autenticação em sequência — ataque automatizado de credenciais.',
        'categoria_jg':  'auth', 'severidade_jg': 'alto',
        'tags_jg':       ['brute-force', 'credenciais'],
        'recomendacoes': ['Bloqueie o IP de origem', 'Ative bloqueio automático de tentativas repetidas'],
    },
    {
        'nome_interno':  'ET_POLICY_GENERIC',
        'tipo_match':    'regex', 'valor_match': r'^ET POLICY',
        'titulo_jg':     'Violação de Política de Rede',
        'resumo_jg':     'Tráfego não autorizado ou fora da política de uso da rede detectado.',
        'categoria_jg':  'p2p', 'severidade_jg': 'medio',
        'tags_jg':       ['policy'],
        'recomendacoes': ['Identifique o dispositivo', 'Aplique política de uso aceitável'],
    },
    {
        'nome_interno':  'ET_INFO_GENERIC',
        'tipo_match':    'regex', 'valor_match': r'^ET INFO',
        'titulo_jg':     'Informação de Rede Coletada',
        'resumo_jg':     'Evento informativo — atividade de rede registrada sem indicador direto de ameaça.',
        'categoria_jg':  'info', 'severidade_jg': 'informativo',
        'tags_jg':       ['info'],
        'recomendacoes': [],
    },
    {
        'nome_interno':  'SURICATA_GENERIC',
        'tipo_match':    'regex', 'valor_match': r'^SURICATA',
        'titulo_jg':     'Alerta do Motor Suricata',
        'resumo_jg':     'Evento gerado internamente pelo motor Suricata — geralmente protocolo ou parser.',
        'categoria_jg':  'info', 'severidade_jg': 'informativo',
        'tags_jg':       ['suricata', 'interno'],
        'recomendacoes': [],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# GESTÃO DO CACHE
# ─────────────────────────────────────────────────────────────────────────────

def resetar_cache():
    global _cache_regras, _cache_supressoes, _cache_ts
    _cache_regras     = None
    _cache_supressoes = None
    _cache_ts         = 0.0
    logger.debug('Tradutor: cache invalidado')


def _get_regras() -> list:
    global _cache_regras, _cache_ts
    import time
    agora = time.monotonic()

    if _cache_regras is not None and (agora - _cache_ts) < _CACHE_TTL_SEGUNDOS:
        return _cache_regras

    try:
        from ..models import RegraDeMapeamento
        db_regras = list(
            RegraDeMapeamento.objects
            .filter(ativo=True)
            .order_by('prioridade', 'id')
            .values(
                'id', 'nome_interno', 'tipo_match', 'valor_match',
                'titulo_jg', 'resumo_jg', 'categoria_jg', 'severidade_jg',
                'tags_jg', 'recomendacoes', 'prioridade',
            )
        )
    except Exception as e:
        logger.warning(f'Tradutor: falha ao carregar regras do banco: {e}')
        db_regras = []

    nomes_db = {r['nome_interno'] for r in db_regras}
    builtin_extras = [r for r in REGRAS_BUILTIN if r.get('nome_interno') not in nomes_db]

    regras_extras = []
    for b in builtin_extras:
        regras_extras.append({
            'id':            None,
            'nome_interno':  b['nome_interno'],
            'tipo_match':    b['tipo_match'],
            'valor_match':   b['valor_match'],
            'titulo_jg':     b['titulo_jg'],
            'resumo_jg':     b.get('resumo_jg', ''),
            'categoria_jg':  b['categoria_jg'],
            'severidade_jg': b['severidade_jg'],
            'tags_jg':       b.get('tags_jg', []),
            'recomendacoes': b.get('recomendacoes', []),
            'prioridade':    b.get('prioridade', 50),
        })

    _cache_regras = db_regras + regras_extras
    _cache_ts     = agora
    logger.debug(f'Tradutor: {len(db_regras)} regras do banco + {len(regras_extras)} builtin')
    return _cache_regras


def _get_supressoes() -> list:
    global _cache_supressoes, _cache_ts
    import time
    agora = time.monotonic()

    if _cache_supressoes is not None and (agora - _cache_ts) < _CACHE_TTL_SEGUNDOS:
        return _cache_supressoes

    try:
        from django.db.models import Q
        from ..models import Supressao
        agora_dt = timezone.now()
        _cache_supressoes = list(
            Supressao.objects
            .filter(ativo=True)
            .filter(Q(expira_em__isnull=True) | Q(expira_em__gt=agora_dt))
            .values('tipo', 'valor', 'escopo', 'sensor_id')
        )
    except Exception as e:
        logger.warning(f'Tradutor: falha ao carregar supressões: {e}')
        _cache_supressoes = []

    return _cache_supressoes


# ─────────────────────────────────────────────────────────────────────────────
# VERIFICAÇÃO DE SUPRESSÃO
# ─────────────────────────────────────────────────────────────────────────────

def esta_suprimido(evento: dict, sensor_id: int | None = None) -> bool:
    try:
        supressoes = _get_supressoes()
        if not supressoes:
            return False

        sid       = str(evento.get('sid', ''))
        signature = evento.get('signature', '').lower()
        src_ip    = evento.get('src_ip', '')
        dest_ip   = evento.get('dest_ip', '') or ''
        categoria = (evento.get('categoria', '') or '').lower()
        classtype = (evento.get('classtype', '') or '').lower()

        raw     = evento.get('raw_json', evento)
        dominio = (
            raw.get('dns', {}).get('rrname', '')
            or raw.get('tls', {}).get('sni', '')
            or raw.get('http', {}).get('hostname', '')
        ).lower()

        for sup in supressoes:
            if sup['escopo'] == 'sensor' and sup['sensor_id'] != sensor_id:
                continue

            tipo  = sup['tipo']
            valor = sup['valor'].lower()

            if tipo == 'sid'       and sid == valor:            return True
            if tipo == 'signature' and valor in signature:      return True
            if tipo == 'ip_src'    and src_ip == sup['valor']:  return True
            if tipo == 'ip_dst'    and dest_ip == sup['valor']: return True
            if tipo == 'dominio'   and valor in dominio:        return True
            if tipo == 'categoria' and valor == categoria:      return True
            if tipo == 'classtype' and valor == classtype:      return True

    except Exception as e:
        logger.debug(f'Tradutor: erro na verificação de supressão: {e}')

    return False


# ─────────────────────────────────────────────────────────────────────────────
# MOTOR DE TRADUÇÃO
# ─────────────────────────────────────────────────────────────────────────────

def traduzir(evento: dict, sensor_id: int | None = None) -> dict:
    if esta_suprimido(evento, sensor_id):
        return _montar_saida('', '', 'info', 'informativo', suprimido=True)

    regra = _encontrar_regra(evento)

    if regra:
        return _montar_saida(
            titulo    = regra['titulo_jg'],
            resumo    = regra.get('resumo_jg', ''),
            categoria = regra['categoria_jg'],
            severidade= regra['severidade_jg'],
            tags      = regra.get('tags_jg') or [],
            recomend  = regra.get('recomendacoes') or [],
            regra_id  = regra.get('id'),
        )

    return _fallback(evento)


def _encontrar_regra(evento: dict) -> Optional[dict]:
    regras = _get_regras()
    if not regras:
        return None

    sid       = str(evento.get('sid', '')).strip()
    signature = (evento.get('signature', '') or '').strip()
    sig_lower = signature.lower()
    classtype = (evento.get('classtype', '') or '').lower().strip()
    categoria = (evento.get('categoria', '') or '').lower().strip()

    por_tipo: dict = {t: [] for t in ('sid', 'signature', 'regex', 'classtype', 'categoria', 'fallback')}
    for r in regras:
        tipo = r.get('tipo_match', 'fallback')
        por_tipo.setdefault(tipo, []).append(r)

    if sid:
        for r in por_tipo['sid']:
            if r['valor_match'].strip() == sid:
                return r

    if signature:
        for r in por_tipo['signature']:
            if r['valor_match'].strip().lower() == sig_lower:
                return r

    if signature:
        for r in por_tipo['regex']:
            try:
                if re.search(r['valor_match'], signature, re.IGNORECASE):
                    return r
            except re.error:
                logger.warning(f"Regex inválida na regra {r.get('nome_interno')}: {r['valor_match']}")

    if classtype:
        for r in por_tipo['classtype']:
            if r['valor_match'].strip().lower() == classtype:
                return r

    if categoria:
        for r in por_tipo['categoria']:
            if r['valor_match'].strip().lower() == categoria:
                return r

    for r in por_tipo['fallback']:
        return r

    return None


def _fallback(evento: dict) -> dict:
    classtype = (evento.get('classtype', '') or '').lower().strip()
    categoria = (evento.get('categoria', '') or '').lower().strip()

    if classtype and classtype in _FALLBACK_CLASSTYPE:
        titulo, cat_jg, sev_jg = _FALLBACK_CLASSTYPE[classtype]
        return _montar_saida(titulo, '', cat_jg, sev_jg)

    for chave, (titulo, cat_jg, sev_jg) in _FALLBACK_CATEGORIA_SURICATA.items():
        if chave in categoria:
            return _montar_saida(titulo, '', cat_jg, sev_jg)

    event_type = (evento.get('event_type', '') or '').lower()
    if event_type == 'dns':
        return _montar_saida('Atividade DNS registrada',   '', 'dns', 'informativo')
    if event_type == 'http':
        return _montar_saida('Requisição HTTP registrada', '', 'web', 'informativo')
    if event_type == 'tls':
        return _montar_saida('Conexão TLS registrada',     '', 'tls', 'informativo')

    titulo, cat_jg, sev_jg = _FALLBACK_PADRAO
    return _montar_saida(titulo, '', cat_jg, sev_jg)


def _montar_saida(
    titulo:     str,
    resumo:     str,
    categoria:  str,
    severidade: str,
    tags:       list = None,
    recomend:   list = None,
    regra_id          = None,
    suprimido:  bool  = False,
) -> dict:
    return {
        'titulo_jg':     titulo,
        'resumo_jg':     resumo,
        'categoria_jg':  categoria,
        'severidade_jg': severidade,
        'tags_jg':       tags or [],
        'recomendacoes': recomend or [],
        'regra_id':      regra_id,
        'suprimido':     suprimido,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SEED DE REGRAS NO BANCO
# ─────────────────────────────────────────────────────────────────────────────

def popular_regras_builtin(sobrescrever: bool = False) -> dict:
    """
    Insere as regras builtin no banco caso ainda não existam.
    Se sobrescrever=True, atualiza as existentes.

    Uso:
        python gerenciar.py shell -c "from incidentes.services.tradutor import popular_regras_builtin; popular_regras_builtin()"
    """
    from ..models import RegraDeMapeamento

    criadas     = 0
    atualizadas = 0

    for b in REGRAS_BUILTIN:
        nome     = b['nome_interno']
        defaults = {
            'tipo_match':    b['tipo_match'],
            'valor_match':   b['valor_match'],
            'titulo_jg':     b['titulo_jg'],
            'resumo_jg':     b.get('resumo_jg', ''),
            'categoria_jg':  b['categoria_jg'],
            'severidade_jg': b['severidade_jg'],
            'tags_jg':       b.get('tags_jg', []),
            'recomendacoes': b.get('recomendacoes', []),
            'prioridade':    b.get('prioridade', 50),
            'ativo':         True,
            'versao':        '1.0',
        }

        if sobrescrever:
            obj, created = RegraDeMapeamento.objects.update_or_create(
                nome_interno=nome, defaults=defaults,
            )
            if created: criadas     += 1
            else:       atualizadas += 1
        else:
            _, created = RegraDeMapeamento.objects.get_or_create(
                nome_interno=nome, defaults=defaults,
            )
            if created:
                criadas += 1

    resetar_cache()
    return {'criadas': criadas, 'atualizadas': atualizadas, 'total': len(REGRAS_BUILTIN)}