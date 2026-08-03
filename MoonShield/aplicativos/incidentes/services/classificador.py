# =============================================================================
# incidentes/services/classificador.py  v2
#
# Fix v2:
#   ✓ Score agora usa categoria_jg (confiável) em vez de sig.cat (string longa
#     do Suricata que nunca batia nos dicts de score → tudo virava _default=30)
#   ✓ Fallback para sig.cat com normalização de strings Suricata reais
#     ("A Network Trojan was detected" → "trojan")
#   ✓ Severidade usa severidade_jg quando disponível
#   ✓ _gerar_group_key usa campos tecnico{} E sig{} para compatibilidade
# =============================================================================

import hashlib
from django.utils import timezone


# ─── PRESETS ──────────────────────────────────────────────────────────────────

PRESETS = {
    "casa": {
        "nome":               "Casa",
        "incidente_minimo":   75,
        "evento_minimo":      45,
        "janela_dedupe_min":  10,
        "forcar_telemetria": [
            "ET INFO Spotify P2P Client",
            "ET INFO Session Traversal Utilities for NAT",
            "ET INFO Observed Google DNS over HTTPS Domain",
            "ET INFO External IP Lookup",
            "ET INFO Observed DNS Query",
            "SURICATA ICMPv4 invalid checksum",
            "SURICATA Applayer Detect protocol only one direction",
            "SURICATA STREAM reassembly overlap",
            "ET INFO STUN Binding",
        ],
        "penalidade_broadcast": -10,
        "bonus_host_conhecido": -15,
    },
    "empresa": {
        "nome":               "Empresa",
        "incidente_minimo":   70,
        "evento_minimo":      40,
        "janela_dedupe_min":  10,
        "forcar_telemetria": [
            "ET INFO Spotify P2P Client",
            "ET INFO Session Traversal Utilities for NAT",
        ],
        "penalidade_broadcast": -8,
        "bonus_host_conhecido": -10,
    },
    "lab": {
        "nome":               "Laboratório",
        "incidente_minimo":   65,
        "evento_minimo":      20,
        "janela_dedupe_min":  5,
        "forcar_telemetria": [],
        "penalidade_broadcast": -5,
        "bonus_host_conhecido": -5,
    },
}

PRESET_PADRAO = "casa"


# ─── SCORE BASE POR CATEGORIA MS ──────────────────────────────────────────────

_SCORE_CATEGORIA_MS = {
    "malware":   85,
    "auth":      65,
    "lateral":   72,
    "exfil":     80,
    "recon":     52,
    "web":       55,
    "tls":       30,
    "dns":       25,
    "p2p":       20,
    "anomalia":  50,
    "info":      25,
    "_default":  30,
}

# ─── SCORE BASE POR CATEGORIA SURICATA (fallback) ─────────────────────────────

_SCORE_CATEGORIA_SURICATA = {
    "malware":                   85,
    "trojan":                    85,
    "ransomware":                90,
    "exploit":                   80,
    "exploit-kit":               80,
    "shellcode":                 75,
    "command-and-control":       80,
    "botnet":                    82,
    "backdoor":                  78,
    "lateral-movement":          75,
    "web-application-attack":    65,
    "attempted-admin":           65,
    "attempted-user":            60,
    "attempted-recon":           55,
    "recon":                     55,
    "scan":                      52,
    "policy-violation":          45,
    "policy":                    40,
    "suspicious":                50,
    "misc-attack":               50,
    "not-suspicious":            15,
    "info":                      15,
    "informational":             15,
    "protocol-command-decode":   20,
    "misc-activity":             25,
    "network-events":            20,
    "network trojan":            85,
    "attempted user":            60,
    "attempted admin":           65,
    "denial of service":         70,
    "web application":           60,
    "credential":                65,
    "brute":                     60,
    "_default":                  30,
}

_PALAVRAS_ALTO_RISCO = [
    "exploit", "malware", "backdoor", "ransomware", "c2",
    "brute force", "sql injection", "rce", "log4", "shellcode",
    "trojan", "botnet", "cobalt", "mimikatz", "metasploit",
    "credential", "lateral", "exfil", "command and control",
]
_PALAVRAS_BAIXO_RISCO = [
    "spotify", "stun", "doh", "mdns", "ssdp", "upnp",
    "dns over https", "broadcast", "telemetry", "windows update",
    "p2p", "ntp", "icmpv4 invalid", "stream reassembly",
    "applayer detect", "et info",
]

_PORTAS_NORMAIS = {80, 443, 53, 123, 67, 68, 5353}

_AJUSTE_SEV_MS = {
    "critico":     25,
    "alto":        15,
    "medio":        5,
    "baixo":        0,
    "informativo":  0,
}


# ─── FUNÇÃO PRINCIPAL ─────────────────────────────────────────────────────────

def classificar_evento(evento: dict, preset_nome: str = None) -> dict:
    preset = _get_preset(preset_nome)

    tec        = evento.get("tecnico") or {}
    sig        = evento.get("sig")    or {}

    sig_nome   = (tec.get("signature") or sig.get("name") or
                  evento.get("titulo_jg") or "")

    # Categoria: MS first, fallback Suricata
    cat_ms     = evento.get("categoria_jg", "") or ""
    cat_suri   = (tec.get("categoria") or sig.get("cat") or "").lower().strip()

    # Severidade: MS first, fallback Suricata
    sev_ms     = evento.get("severidade_jg", "") or ""
    sev_suri   = (evento.get("sev") or tec.get("severidade") or sig.get("sev") or "medio")

    dest_porta = int(tec.get("dest_porta") or sig.get("port") or 0)
    direction  = evento.get("direction") or tec.get("direction") or "unknown"
    dest_ip    = evento.get("dstIp") or tec.get("dest_ip") or ""
    acao       = (tec.get("acao") or sig.get("action") or "alert").lower()

    # ── 1. Forçar telemetria por assinatura ───────────────────────────────────
    if _e_forcado_telemetria(sig_nome, preset):
        evento["score_evento"]  = 25
        evento["classificacao"] = "telemetria"
        evento["group_key"]     = _gerar_group_key(evento)
        return evento

    # ── 2. Score base ─────────────────────────────────────────────────────────
    if cat_ms and cat_ms in _SCORE_CATEGORIA_MS:
        score = _SCORE_CATEGORIA_MS[cat_ms]
    else:
        score = _score_por_categoria_suricata(cat_suri)

    # ── 3. Ajuste por severidade MS ───────────────────────────────────────────
    if sev_ms in _AJUSTE_SEV_MS:
        score += _AJUSTE_SEV_MS[sev_ms]
    else:
        score += _ajuste_severidade_suri(sev_suri)

    # ── 4. Palavras-chave no nome da assinatura ───────────────────────────────
    sig_lower = sig_nome.lower()
    for palavra in _PALAVRAS_ALTO_RISCO:
        if palavra in sig_lower:
            score += 12
            break
    for palavra in _PALAVRAS_BAIXO_RISCO:
        if palavra in sig_lower:
            score -= 10
            break

    # ── 5. Direção ────────────────────────────────────────────────────────────
    score += {"inbound": 10, "lateral": 5, "outbound": 3}.get(direction, 0)

    # ── 6. Broadcast ──────────────────────────────────────────────────────────
    if _e_broadcast(dest_ip):
        score += preset["penalidade_broadcast"]

    # ── 7. Porta estranha ─────────────────────────────────────────────────────
    if dest_porta and dest_porta not in _PORTAS_NORMAIS and score < 40:
        score += 5

    # ── 8. Ação drop/reject ───────────────────────────────────────────────────
    if acao in ("drop", "reject"):
        score += 20

    # ── 9. Clamp ──────────────────────────────────────────────────────────────
    score = max(0, min(100, score))

    evento["score_evento"]  = score
    evento["classificacao"] = _classificar(score, preset)
    evento["group_key"]     = _gerar_group_key(evento)
    return evento


def classificar_lista(eventos: list, preset_nome: str = None) -> list:
    preset = _get_preset(preset_nome)
    classificados = [classificar_evento(e, preset_nome) for e in eventos]
    return _agrupar(classificados, preset["janela_dedupe_min"])


def get_preset_ativo() -> str:
    try:
        from configuracoes.models import ConfigSistema
        cfg = ConfigSistema.get_solo()
        preset = getattr(cfg, "active_preset", None)
        if preset and preset in PRESETS:
            return preset
    except Exception:
        pass
    return PRESET_PADRAO


def get_info_preset(preset_nome: str = None) -> dict:
    p = _get_preset(preset_nome)
    return {
        "nome":              p["nome"],
        "incidente_minimo":  p["incidente_minimo"],
        "evento_minimo":     p["evento_minimo"],
        "janela_dedupe_min": p["janela_dedupe_min"],
    }


# ─── AGRUPAMENTO ──────────────────────────────────────────────────────────────

def _agrupar(eventos: list, janela_minutos: int) -> list:
    from django.utils.dateparse import parse_datetime

    eventos_ordenados = sorted(eventos, key=lambda x: x.get("timestamp", ""))
    grupos_ativos  = {}
    resultado_final = []

    for ev in eventos_ordenados:
        key    = ev.get("group_key", "")
        ts_str = ev.get("timestamp", "")
        ts_atual = parse_datetime(ts_str) if ts_str else None

        if not key or not ts_atual:
            ev["group_count"]         = 1
            ev["primeira_ocorrencia"] = ts_str
            resultado_final.append(ev)
            continue

        if key in grupos_ativos:
            grupo    = grupos_ativos[key]
            ts_grupo = parse_datetime(grupo.get("timestamp", ""))

            if ts_grupo:
                try:
                    diff_min = abs((ts_atual - ts_grupo).total_seconds()) / 60.0
                except TypeError:
                    diff_min = janela_minutos + 1

                if diff_min <= janela_minutos:
                    ev["group_count"]         = grupo["group_count"] + 1
                    ev["primeira_ocorrencia"] = grupo["primeira_ocorrencia"]
                    grupos_ativos[key] = ev
                    continue

            resultado_final.append(grupos_ativos[key])

        ev["group_count"]         = 1
        ev["primeira_ocorrencia"] = ts_str
        grupos_ativos[key] = ev

    for grupo in grupos_ativos.values():
        resultado_final.append(grupo)

    resultado_final.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return resultado_final


# ─── AUXILIARES ───────────────────────────────────────────────────────────────

def _get_preset(nome: str = None) -> dict:
    if not nome:
        nome = get_preset_ativo()
    return PRESETS.get(nome, PRESETS[PRESET_PADRAO])


def _score_por_categoria_suricata(categoria: str) -> int:
    if not categoria:
        return _SCORE_CATEGORIA_SURICATA["_default"]
    if categoria in _SCORE_CATEGORIA_SURICATA:
        return _SCORE_CATEGORIA_SURICATA[categoria]
    for chave, score in _SCORE_CATEGORIA_SURICATA.items():
        if chave != "_default" and chave in categoria:
            return score
    return _SCORE_CATEGORIA_SURICATA["_default"]


def _e_forcado_telemetria(sig_nome: str, preset: dict) -> bool:
    sig_lower = sig_nome.lower()
    for sig_forcada in preset.get("forcar_telemetria", []):
        if sig_forcada.lower() in sig_lower:
            return True
    return False


def _e_broadcast(ip: str) -> bool:
    if not ip:
        return False
    return ip.endswith(".255") or ip == "255.255.255.255"


def _ajuste_severidade_suri(sev: str) -> int:
    return {"critico": 10, "alto": 5, "medio": 0, "baixo": -5}.get(sev, 0)


def _classificar(score: int, preset: dict) -> str:
    if score >= preset["incidente_minimo"]:
        return "incidente"
    if score >= preset["evento_minimo"]:
        return "evento"
    return "telemetria"


def _gerar_group_key(evento: dict) -> str:
    tec = evento.get("tecnico") or {}
    sig = evento.get("sig")    or {}

    sig_nome = (tec.get("signature") or sig.get("name") or
                evento.get("titulo_jg") or
                str(tec.get("sid") or sig.get("sid") or evento.get("id") or ""))

    src_ip  = evento.get("srcIp") or ""
    dest_ip = evento.get("dstIp") or tec.get("dest_ip") or ""
    porta   = str(tec.get("dest_porta") or sig.get("port") or "")
    proto   = (tec.get("protocolo") or sig.get("proto") or "")

    if not sig_nome.strip():
        sig_nome = str(evento.get("id") or id(evento))

    raw = f"{sig_nome}|{src_ip}|{dest_ip}|{porta}|{proto}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]