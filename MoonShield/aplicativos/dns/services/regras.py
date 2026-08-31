"""
dns/services/regras.py — MoonShield
─────────────────────────────────────────────────────────────────────────────
Normalização e aplicação segura de regras customizadas do AdGuard Home.

Melhorias:
- aceita domínio, URL ou regra AdGuard completa;
- normaliza domínio sem quebrar regras avançadas;
- variação .com <-> .com.br somente quando faz sentido;
- remove duplicatas preservando ordem;
- resolve conflito direto BLOCK x ALLOW;
- nunca apaga regras não relacionadas.
─────────────────────────────────────────────────────────────────────────────
"""

import logging
import re
from urllib.parse import urlsplit

from .adguard_client import AdGuardClient

logger = logging.getLogger(__name__)

_ADVANCED_PREFIXES = ("||", "@@", "!", "#", "/", "0.0.0.0", "127.")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    result = []

    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)

    return result


def _extrair_dominio(raw: str) -> str:
    """
    Aceita:
      youtube.com
      www.youtube.com
      https://www.youtube.com/watch?v=...
      *.youtube.com

    Retorna hostname normalizado ou "" quando inválido.
    """
    value = (raw or "").strip().lower()
    if not value:
        return ""

    value = value.rstrip(".")
    if value.startswith("*."):
        value = value[2:]

    # Se parecer URL, usa parser. Sem esquema, injeta // para o urlsplit
    # interpretar o primeiro trecho como hostname.
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = (parsed.hostname or "").strip().lower().rstrip(".")
    except Exception:
        return ""

    if host.startswith("www."):
        host = host[4:]

    if not host:
        return ""

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""

    if not _DOMAIN_RE.fullmatch(host):
        return ""

    return host


def _variacoes_dominio(domain: str) -> list[str]:
    """
    Mantém a conveniência usada no MoonShield sem criar variações absurdas.

    youtube.com    -> youtube.com + youtube.com.br
    youtube.com.br -> youtube.com.br + youtube.com

    Para .org, .net, .local etc. não inventa sufixo .br.
    """
    domains = [domain]

    if domain.endswith(".com.br"):
        base = domain[:-3]  # remove apenas ".br": youtube.com.br -> youtube.com
        if base:
            domains.append(base)
    elif domain.endswith(".com"):
        domains.append(domain + ".br")

    return _dedupe_keep_order(domains)


def _regra_para_dominio(domain: str, mode: str) -> str:
    return f"@@||{domain}^" if mode == "allow" else f"||{domain}^"


def _regra_oposta(rule: str) -> str | None:
    """
    Detecta apenas conflito direto entre regras simples:
      ||youtube.com^
      @@||youtube.com^

    Regras avançadas não são reinterpretadas automaticamente.
    """
    rule = (rule or "").strip()

    if rule.startswith("@@||") and rule.endswith("^"):
        return rule[2:]

    if rule.startswith("||") and rule.endswith("^"):
        return "@@" + rule

    return None


def _formatar_regras_inteligente(raw_text: str, mode: str = "block") -> list[str]:
    """
    Converte texto livre em regras AdGuard válidas.

    Regras avançadas são preservadas exatamente como digitadas.
    Entradas simples são normalizadas e convertidas para ||dominio^ / @@||dominio^.
    """
    mode = "allow" if mode == "allow" else "block"
    rules: list[str] = []

    for raw_line in (raw_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith(_ADVANCED_PREFIXES):
            rules.append(line)
            continue

        domain = _extrair_dominio(line)
        if not domain:
            logger.warning("Regra DNS ignorada por domínio inválido: %r", line)
            continue

        for variation in _variacoes_dominio(domain):
            rules.append(_regra_para_dominio(variation, mode))

    return _dedupe_keep_order(rules)


def adicionar_regras(
    client: AdGuardClient,
    raw_text: str,
    mode: str = "block",
) -> dict:
    """
    Faz append seguro nas regras atuais.

    Também remove o conflito oposto exato para que a ação do operador seja
    determinística. Exemplo: ao bloquear youtube.com, remove
    @@||youtube.com^ se essa permissão simples já existir.
    """
    novas_regras = _formatar_regras_inteligente(raw_text, mode=mode)

    regras_atuais = client.get_custom_rules() or []
    if not isinstance(regras_atuais, list):
        logger.warning(
            "get_custom_rules retornou %s — normalizando para lista vazia",
            type(regras_atuais),
        )
        regras_atuais = []

    regras_atuais = [
        rule.strip()
        for rule in regras_atuais
        if isinstance(rule, str) and rule.strip()
    ]
    regras_atuais = _dedupe_keep_order(regras_atuais)

    if not novas_regras:
        return {
            "added": [],
            "skipped": [],
            "removed_conflicts": [],
            "invalid_or_empty": True,
            "total": len(regras_atuais),
        }

    current_set = set(regras_atuais)
    removed_conflicts: list[str] = []

    # Resolve somente conflitos diretos, sem tentar interpretar sintaxe
    # avançada do AdGuard.
    for rule in novas_regras:
        opposite = _regra_oposta(rule)
        if opposite and opposite in current_set:
            regras_atuais.remove(opposite)
            current_set.remove(opposite)
            removed_conflicts.append(opposite)

    added: list[str] = []
    skipped: list[str] = []

    for rule in novas_regras:
        if rule in current_set:
            skipped.append(rule)
            continue

        regras_atuais.append(rule)
        current_set.add(rule)
        added.append(rule)

    if added or removed_conflicts:
        client.set_custom_rules(regras_atuais)

    return {
        "added": added,
        "skipped": skipped,
        "removed_conflicts": removed_conflicts,
        "invalid_or_empty": False,
        "total": len(regras_atuais),
    }
