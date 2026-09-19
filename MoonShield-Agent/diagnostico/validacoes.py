import ipaddress
import re
from urllib.parse import urlparse

# Simple regex for a valid hostname/FQDN (basic RFC 1123)
_HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)

def _is_valid_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def _is_valid_hostname(target: str) -> bool:
    if not target or len(target) > 253:
        return False
    return bool(_HOSTNAME_REGEX.match(target))

def validar_alvo_rede(target: str) -> str:
    """Valida um alvo genérico de rede (IP ou Hostname). Levanta ValueError se inválido."""
    if not target or not isinstance(target, str):
        raise ValueError("Alvo deve ser uma string não vazia.")

    target = target.strip()

    if "\n" in target or "\r" in target or ";" in target or "&" in target or "|" in target or "$" in target or "`" in target:
        raise ValueError("Caracteres de shell injection detectados.")

    if target.startswith("-"):
        raise ValueError("O alvo não pode começar com hífen.")

    if _is_valid_ip(target):
        return target

    if _is_valid_hostname(target):
        return target

    raise ValueError(f"Alvo inválido: '{target}'. Deve ser IP ou Hostname válido.")

def validar_url_http(url: str) -> str:
    """Valida uma URL HTTP/HTTPS."""
    if not url or not isinstance(url, str):
        raise ValueError("URL não pode estar vazia.")
    url = url.strip()

    if "\n" in url or "\r" in url or ";" in url or "&" in url or "|" in url or "$" in url or "`" in url:
        raise ValueError("Caracteres de shell injection detectados.")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Esquema inválido: {parsed.scheme}. Apenas http e https são suportados.")

    if not parsed.netloc:
        raise ValueError("URL não possui domínio ou IP válido.")

    if parsed.netloc.startswith("-"):
        raise ValueError("Domínio não pode começar com hífen.")

    # Validar hostname/IP na URL
    host = parsed.hostname
    if not host or (not _is_valid_ip(host) and not _is_valid_hostname(host)):
        raise ValueError("Domínio ou IP inválido na URL.")

    return url

def validar_porta_tcp(porta) -> int:
    try:
        p = int(porta)
        if 1 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    raise ValueError(f"Porta TCP inválida: {porta}. Deve ser um inteiro entre 1 e 65535.")
