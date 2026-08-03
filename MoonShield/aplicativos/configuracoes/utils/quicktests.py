"""
aplicativos/configuracoes/utils/quicktests.py
─────────────────────────────────────────────
Executa testes de rede REAIS no servidor:
  - ping_gateway  → ICMP ping para o gateway configurado
  - resolve_dns   → Resolve google.com usando o DNS configurado
  - dns_latency   → Mede latência do DNS configurado
  - internet      → Tenta abrir conexão TCP com 8.8.8.8:53

Todos retornam: { "ok": bool, "ms": int|None, "msg": str }
"""

import socket
import time
import subprocess
import platform


# ─────────────────────────────────────────────────────────────────────────────
# HELPER INTERNO: mede tempo de um socket TCP
# ─────────────────────────────────────────────────────────────────────────────

def _tcp_latency(host: str, port: int = 53, timeout: float = 3.0) -> dict:
    """Abre conexão TCP e mede o RTT em ms."""
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            ms = round((time.perf_counter() - t0) * 1000)
        return {"ok": True, "ms": ms, "msg": f"{host}:{port} acessível ({ms}ms)"}
    except OSError as e:
        return {"ok": False, "ms": None, "msg": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# PING GATEWAY
# ─────────────────────────────────────────────────────────────────────────────

def test_ping_gateway(gateway: str) -> dict:
    """
    Faz ping ICMP real para o gateway.
    Usa subprocess com ping nativo do SO (Windows ou Linux/Mac).
    """
    if not gateway or gateway == "—":
        return {"ok": False, "ms": None, "msg": "Gateway não configurado."}

    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", "2000", gateway]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", gateway]

    try:
        t0 = time.perf_counter()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        ms = round((time.perf_counter() - t0) * 1000)

        if result.returncode == 0:
            # Tenta extrair o tempo real do output do ping
            ms_real = _parse_ping_ms(result.stdout, system)
            return {
                "ok": True,
                "ms": ms_real if ms_real else ms,
                "msg": f"Gateway {gateway} respondeu ({ms_real or ms}ms)",
            }
        else:
            return {
                "ok": False,
                "ms": None,
                "msg": f"Gateway {gateway} não respondeu (timeout ou inacessível)",
            }
    except subprocess.TimeoutExpired:
        return {"ok": False, "ms": None, "msg": f"Timeout ao pingar {gateway}"}
    except FileNotFoundError:
        # ping não disponível — fallback via TCP
        return _tcp_latency(gateway, port=80)
    except Exception as e:
        return {"ok": False, "ms": None, "msg": str(e)}


def _parse_ping_ms(output: str, system: str) -> int | None:
    """Extrai o tempo em ms do output do ping."""
    import re
    if system == "Windows":
        # "Tempo = 5ms" ou "time=5ms"
        m = re.search(r"[Tt]empo\s*[=<]\s*(\d+)\s*ms", output)
        if not m:
            m = re.search(r"time[=<](\d+)ms", output)
    else:
        # "time=5.23 ms"
        m = re.search(r"time[=<]([\d.]+)\s*ms", output)

    if m:
        try:
            return round(float(m.group(1)))
        except Exception:
            return None
    return None


# ─────────────────────────────────────────────────────────────────────────────
# RESOLVE DNS (google.com)
# ─────────────────────────────────────────────────────────────────────────────

def test_resolve_dns() -> dict:
    """
    Resolve google.com usando o resolver padrão do sistema.
    Mede o tempo de resposta.
    """
    try:
        t0 = time.perf_counter()
        ip = socket.gethostbyname("google.com")
        ms = round((time.perf_counter() - t0) * 1000)
        return {"ok": True, "ms": ms, "msg": f"google.com → {ip} ({ms}ms)"}
    except socket.gaierror as e:
        return {"ok": False, "ms": None, "msg": f"Falha ao resolver DNS: {e}"}
    except Exception as e:
        return {"ok": False, "ms": None, "msg": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# LATÊNCIA DNS CONFIGURADO
# ─────────────────────────────────────────────────────────────────────────────

def test_dns_latency(dns_server: str) -> dict:
    """
    Mede latência de resposta do servidor DNS configurado via TCP porta 53.
    Se não houver DNS configurado, usa 1.1.1.1.
    """
    host = dns_server if dns_server and dns_server not in ("", "—") else "1.1.1.1"
    result = _tcp_latency(host, port=53, timeout=3.0)
    result["msg"] = f"DNS {host}: {result['msg']}"
    return result


# ─────────────────────────────────────────────────────────────────────────────
# ACESSO À INTERNET
# ─────────────────────────────────────────────────────────────────────────────

def test_internet_access() -> dict:
    """
    Verifica acesso à internet abrindo conexão TCP com 8.8.8.8:53 (Google DNS).
    Não depende de resolução de nome — é puro TCP.
    """
    result = _tcp_latency("8.8.8.8", port=53, timeout=4.0)
    if result["ok"]:
        result["msg"] = f"Internet OK — 8.8.8.8:53 acessível ({result['ms']}ms)"
    else:
        result["msg"] = f"Sem acesso à internet: {result['msg']}"
    return result