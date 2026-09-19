import subprocess
import shutil
import socket
import time
from typing import Any
import urllib.request
import urllib.error
import urllib.parse
from contextlib import closing

from .validacoes import validar_alvo_rede, validar_url_http, validar_porta_tcp
from .parsers import parse_ping_output, parse_mtr_json, parse_ip_j

ALLOWED_TOOLS = {
    "ping",
    "traceroute",
    "mtr",
    "dns_lookup",
    "reverse_dns",
    "dns_latency",
    "tcp_connect",
    "http_check",
    "arp_table",
    "routes",
    "interfaces",
    "sockets"
}

TARGETLESS_TOOLS = {
    "routes",
    "interfaces",
    "arp_table",
    "sockets",
}

def _get_bin(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"Ferramenta '{name}' não encontrada no sistema.")
    return path

def _run_subprocess(args: list[str], timeout: float) -> dict[str, Any]:
    start_time = time.time()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit_code": proc.returncode,
            "duration_ms": duration_ms,
            "timeout_excedido": False
        }
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "stdout": exc.stdout.decode('utf-8', errors='replace') if exc.stdout else "",
            "stderr": exc.stderr.decode('utf-8', errors='replace') if exc.stderr else "",
            "exit_code": -1,
            "duration_ms": duration_ms,
            "timeout_excedido": True
        }
    except Exception as exc:
        duration_ms = int((time.time() - start_time) * 1000)
        raise RuntimeError(f"Falha ao executar subprocesso: {exc}")

def execute_ping(target: str, options: dict[str, Any]) -> dict[str, Any]:
    valid_target = validar_alvo_rede(target)
    count = max(1, min(20, int(options.get("count", 4))))
    timeout = max(1, min(10, int(options.get("timeout", 4))))

    bin_path = _get_bin("ping")
    args = [bin_path, "-c", str(count), "-W", str(timeout), valid_target]

    res = _run_subprocess(args, timeout=timeout + (count * 1.5))
    if res["timeout_excedido"]:
        return {
            "status": "err",
            "error_code": "timeout",
            "summary": "Tempo limite excedido",
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "structured": {},
            "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
        }

    parsed = parse_ping_output(res["stdout"])

    if res["exit_code"] == 0 and parsed.get("loss_percent", 100) == 0:
        status = "ok"
        summary = "Destino respondeu sem perda de pacotes"
    elif parsed.get("received", 0) > 0:
        status = "warn"
        summary = f"Destino respondeu com perda de pacotes ({parsed.get('loss_percent')}%)"
    else:
        status = "err"
        summary = "Destino inatingível ou 100% de perda"

    return {
        "status": status,
        "summary": summary,
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": parsed,
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_traceroute(target: str, options: dict[str, Any]) -> dict[str, Any]:
    valid_target = validar_alvo_rede(target)
    max_hops = max(1, min(64, int(options.get("max_hops", 30))))
    timeout_total = 30.0

    bin_path = _get_bin("traceroute")
    args = [bin_path, "-m", str(max_hops), "-w", "1", "-q", "1", valid_target]

    res = _run_subprocess(args, timeout=timeout_total)
    if res["timeout_excedido"]:
        return {
            "status": "err",
            "error_code": "timeout",
            "summary": "Tempo limite excedido",
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "structured": {},
            "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
        }

    status = "ok" if res["exit_code"] == 0 else "warn"
    return {
        "status": status,
        "summary": "Traceroute concluído" if status == "ok" else "Traceroute finalizou com erros",
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_mtr(target: str, options: dict[str, Any]) -> dict[str, Any]:
    valid_target = validar_alvo_rede(target)
    cycles = max(3, min(30, int(options.get("cycles", 10))))
    timeout_total = float(cycles * 2) + 5.0

    bin_path = _get_bin("mtr")
    args = [bin_path, "--report", "--json", "--report-cycles", str(cycles), valid_target]

    res = _run_subprocess(args, timeout=timeout_total)
    if res["timeout_excedido"]:
        return {
            "status": "err",
            "error_code": "timeout",
            "summary": "Tempo limite excedido",
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "structured": {},
            "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
        }

    parsed = parse_mtr_json(res["stdout"])

    return {
        "status": "ok" if res["exit_code"] == 0 else "warn",
        "summary": "MTR finalizado",
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": parsed,
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_dns_lookup(target: str, options: dict[str, Any]) -> dict[str, Any]:
    valid_target = validar_alvo_rede(target)
    record_type = options.get("record_type", "A")
    if record_type not in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
        record_type = "A"

    bin_path = _get_bin("dig")
    args = [bin_path, valid_target, record_type, "+short", "+time=3", "+tries=2"]

    res = _run_subprocess(args, timeout=10.0)
    if res["timeout_excedido"]:
        return {
            "status": "err",
            "error_code": "timeout",
            "summary": "Tempo limite excedido",
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "structured": {},
            "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
        }

    stdout = res["stdout"].strip()
    status = "ok" if stdout and res["exit_code"] == 0 else "err"
    summary = "Consulta resolvida" if status == "ok" else "Nenhum registro encontrado"

    return {
        "status": status,
        "summary": summary,
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": {"records": stdout.splitlines()},
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_reverse_dns(target: str, options: dict[str, Any]) -> dict[str, Any]:
    valid_target = validar_alvo_rede(target) # Ensures basic string sanity, could be IP
    bin_path = _get_bin("dig")
    args = [bin_path, "-x", valid_target, "+short", "+time=3", "+tries=2"]

    res = _run_subprocess(args, timeout=10.0)
    if res["timeout_excedido"]:
        return {
            "status": "err",
            "error_code": "timeout",
            "summary": "Tempo limite excedido",
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "structured": {},
            "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
        }

    stdout = res["stdout"].strip()
    status = "ok" if stdout and res["exit_code"] == 0 else "err"
    summary = "Reverso resolvido" if status == "ok" else "Nenhum registro reverso encontrado"

    return {
        "status": status,
        "summary": summary,
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": {"records": stdout.splitlines()},
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_dns_latency(target: str, options: dict[str, Any]) -> dict[str, Any]:
    valid_target = validar_alvo_rede(target)
    bin_path = _get_bin("dig")
    # Execute single dig with stats to get Query time
    args = [bin_path, valid_target, "A", "+stats", "+time=3", "+tries=1"]

    res = _run_subprocess(args, timeout=10.0)
    if res["timeout_excedido"]:
        return {
            "status": "err",
            "error_code": "timeout",
            "summary": "Tempo limite excedido",
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "structured": {},
            "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
        }

    # parse "Query time: 12 msec"
    duration = None
    for line in res["stdout"].splitlines():
        if "Query time:" in line:
            parts = line.split(":")
            if len(parts) == 2:
                try:
                    duration = int(parts[1].strip().split()[0])
                except ValueError:
                    pass
            break

    status = "ok" if res["exit_code"] == 0 and duration is not None else "err"
    return {
        "status": status,
        "summary": f"Latência de DNS: {duration} ms" if status == "ok" else "Falha ao medir latência",
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": {"query_time_ms": duration},
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_tcp_connect(target: str, options: dict[str, Any]) -> dict[str, Any]:
    valid_target = validar_alvo_rede(target)
    port = validar_porta_tcp(options.get("port", 80))
    timeout = max(1, min(10, int(options.get("timeout", 5))))

    start_time = time.time()
    reachable = False
    error_msg = ""

    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(timeout)
            sock.connect((valid_target, port))
            reachable = True
    except socket.timeout:
        error_msg = "Timeout"
    except Exception as e:
        error_msg = str(e)

    duration_ms = int((time.time() - start_time) * 1000)

    status = "ok" if reachable else "err"
    summary = f"Conexão TCP estabelecida na porta {port}" if reachable else f"Falha ao conectar: {error_msg}"

    return {
        "status": status,
        "summary": summary,
        "stdout": "",
        "stderr": error_msg,
        "structured": {"reachable": reachable, "port": port},
        "meta": {"duration_ms": duration_ms, "exit_code": 0 if reachable else 1}
    }

def execute_http_check(target: str, options: dict[str, Any]) -> dict[str, Any]:
    url = validar_url_http(target)
    timeout = max(1, min(15, int(options.get("timeout", 5))))

    start_time = time.time()
    req = urllib.request.Request(url, headers={'User-Agent': 'MoonShield-Agent/1.0'})

    status_code = None
    headers_dict = {}
    error_msg = ""
    final_url = url

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = response.getcode()
            final_url = response.geturl()
            for k, v in response.headers.items():
                if k.lower() not in ["set-cookie", "authorization"]:
                    headers_dict[k] = v
    except urllib.error.HTTPError as e:
        status_code = e.code
        error_msg = str(e)
    except urllib.error.URLError as e:
        error_msg = str(e.reason)
    except socket.timeout:
        error_msg = "Timeout"
    except Exception as e:
        error_msg = str(e)

    duration_ms = int((time.time() - start_time) * 1000)

    if status_code and 200 <= status_code < 400:
        status = "ok"
        summary = f"HTTP {status_code} recebido"
    elif status_code:
        status = "warn"
        summary = f"HTTP {status_code} recebido"
    else:
        status = "err"
        summary = f"Falha na requisição: {error_msg}"

    return {
        "status": status,
        "summary": summary,
        "stdout": "",
        "stderr": error_msg,
        "structured": {
            "status_code": status_code,
            "final_url": final_url,
            "headers": headers_dict
        },
        "meta": {"duration_ms": duration_ms, "exit_code": 0 if status_code else 1}
    }

def execute_arp_table(target: str, options: dict[str, Any]) -> dict[str, Any]:
    bin_path = _get_bin("ip")
    args = [bin_path, "-j", "neigh"]

    res = _run_subprocess(args, timeout=5.0)
    if res["timeout_excedido"]:
        return {"status": "err", "error_code": "timeout", "summary": "Tempo limite excedido", "stdout": res["stdout"], "meta": res}

    parsed = parse_ip_j(res["stdout"])
    return {
        "status": "ok" if res["exit_code"] == 0 else "err",
        "summary": "Tabela ARP / Neighbors lida com sucesso",
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": {"neighbors": parsed},
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_routes(target: str, options: dict[str, Any]) -> dict[str, Any]:
    bin_path = _get_bin("ip")
    args = [bin_path, "-j", "route"]

    res = _run_subprocess(args, timeout=5.0)
    if res["timeout_excedido"]:
        return {"status": "err", "error_code": "timeout", "summary": "Tempo limite excedido", "stdout": res["stdout"], "meta": res}

    parsed = parse_ip_j(res["stdout"])
    return {
        "status": "ok" if res["exit_code"] == 0 else "err",
        "summary": "Tabela de rotas lida com sucesso",
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": {"routes": parsed},
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_interfaces(target: str, options: dict[str, Any]) -> dict[str, Any]:
    bin_path = _get_bin("ip")
    args = [bin_path, "-j", "addr"]

    res = _run_subprocess(args, timeout=5.0)
    if res["timeout_excedido"]:
        return {"status": "err", "error_code": "timeout", "summary": "Tempo limite excedido", "stdout": res["stdout"], "meta": res}

    parsed = parse_ip_j(res["stdout"])
    return {
        "status": "ok" if res["exit_code"] == 0 else "err",
        "summary": "Interfaces lidas com sucesso",
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": {"interfaces": parsed},
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

def execute_sockets(target: str, options: dict[str, Any]) -> dict[str, Any]:
    bin_path = _get_bin("ss")
    # Only allow a few safe flags, e.g. -t, -u, -n, -l, -a
    safe_flags = ["-t", "-u", "-n", "-l", "-a"]
    user_flags = options.get("flags", ["-tunl"])

    args = [bin_path]
    if isinstance(user_flags, list):
        for f in user_flags:
            if f in safe_flags:
                args.append(f)
    if len(args) == 1:
        args.append("-tunl")

    res = _run_subprocess(args, timeout=10.0)
    if res["timeout_excedido"]:
        return {"status": "err", "error_code": "timeout", "summary": "Tempo limite excedido", "stdout": res["stdout"], "meta": res}

    return {
        "status": "ok" if res["exit_code"] == 0 else "err",
        "summary": "Tabela de Sockets lida com sucesso",
        "stdout": res["stdout"],
        "stderr": res["stderr"],
        "structured": {},
        "meta": {"duration_ms": res["duration_ms"], "exit_code": res["exit_code"]}
    }

_EXECUTORS = {
    "ping": execute_ping,
    "traceroute": execute_traceroute,
    "mtr": execute_mtr,
    "dns_lookup": execute_dns_lookup,
    "reverse_dns": execute_reverse_dns,
    "dns_latency": execute_dns_latency,
    "tcp_connect": execute_tcp_connect,
    "http_check": execute_http_check,
    "arp_table": execute_arp_table,
    "routes": execute_routes,
    "interfaces": execute_interfaces,
    "sockets": execute_sockets,
}

def dispatch_tool(tool: str, target: str, options: dict[str, Any]) -> dict[str, Any]:
    if tool not in ALLOWED_TOOLS:
        return {
            "ok": False,
            "tool": tool,
            "target": target,
            "status": "err",
            "error_code": "tool_not_allowed",
            "summary": f"Ferramenta não permitida: {tool}"
        }

    executor = _EXECUTORS.get(tool)
    if not executor:
        return {
            "ok": False,
            "tool": tool,
            "target": target,
            "status": "err",
            "error_code": "executor_not_implemented",
            "summary": f"Executor não implementado para a ferramenta: {tool}"
        }

    try:
        result = executor(target, options)
        result["ok"] = result.get("status") in ("ok", "warn")
        result["tool"] = tool
        result["target"] = target
        return result
    except FileNotFoundError as exc:
        return {
            "ok": False,
            "tool": tool,
            "target": target,
            "status": "err",
            "error_code": "tool_unavailable",
            "summary": str(exc),
            "stderr": str(exc)
        }
    except ValueError as exc:
        return {
            "ok": False,
            "tool": tool,
            "target": target,
            "status": "err",
            "error_code": "invalid_target",
            "summary": str(exc),
            "stderr": str(exc)
        }
    except Exception as exc:
        return {
            "ok": False,
            "tool": tool,
            "target": target,
            "status": "err",
            "error_code": "internal_error",
            "summary": "Erro interno ao executar a ferramenta.",
            "stderr": str(exc)
        }
