from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods, require_POST
import json
import logging

from rede.services.topologia import obter_topologia
from rede.services.agent_client import agent_disponivel
from relatorios.models import ExecucaoDiagnostico
from relatorios.services.diagnostico_agent import executar_diagnostico_no_agent
from configuracoes.models import ConfigSistema

logger = logging.getLogger(__name__)

# View para a página principal de Relatórios
@login_required
def index(request):
    contexto = {
        'titulo': 'Relatórios do Sistema'
    }
    return render(request, 'relatorios/relatorios.html', contexto)

# Nova View para a página de Diagnóstico & Testes (Ping, etc.)
@login_required
def diagnostico(request):
    contexto = {
        'titulo': 'Diagnóstico e Testes de Rede'
    }
    return render(request, 'relatorios/diagnostico.html', contexto)




def _obter_contexto_diagnostico(request=None) -> dict:
    topologia = obter_topologia()

    wan = topologia.get("wan", {}).get("principal") or {}
    lan = topologia.get("lan", {}).get("principal") or {}

    try:
        config = ConfigSistema.get_solo()
        node = config.node_name or "MoonShield"
    except Exception:
        node = "MoonShield"

    # WAN Extraction
    wan_iface = wan.get("nome", "")
    wan_real = wan.get("real", {})
    wan_desejado = wan.get("desejado", {})

    wan_ip = wan_real.get("ipv4", "")
    wan_prefix = wan_real.get("prefixo", "")
    wan_cidr = f"{wan_ip}/{wan_prefix}" if wan_ip and wan_prefix else wan_ip

    # Priority for gateway: real state, then desired state
    gateway = wan_real.get("gateway") or wan_desejado.get("gateway", "")

    # LAN Extraction
    lan_iface = lan.get("nome", "")
    lan_real = lan.get("real", {})
    lan_ip = lan_real.get("ipv4", "")
    lan_prefix = lan_real.get("prefixo", "")
    lan_cidr = f"{lan_ip}/{lan_prefix}" if lan_ip and lan_prefix else lan_ip

    return {
        "ok": True,
        "agent": "online" if agent_disponivel() else "offline",
        "hostname": node,
        "wan_iface": wan_iface,
        "wan_cidr": wan_cidr,
        "lan_iface": lan_iface,
        "lan_cidr": lan_cidr,
        "gateway": gateway,
        "dns1": "",
        "dns2": "",
        "ip_local": lan_ip or (request.get_host().split(":")[0] if request else ""),
        "node": node
    }

@login_required
@require_http_methods(["GET"])
def diagnostico_contexto_api(request):
    context = _obter_contexto_diagnostico(request)
    return JsonResponse(context)

@login_required
@require_http_methods(["POST"])
def diagnostico_executar_api(request):
    try:
        dados = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "JSON inválido."}, status=400)

    tool = dados.get("tool", "")
    target = dados.get("target", "") or ""
    options = dados.get("options", {})
    source = dados.get("source", "guided")

    if not isinstance(tool, str) or not tool:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Tool é obrigatória."}, status=400)

    # Ferramentas que não precisam de target
    targetless_tools = {"routes", "interfaces", "arp_table", "sockets"}

    if not isinstance(target, str):
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Target deve ser texto."}, status=400)

    if not target and tool not in targetless_tools:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Target é obrigatório para esta ferramenta."}, status=400)

    if len(target) > 255:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Target excedeu limite de tamanho."}, status=400)

    if source not in [c[0] for c in ExecucaoDiagnostico.ORIGEM_CHOICES]:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Origem (source) inválida."}, status=400)

    # Allowlist of tools
    allowed_tools = {
        "ping", "traceroute", "mtr", "dns_lookup", "reverse_dns",
        "dns_latency", "tcp_connect", "http_check", "arp_table",
        "routes", "interfaces", "sockets"
    }

    if tool not in allowed_tools:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": f"Ferramenta não permitida: {tool}"}, status=400)

    if not isinstance(options, dict):
        options = {}

    # Execute (will return a standard dictionary block regardless of offline/online)
    result = executar_diagnostico_no_agent(tool, target, options)

    # Determine basic fields
    status = result.get("status", "err")

    # Truncate large outputs to ~256KB
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")

    MAX_LEN = 256 * 1024
    output_truncated = False

    if len(stdout) > MAX_LEN:
        stdout = stdout[:MAX_LEN] + "\n\n... (TRUNCATED)"
        output_truncated = True
    if len(stderr) > MAX_LEN:
        stderr = stderr[:MAX_LEN] + "\n\n... (TRUNCATED)"
        output_truncated = True

    meta = result.get("meta", {})
    meta["output_truncated"] = output_truncated

    # Montar contexto_snapshot
    snapshot = _obter_contexto_diagnostico()

    # Salva apenas execuções válidas que tentaram (incluindo agent timeout, offline, unavailable)
    # Não salva requests bloqueados no começo pelas regras do Django.
    execucao = ExecucaoDiagnostico.objects.create(
        usuario=request.user,
        ferramenta=tool,
        alvo=target,
        opcoes=options,
        origem=source,
        status=status,
        resumo=result.get("summary", ""),
        stdout=stdout,
        stderr=stderr,
        resultado_estruturado=result.get("structured", {}),
        duration_ms=meta.get("duration_ms"),
        exit_code=meta.get("exit_code"),
        contexto_snapshot=snapshot
    )

    status_http = 200
    # Retornar 503 se indisponível para facilitar no front (mas a execução é salva)
    if result.get("error_code") == "agent_unavailable":
        status_http = 503
    elif result.get("error_code") == "timeout":
        status_http = 504

    response_data = {
        "ok": result.get("ok", False),
        "execution_id": str(execucao.id),
        "tool": tool,
        "target": target,
        "status": status,
        "summary": result.get("summary", ""),
        "stdout": stdout,
        "stderr": stderr,
        "structured": result.get("structured", {}),
        "meta": meta
    }
    if "error_code" in result:
        response_data["error_code"] = result["error_code"]

    return JsonResponse(response_data, status=status_http)


@login_required
@require_http_methods(["GET"])
def diagnostico_historico_api(request):
    qs = ExecucaoDiagnostico.objects.all()

    tool = request.GET.get("tool")
    if tool:
        qs = qs.filter(ferramenta=tool)

    status_filter = request.GET.get("status")
    if status_filter:
        qs = qs.filter(status=status_filter)

    source = request.GET.get("source")
    if source:
        qs = qs.filter(origem=source)

    paginator = Paginator(qs, 20)
    page_number = request.GET.get("page", 1)
    page_obj = paginator.get_page(page_number)

    items = []
    for ex in page_obj:
        items.append({
            "id": str(ex.id),
            "created_at": ex.created_at.isoformat(),
            "tool": ex.ferramenta,
            "target": ex.alvo,
            "source": ex.origem,
            "status": ex.status,
            "summary": ex.resumo,
            "duration_ms": ex.duration_ms,
            "user": ex.usuario.username if ex.usuario else None
        })

    return JsonResponse({
        "ok": True,
        "total": paginator.count,
        "page": page_obj.number,
        "pages": paginator.num_pages,
        "items": items
    })

@login_required
@require_http_methods(["GET"])
def diagnostico_execucao_api(request, execucao_id):
    try:
        ex = ExecucaoDiagnostico.objects.get(id=execucao_id)
    except ExecucaoDiagnostico.DoesNotExist:
        return JsonResponse({"ok": False, "status": "err", "error_code": "not_found", "summary": "Execução não encontrada."}, status=404)

    # Sanitizar opções
    safe_options = dict(ex.opcoes)
    for sensitive in ["password", "token", "secret"]:
        if sensitive in safe_options:
            safe_options[sensitive] = "******"

    return JsonResponse({
        "ok": True,
        "id": str(ex.id),
        "tool": ex.ferramenta,
        "target": ex.alvo,
        "options": safe_options,
        "source": ex.origem,
        "status": ex.status,
        "summary": ex.resumo,
        "stdout": ex.stdout,
        "stderr": ex.stderr,
        "structured": ex.resultado_estruturado,
        "duration_ms": ex.duration_ms,
        "exit_code": ex.exit_code,
        "contexto_snapshot": ex.contexto_snapshot,
        "created_at": ex.created_at.isoformat(),
        "user": ex.usuario.username if ex.usuario else None
    })

@login_required
@require_POST
def diagnostico_live_start_api(request):
    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "status": "err", "error_code": "invalid_json"}, status=400)

    tool = data.get("tool")
    target = data.get("target") or ""
    options = data.get("options", {})

    if tool not in ["ping", "mtr"]:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": f"Ferramenta não permitida para live: {tool}"}, status=400)

    from .services.diagnostico_agent import is_agent_online, run_ipc_action
    if not is_agent_online():
        return JsonResponse({"ok": False, "status": "err", "error_code": "agent_unavailable", "summary": "MoonShield Agent está offline."}, status=503)

    resp = run_ipc_action("diagnostic.live.start", {"tool": tool, "target": target, "options": options})
    if not resp:
        return JsonResponse({"ok": False, "status": "err", "summary": "Sem resposta do Agent"}, status=500)

    return JsonResponse(resp)

@login_required
def diagnostico_live_status_api(request, session_id):
    from .services.diagnostico_agent import is_agent_online, run_ipc_action
    if not is_agent_online():
        return JsonResponse({"ok": False, "status": "err", "error_code": "agent_unavailable", "summary": "MoonShield Agent está offline."}, status=503)

    resp = run_ipc_action("diagnostic.live.status", {"session_id": str(session_id)})
    if not resp:
        return JsonResponse({"ok": False, "status": "err", "summary": "Sem resposta do Agent"}, status=500)

    return JsonResponse(resp)

@login_required
@require_POST
def diagnostico_live_stop_api(request, session_id):
    from .services.diagnostico_agent import is_agent_online, run_ipc_action
    if not is_agent_online():
        return JsonResponse({"ok": False, "status": "err", "error_code": "agent_unavailable", "summary": "MoonShield Agent está offline."}, status=503)

    resp = run_ipc_action("diagnostic.live.stop", {"session_id": str(session_id)})
    if not resp:
        return JsonResponse({"ok": False, "status": "err", "summary": "Sem resposta do Agent"}, status=500)

    if resp.get("ok"):
        # Save ONE ExecucaoDiagnostico
        try:
            snapshot = _obter_contexto_diagnostico()
            stdout = resp.get("stdout", "")
            stderr = resp.get("stderr", "")
            if len(stdout) > 256*1024:
                stdout = stdout[:256*1024] + "\n\n... (TRUNCATED)"
            if len(stderr) > 256*1024:
                stderr = stderr[:256*1024] + "\n\n... (TRUNCATED)"

            ExecucaoDiagnostico.objects.create(
                usuario=request.user,
                ferramenta=resp.get("tool"),
                alvo=resp.get("target"),
                opcoes={},
                origem="terminal", # The prompt says we can use terminal or guided if no live exists to avoid migrations!
                status="ok",
                resumo="Sessão Live Finalizada",
                stdout=stdout,
                stderr=stderr,
                resultado_estruturado=resp.get("structured", {}),
                duration_ms=resp.get("elapsed_ms"),
                exit_code=0,
                contexto_snapshot=snapshot
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Erro ao salvar historico live: {e}")

    return JsonResponse(resp)
