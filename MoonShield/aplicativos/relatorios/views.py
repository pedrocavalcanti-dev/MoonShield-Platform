from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
import json
import logging

from rede.services.topologia import obter_topologia
from rede.services.agent_client import agent_disponivel
from relatorios.models import ExecucaoDiagnostico
from relatorios.services.diagnostico_agent import executar_diagnostico_no_agent

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


@login_required
@require_http_methods(["GET"])
def diagnostico_contexto_api(request):
    topologia = obter_topologia()

    # Extrair info WAN
    wan = topologia.get("wan", {}).get("principal") or {}
    wan_desejado = wan.get("desejado", {})
    wan_observado = wan.get("observado", {})

    # Extrair info LAN
    lan = topologia.get("lan", {}).get("principal") or {}
    lan_desejado = lan.get("desejado", {})

    # DNS e Gateway normalmente ficam no gateway/dns da WAN desejada

    node = request.get_host().split(":")[0]  # O node atual acessado pelo browser

    # Extrair IPs (seguro extrair de observed/addresses)
    wan_cidr = ""
    wan_ips = wan_observado.get("addresses", [])
    if wan_ips:
        wan_cidr = wan_ips[0].get("address", "")

    lan_cidr = ""
    lan_ips = lan.get("observado", {}).get("addresses", [])
    if lan_ips:
        lan_cidr = lan_ips[0].get("address", "")

    context = {
        "ok": True,
        "agent": "online" if agent_disponivel() else "offline",
        "hostname": node,
        "wan_iface": wan_desejado.get("nome", ""),
        "wan_cidr": wan_cidr,
        "lan_iface": lan_desejado.get("nome", ""),
        "lan_cidr": lan_cidr,
        "gateway": wan_desejado.get("ipv4", {}).get("gateway", ""),
        "dns1": "",
        "dns2": "",
        "ip_local": lan_cidr or node,
        "node": node
    }

    # Se houver dns configurado na WAN
    dns_list = wan_desejado.get("ipv4", {}).get("dns", [])
    if dns_list:
        if len(dns_list) > 0:
            context["dns1"] = dns_list[0]
        if len(dns_list) > 1:
            context["dns2"] = dns_list[1]

    return JsonResponse(context)


@login_required
@require_http_methods(["POST"])
def diagnostico_executar_api(request):
    try:
        dados = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "JSON inválido."}, status=400)

    tool = dados.get("tool", "")
    target = dados.get("target", "")
    options = dados.get("options", {})
    source = dados.get("source", "guided")

    if not isinstance(tool, str) or not tool:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Tool é obrigatória."}, status=400)

    if not isinstance(target, str) or not target:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Target é obrigatório."}, status=400)

    if len(target) > 255:
        return JsonResponse({"ok": False, "status": "err", "error_code": "validation_error", "summary": "Target excedeu limite de tamanho."}, status=400)

    if source not in [c[0] for c in ExecucaoDiagnostico.ORIGEM_CHOICES]:
        source = "guided"

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
    topologia = obter_topologia()
    wan = topologia.get("wan", {}).get("principal") or {}
    lan = topologia.get("lan", {}).get("principal") or {}
    snapshot = {
        "wan_iface": wan.get("desejado", {}).get("nome", ""),
        "lan_iface": lan.get("desejado", {}).get("nome", ""),
    }

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
