"""
Serviço central de consolidação do status do sistema de IDS do MoonShield.
Orquestra leituras passivas em todos os submódulos para prover uma visão limpa,
serializável e sem efeitos colaterais para consumo das interfaces visuais, APIs e CLIs.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict

# Importação controlada para uso de hints ou conversões (NÃO executa ações do BD/Django)
from .tipos import (
    ConfiguracaoSuricataDados,
    DiagnosticoItem,
    EstadoServico,
    StatusServicoDados,
)

# Reuso de métodos read-only de outros módulos especialistas
from .ambiente import (
    detectar_ambiente_completo,
    obter_versao_suricata,
    localizar_suricata_yaml,
    localizar_eve_json,
    verificar_caminhos_suricata,
)
from .interfaces import (
    obter_topologia_detectada,
    obter_interface_por_nome,
)
from .regras import (
    obter_status_regras_completo,
)
from .configurador import (
    obter_status_configuracao,
)
from .servicos import (
    obter_status_stack,
    obter_status_servicos,
)
from .diagnostico import (
    executar_diagnostico_resumido,
    executar_diagnostico,
    obter_acoes_recomendadas,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

STATUS_OK = "ok"
STATUS_AVISO = "aviso"
STATUS_ERRO = "erro"
STATUS_DESCONHECIDO = "desconhecido"
STATUS_DESATIVADO = "desativado"

EVE_JSON_PADRAO = Path("/var/log/suricata/eve.json")

CURSOR_PADRAO_RELATIVO = Path("var/cursors/suricata_eve.cursor")

LIMITE_ATRASO_EVE_SEGUNDOS = 300
LIMITE_ATRASO_MONITOR_SEGUNDOS = 300
LIMITE_ATRASO_CURSOR_BYTES = 10 * 1024 * 1024


# ==============================================================================
# HELPERS DE SERIALIZAÇÃO E LOCALIZAÇÃO
# ==============================================================================

def _validar_serializacao_status(dados: dict[str, object]) -> dict[str, object]:
    """Garante que a resposta não crashe o formatador JSON da REST API."""
    def _converter(valor):
        if isinstance(valor, Enum):
            return valor.value
        if isinstance(valor, Path):
            return str(valor)
        if isinstance(valor, datetime):
            return valor.isoformat()
        if hasattr(valor, "to_dict") and callable(getattr(valor, "to_dict")):
            return valor.to_dict()
        if hasattr(valor, "__dataclass_fields__"):
            return asdict(valor)
        if isinstance(valor, set):
            return sorted(list(valor))
        if isinstance(valor, bytes):
            return valor.decode("utf-8", errors="replace")
        if isinstance(valor, dict):
            return {k: _converter(v) for k, v in valor.items()}
        if isinstance(valor, list):
            return [_converter(v) for v in valor]
        if isinstance(valor, tuple):
            return tuple(_converter(v) for v in valor)
        return valor

    return {k: _converter(v) for k, v in dados.items()}


def obter_caminho_cursor(
    caminho_preferido: str | Path | None = None,
    base_dir: str | Path | None = None,
) -> Path:
    """Resolve a localização do cursor nativo sem acoplar diretamente na config do Django."""
    if caminho_preferido:
        return Path(caminho_preferido)
        
    if base_dir:
        return Path(base_dir) / CURSOR_PADRAO_RELATIVO
        
    # Heurística voltando a partir de /MoonShield/aplicativos/incidentes/services/suricata
    # __file__ -> suricata -> services -> incidentes -> aplicativos -> MoonShield
    raiz_estimada = Path(__file__).resolve().parent.parent.parent.parent.parent
    return raiz_estimada / CURSOR_PADRAO_RELATIVO


def obter_status_arquivo(caminho: str | Path) -> dict[str, object]:
    """Analisa propriedades base do POSIX FS de forma imutável."""
    p_obj = Path(caminho)
    info = {
        "caminho": str(p_obj),
        "existe": False,
        "arquivo": False,
        "legivel": False,
        "gravavel": False,
        "tamanho": 0,
        "modificado_em": None,
        "idade_segundos": None,
    }
    
    if p_obj.exists():
        info["existe"] = True
        info["arquivo"] = p_obj.is_file()
        info["legivel"] = os.access(p_obj, os.R_OK)
        info["gravavel"] = os.access(p_obj, os.W_OK)
        try:
            st = p_obj.stat()
            info["tamanho"] = st.st_size
            dt_mod = datetime.fromtimestamp(st.st_mtime)
            info["modificado_em"] = dt_mod.isoformat()
            info["idade_segundos"] = (datetime.now() - dt_mod).total_seconds()
        except OSError:
            pass
            
    return info


# ==============================================================================
# AUDITORES DE CAMADA LÓGICA E DE ARQUIVO
# ==============================================================================

def obter_status_eve(eve_path: str | Path | None = None) -> dict[str, object]:
    """Analisa a integridade temporal do log que alimenta o funil do IDS."""
    caminho_real = eve_path or localizar_eve_json() or EVE_JSON_PADRAO
    fs_info = obter_status_arquivo(caminho_real)
    
    info = {
        "caminho": str(caminho_real),
        "existe": fs_info["existe"],
        "legivel": fs_info["legivel"],
        "tamanho": fs_info["tamanho"],
        "idade_segundos": fs_info["idade_segundos"],
        "atualizando": False,
        "vazio": False,
        "status": STATUS_OK,
        "mensagem": "Arquivo recebendo logs.",
    }
    
    if not info["existe"]:
        info["status"] = STATUS_ERRO
        info["mensagem"] = "O arquivo EVE JSON não foi encontrado no sistema."
        return info
        
    if info["tamanho"] == 0:
        info["vazio"] = True
        info["status"] = STATUS_AVISO
        info["mensagem"] = "Arquivo existente porém ainda vazio."
        return info

    if info["idade_segundos"] is not None:
        if info["idade_segundos"] <= LIMITE_ATRASO_EVE_SEGUNDOS:
            info["atualizando"] = True
        else:
            info["status"] = STATUS_AVISO
            info["mensagem"] = f"Arquivo inativo há mais de {LIMITE_ATRASO_EVE_SEGUNDOS}s."

    return info



def _ler_cursor_payload(cursor_path: str | Path) -> dict[str, object] | None:
    """
    Lê o cursor JSON completo de forma segura.

    O formato real do monitor contém metadados além do offset, por exemplo:
    {
      "path": "/var/log/suricata/eve.json",
      "offset": 36119967,
      "inode": 148,
      "device": 65025,
      "updated_at": "2026-08-18T23:32:41.029400+00:00"
    }

    O código antigo lia apenas 128 bytes; isso truncava o JSON e fazia um cursor
    válido ser classificado como corrompido.
    """
    path_obj = Path(cursor_path)

    if not path_obj.is_file() or not os.access(path_obj, os.R_OK):
        return None

    try:
        # Cursor é um arquivo pequeno. Limitamos a 64 KiB para evitar leitura
        # acidental de um arquivo indevido caso o caminho seja alterado.
        if path_obj.stat().st_size > 64 * 1024:
            logger.warning("Cursor Suricata maior que o esperado: %s", path_obj)
            return None

        with path_obj.open("r", encoding="utf-8", errors="strict") as arquivo:
            dados = json.load(arquivo)

        if not isinstance(dados, dict):
            return None

        offset = dados.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            return None

        return dados
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        logger.exception("Falha ao ler cursor Suricata: %s", path_obj)
        return None


def ler_cursor(cursor_path: str | Path) -> int | None:
    """Retorna somente o offset numérico do cursor, preservando compatibilidade."""
    dados = _ler_cursor_payload(cursor_path)
    if not dados:
        return None

    offset = dados.get("offset")
    return offset if isinstance(offset, int) and not isinstance(offset, bool) and offset >= 0 else None


def obter_status_cursor(cursor_path: str | Path, eve_path: str | Path) -> dict[str, object]:
    """
    Correlaciona o cursor persistido pelo monitor com o arquivo EVE atual.

    A validação considera:
    - existência e legibilidade do cursor;
    - offset;
    - inode/device do arquivo monitorado, quando presentes;
    - tamanho atual do EVE;
    - idade do cursor;
    - backlog em bytes.
    """
    info: dict[str, object] = {
        "caminho": str(cursor_path),
        "existe": False,
        "legivel": False,
        "posicao": 0,
        "tamanho_eve": 0,
        "atraso_bytes": 0,
        "idade_segundos": None,
        "valido": False,
        "acompanhando": False,
        "status": STATUS_DESCONHECIDO,
        "mensagem": "Cursor ainda não avaliado.",
        "path_eve_cursor": None,
        "inode_cursor": None,
        "device_cursor": None,
        "inode_eve": None,
        "device_eve": None,
        "rotacao_detectada": False,
        "atualizado_em": None,
    }

    st_cursor = obter_status_arquivo(cursor_path)
    info["existe"] = bool(st_cursor.get("existe"))
    info["legivel"] = bool(st_cursor.get("legivel"))
    info["idade_segundos"] = st_cursor.get("idade_segundos")

    st_eve = obter_status_arquivo(eve_path)
    tamanho_eve = int(st_eve.get("tamanho") or 0)
    info["tamanho_eve"] = tamanho_eve

    if not info["existe"]:
        info["status"] = STATUS_AVISO
        info["mensagem"] = "Cursor ainda não foi criado pelo monitor."
        return info

    if not info["legivel"]:
        info["status"] = STATUS_ERRO
        info["mensagem"] = "O cursor existe, mas não pode ser lido pelo MoonShield."
        return info

    payload = _ler_cursor_payload(cursor_path)
    if not payload:
        info["status"] = STATUS_ERRO
        info["mensagem"] = "O arquivo de cursor não contém um JSON válido com offset numérico."
        return info

    posicao = int(payload["offset"])
    info["posicao"] = posicao
    info["valido"] = True
    info["path_eve_cursor"] = payload.get("path")
    info["inode_cursor"] = payload.get("inode")
    info["device_cursor"] = payload.get("device")
    info["atualizado_em"] = payload.get("updated_at")

    # Metadados do EVE real para reconhecer rotação.
    try:
        eve_stat = Path(eve_path).stat()
        info["inode_eve"] = int(eve_stat.st_ino)
        info["device_eve"] = int(eve_stat.st_dev)
    except OSError:
        eve_stat = None

    inode_cursor = payload.get("inode")
    device_cursor = payload.get("device")
    inode_eve = info["inode_eve"]
    device_eve = info["device_eve"]

    if (
        eve_stat is not None
        and isinstance(inode_cursor, int)
        and isinstance(device_cursor, int)
        and (inode_cursor != inode_eve or device_cursor != device_eve)
    ):
        info["rotacao_detectada"] = True
        info["status"] = STATUS_AVISO
        info["mensagem"] = (
            "O EVE foi rotacionado e o cursor ainda referencia o arquivo anterior. "
            "O monitor deve reposicionar o cursor automaticamente."
        )
        return info

    # Se o cursor aponta para o EVE atual, o offset nunca pode exceder o tamanho.
    if posicao > tamanho_eve and tamanho_eve >= 0:
        info["status"] = STATUS_ERRO
        info["mensagem"] = (
            "O offset do cursor ultrapassa o tamanho atual do EVE sem evidência de rotação."
        )
        return info

    atraso = max(0, tamanho_eve - posicao)
    info["atraso_bytes"] = atraso

    idade_cursor = st_cursor.get("idade_segundos")
    idade_eve = st_eve.get("idade_segundos")

    # Cursor válido e recente significa que o monitor está acompanhando a fila.
    cursor_recente = idade_cursor is not None and idade_cursor <= LIMITE_ATRASO_MONITOR_SEGUNDOS
    eve_recente = idade_eve is not None and idade_eve <= LIMITE_ATRASO_EVE_SEGUNDOS

    if atraso > LIMITE_ATRASO_CURSOR_BYTES:
        info["status"] = STATUS_AVISO
        info["acompanhando"] = bool(cursor_recente)
        info["mensagem"] = (
            f"O monitor está com backlog de aproximadamente "
            f"{atraso / (1024 * 1024):.1f} MB."
        )
        return info

    if eve_recente and not cursor_recente:
        info["status"] = STATUS_ERRO
        info["mensagem"] = (
            "O EVE continua recebendo eventos, mas o cursor não é atualizado "
            f"há mais de {LIMITE_ATRASO_MONITOR_SEGUNDOS}s."
        )
        return info

    info["acompanhando"] = True
    info["status"] = STATUS_OK
    info["mensagem"] = "Cursor válido e acompanhando o fluxo de eventos."
    return info


def obter_status_monitor_local(
    eve_path: str | Path | None = None,
    cursor_path: str | Path | None = None,
    base_dir: str | Path | None = None,
) -> dict[str, object]:
    """Consolida o estado real do monitor local do EVE."""
    servicos = obter_status_servicos()
    svc_status = (
        servicos.get("moonshield-suricata-monitor")
        or servicos.get("monitor")
        or servicos.get("monitor_suricata")
    )
    svc_dict = _validar_serializacao_status({"s": svc_status})["s"] if svc_status else {}
    if not isinstance(svc_dict, dict):
        svc_dict = {}

    caminho_eve = Path(eve_path or localizar_eve_json() or EVE_JSON_PADRAO)
    caminho_cur = obter_caminho_cursor(cursor_path, base_dir)

    st_eve = obter_status_eve(caminho_eve)
    st_cur = obter_status_cursor(caminho_cur, caminho_eve)

    is_ativo = bool(svc_dict.get("ativo", False))
    is_instalado = bool(svc_dict.get("instalado", False))

    lendo_eve = bool(
        is_ativo
        and st_eve.get("existe")
        and st_eve.get("legivel")
        and st_cur.get("valido")
        and st_cur.get("acompanhando")
    )

    if not is_instalado:
        status_final = STATUS_ERRO
        mensagem = "Serviço moonshield-suricata-monitor não está instalado."
    elif not is_ativo:
        status_final = STATUS_ERRO
        mensagem = "Serviço moonshield-suricata-monitor está parado."
    elif st_eve.get("status") == STATUS_ERRO:
        status_final = STATUS_ERRO
        mensagem = f"Monitor ativo, porém o EVE possui erro: {st_eve.get('mensagem', '')}"
    elif st_cur.get("status") == STATUS_ERRO:
        status_final = STATUS_ERRO
        mensagem = f"Monitor ativo, porém o cursor possui erro: {st_cur.get('mensagem', '')}"
    elif st_eve.get("status") == STATUS_AVISO or st_cur.get("status") == STATUS_AVISO:
        status_final = STATUS_AVISO
        mensagem = st_cur.get("mensagem") or st_eve.get("mensagem") or "Monitor ativo com aviso."
    else:
        status_final = STATUS_OK
        mensagem = "Monitor ativo, lendo o EVE e mantendo o cursor sincronizado."

    saudavel = status_final == STATUS_OK and lendo_eve

    return {
        "servico": svc_dict,
        "eve": st_eve,
        "cursor": st_cur,
        "ativo": is_ativo,
        "instalado": is_instalado,
        "lendo_eve": lendo_eve,
        "saudavel": saudavel,
        "status": status_final,
        "mensagem": mensagem,
    }


def _normalizar_versao_suricata(ambiente: dict[str, object]) -> str | None:
    """Obtém uma versão estável do Suricata para consumo do frontend."""
    suri_amb = ambiente.get("suricata") if isinstance(ambiente, dict) else {}
    if not isinstance(suri_amb, dict):
        suri_amb = {}

    versao = suri_amb.get("versao")
    if versao:
        return str(versao)

    try:
        detectada = obter_versao_suricata()
    except Exception:
        logger.exception("Falha ao consultar versão do Suricata.")
        return None

    if isinstance(detectada, str):
        return detectada.strip() or None

    if isinstance(detectada, dict):
        for chave in ("versao", "version", "valor"):
            valor = detectada.get(chave)
            if valor:
                return str(valor)

    return str(detectada) if detectada else None


def _normalizar_regras_para_painel(status_regras: object) -> dict[str, object]:
    """
    Mantém o payload original de regras e acrescenta aliases estáveis usados
    pelo painel, evitando que diferenças como instalada/instalado quebrem a UI.
    """
    regras = dict(status_regras) if isinstance(status_regras, dict) else {}

    moon_original = regras.get("moonshield")
    moon = dict(moon_original) if isinstance(moon_original, dict) else {}

    moon_instalada = bool(
        moon.get("instaladas", moon.get("instalado", moon.get("instalada", False)))
    )
    moon["instaladas"] = moon_instalada
    moon["instalado"] = moon_instalada
    moon.setdefault("arquivo", moon.get("caminho"))
    moon.setdefault(
        "referenciado",
        bool(moon.get("referenciadas", moon.get("referenciada", moon.get("referenciado", False))))
    )
    moon.setdefault("total", moon.get("total_regras"))

    et_original = regras.get("et_open") or regras.get("etopen")
    et = dict(et_original) if isinstance(et_original, dict) else {}

    et_instalada = bool(
        et.get("instalada", et.get("instalado", et.get("instaladas", False)))
    )
    et["instalada"] = et_instalada
    et["instalado"] = et_instalada
    et.setdefault("arquivo", et.get("caminho"))
    et.setdefault("total", et.get("total_regras"))

    regras["moonshield"] = moon
    regras["et_open"] = et
    regras["moonshield_instalado"] = moon_instalada
    regras["et_open_instalado"] = et_instalada
    return regras


def obter_status_suricata_local(
    configuracao: ConfiguracaoSuricataDados | None = None,
) -> dict[str, object]:
    """Consolida binário, YAML, regras, serviço, EVE e topologia do Suricata."""
    ambiente = detectar_ambiente_completo()
    if not isinstance(ambiente, dict):
        ambiente = {}

    sistema = ambiente.get("sistema") if isinstance(ambiente.get("sistema"), dict) else {}
    suri_amb = ambiente.get("suricata") if isinstance(ambiente.get("suricata"), dict) else {}

    path_yaml = getattr(configuracao, "yaml_path", None) if configuracao else None
    path_eve = getattr(configuracao, "eve_path", None) if configuracao else None

    st_config = obter_status_configuracao(path_yaml)
    if not isinstance(st_config, dict):
        st_config = {}

    st_regras = _normalizar_regras_para_painel(obter_status_regras_completo())

    try:
        topologia_obj = obter_topologia_detectada(incluir_virtuais=True)
        st_topologia = (
            topologia_obj.to_dict()
            if hasattr(topologia_obj, "to_dict")
            else dict(topologia_obj)
            if isinstance(topologia_obj, dict)
            else {}
        )
    except Exception:
        logger.exception("Falha ao detectar topologia para status Suricata.")
        st_topologia = {}

    servicos = obter_status_servicos()
    svc_status = servicos.get("suricata") if isinstance(servicos, dict) else None
    svc_dict = _validar_serializacao_status({"s": svc_status})["s"] if svc_status else {}
    if not isinstance(svc_dict, dict):
        svc_dict = {}

    st_eve = obter_status_eve(path_eve)
    versao = _normalizar_versao_suricata(ambiente)

    is_linux = bool(sistema.get("linux", False))
    is_instalado = bool(suri_amb.get("instalado", False) or versao)
    is_yaml_ok = bool(st_config.get("moonshield_configurado", False))
    is_ativo = bool(svc_dict.get("ativo", False))
    is_regras_ms_ok = bool(st_regras.get("moonshield", {}).get("instaladas", False))

    pronto = bool(
        is_linux
        and is_instalado
        and st_config.get("existe", False)
        and is_yaml_ok
        and is_regras_ms_ok
        and is_ativo
        and st_eve.get("existe", False)
        and st_eve.get("legivel", False)
    )

    if not is_linux:
        status_final = STATUS_ERRO
        mensagem = "O host atual não oferece o ambiente Linux exigido pelo Suricata local."
    elif not is_instalado:
        status_final = STATUS_ERRO
        mensagem = "Binário do Suricata não foi localizado."
    elif not st_config.get("existe", False):
        status_final = STATUS_ERRO
        mensagem = "O arquivo suricata.yaml não foi localizado."
    elif not is_yaml_ok:
        status_final = STATUS_ERRO
        mensagem = "O suricata.yaml existe, mas a configuração MoonShield não está completa."
    elif not is_regras_ms_ok:
        status_final = STATUS_ERRO
        mensagem = "As regras MoonShield não estão instaladas."
    elif not is_ativo:
        status_final = STATUS_ERRO
        mensagem = "O serviço Suricata está parado."
    elif st_eve.get("status") == STATUS_ERRO:
        status_final = STATUS_ERRO
        mensagem = st_eve.get("mensagem") or "O EVE apresenta erro."
    elif st_eve.get("status") == STATUS_AVISO:
        status_final = STATUS_AVISO
        mensagem = st_eve.get("mensagem") or "Suricata ativo com aviso no EVE."
    else:
        status_final = STATUS_OK
        mensagem = "Motor Suricata parametrizado, validado e em execução."

    return {
        "instalado": is_instalado,
        "versao": versao,
        "binario": suri_amb.get("binario"),
        "yaml": st_config,
        "configuracao": st_config.get("analise", {}),
        "regras": st_regras,
        "topologia": st_topologia,
        "servico": svc_dict,
        "eve": st_eve,
        "ativo": is_ativo,
        "configurado": is_yaml_ok,
        "pronto": pronto,
        "status": status_final,
        "mensagem": mensagem,
    }


def _localizar_worker_tarefas(servicos: dict[str, object]) -> dict[str, object]:
    """Localiza o worker de tarefas independentemente do alias usado por servicos.py."""
    if not isinstance(servicos, dict):
        return {}

    for chave in (
        "worker_tarefas",
        "moonshield-suricata-worker",
        "suricata-worker",
        "worker",
    ):
        valor = servicos.get(chave)
        if isinstance(valor, dict):
            return valor

    return {}


def _gerar_resumo_saude(stack: dict[str, object]) -> dict[str, object]:
    """Resumo simples e determinístico para widgets do painel."""
    checks: list[tuple[str, str]] = []

    suri = stack.get("suricata") if isinstance(stack.get("suricata"), dict) else {}
    mon = stack.get("monitor") if isinstance(stack.get("monitor"), dict) else {}
    worker = (
        stack.get("servicos", {}).get("worker_tarefas")
        if isinstance(stack.get("servicos"), dict)
        and isinstance(stack.get("servicos", {}).get("worker_tarefas"), dict)
        else {}
    )

    checks.append(("Suricata", str(suri.get("status", STATUS_DESCONHECIDO))))
    checks.append(("Monitor", str(mon.get("status", STATUS_DESCONHECIDO))))

    eve = mon.get("eve") if isinstance(mon.get("eve"), dict) else {}
    cursor = mon.get("cursor") if isinstance(mon.get("cursor"), dict) else {}
    checks.append(("EVE", str(eve.get("status", STATUS_DESCONHECIDO))))
    checks.append(("Cursor", str(cursor.get("status", STATUS_DESCONHECIDO))))

    if worker:
        worker_status = STATUS_OK if worker.get("ativo") else STATUS_ERRO
        checks.append(("Worker de tarefas", worker_status))

    saudaveis = sum(1 for _, status in checks if status == STATUS_OK)
    avisos = sum(1 for _, status in checks if status == STATUS_AVISO)
    erros = sum(1 for _, status in checks if status == STATUS_ERRO)
    total = len(checks)

    # Score meramente representativo. O status oficial continua sendo stack["status"].
    score = round(((saudaveis + avisos * 0.5) / total) * 100) if total else 0

    return {
        "total": total,
        "saudaveis": saudaveis,
        "avisos": avisos,
        "erros": erros,
        "score": score,
        "itens": [{"nome": nome, "status": status} for nome, status in checks],
    }


def obter_status_stack_completo(
    configuracao: ConfiguracaoSuricataDados | None = None,
    cursor_path: str | Path | None = None,
    base_dir: str | Path | None = None,
    incluir_diagnostico: bool = False,
) -> dict[str, object]:
    """Gera um único snapshot coerente da stack Suricata para todo o painel."""
    ambiente = detectar_ambiente_completo()

    st_servicos_raw = obter_status_stack()
    st_servicos = _validar_serializacao_status(st_servicos_raw) if isinstance(st_servicos_raw, dict) else {}

    # Normaliza o alias do worker para o frontend.
    worker = _localizar_worker_tarefas(st_servicos)
    if worker:
        st_servicos["worker_tarefas"] = worker

    st_suri = obter_status_suricata_local(configuracao)
    st_mon = obter_status_monitor_local(
        eve_path=getattr(configuracao, "eve_path", None) if configuracao else None,
        cursor_path=cursor_path,
        base_dir=base_dir,
    )

    stack_ativa = bool(st_suri.get("ativo") and st_mon.get("ativo"))
    monitor_instalado = bool(
        st_mon.get("instalado")
        or (
            isinstance(st_mon.get("servico"), dict)
            and st_mon["servico"].get("instalado")
        )
    )

    worker_conhecido = bool(worker)
    worker_instalado = bool(worker.get("instalado", True)) if worker_conhecido else True
    worker_ativo = bool(worker.get("ativo", False)) if worker_conhecido else True

    stack_pronta = bool(
        st_suri.get("pronto")
        and monitor_instalado
        and worker_instalado
    )

    avisos: list[str] = []
    erros: list[str] = []

    if st_suri.get("status") == STATUS_ERRO:
        erros.append(f"Suricata: {st_suri.get('mensagem', 'falha não detalhada')}")
    elif st_suri.get("status") == STATUS_AVISO:
        avisos.append(f"Suricata: {st_suri.get('mensagem', 'aviso não detalhado')}")

    if st_mon.get("status") == STATUS_ERRO:
        erros.append(f"Monitor: {st_mon.get('mensagem', 'falha não detalhada')}")
    elif st_mon.get("status") == STATUS_AVISO:
        avisos.append(f"Monitor: {st_mon.get('mensagem', 'aviso não detalhado')}")

    if worker_conhecido:
        if not worker_instalado:
            avisos.append("Worker de tarefas do Suricata não está instalado.")
        elif not worker_ativo:
            avisos.append("Worker de tarefas do Suricata está parado.")

    if stack_ativa and not st_mon.get("lendo_eve"):
        avisos.append("Os serviços estão ativos, porém o monitor não confirmou leitura contínua do EVE.")

    status_final = calcular_status_geral(erros, avisos, stack_ativa)

    saudavel = bool(
        status_final == STATUS_OK
        and stack_ativa
        and stack_pronta
        and st_mon.get("saudavel")
        and st_suri.get("pronto")
    )

    if status_final == STATUS_OK:
        mensagem = "Stack Suricata operacional e sincronizada."
    elif status_final == STATUS_AVISO:
        mensagem = "Stack Suricata operacional, mas existem pontos que exigem atenção."
    elif status_final == STATUS_ERRO:
        mensagem = "Stack Suricata apresenta falhas que exigem intervenção."
    else:
        mensagem = gerar_mensagem_status(status_final, "Stack Suricata")

    dados: dict[str, object] = {
        "suricata": st_suri,
        "monitor": st_mon,
        "servicos": st_servicos,
        "ambiente": ambiente,
        "diagnostico": None,
        "stack_ativa": stack_ativa,
        "stack_pronta": stack_pronta,
        "saudavel": saudavel,
        "status": status_final,
        "mensagem": mensagem,
        "avisos": avisos,
        "erros": erros,
        "verificado_em": datetime.now().astimezone().isoformat(),
    }

    dados["resumo_saude"] = _gerar_resumo_saude(dados)

    if incluir_diagnostico:
        dados["diagnostico"] = _validar_serializacao_status(
            executar_diagnostico_resumido(configuracao)
        )

    return _validar_serializacao_status(dados)

def calcular_status_geral(erros: list[str], avisos: list[str], ativo: bool) -> str:
    """Padroniza a resposta de macro-status visual a ser enviada ao frontend."""
    if erros:
        return STATUS_ERRO
    if avisos:
        return STATUS_AVISO
    if ativo:
        return STATUS_OK
    return STATUS_DESATIVADO


def gerar_mensagem_status(status: str, contexto: str = "Suricata") -> str:
    """Tradução do enum semântico em sentenças amigáveis para UI."""
    if status == STATUS_OK:
        return f"{contexto} está funcionando normalmente."
    if status == STATUS_AVISO:
        return f"{contexto} está ativo, mas possui avisos pendentes."
    if status == STATUS_ERRO:
        return f"{contexto} apresenta problemas críticos que precisam de atenção."
    if status == STATUS_DESATIVADO:
        return f"{contexto} encontra-se desativado."
    return f"Não foi possível determinar o estado do componente {contexto}."



def obter_resumo_cards(
    configuracao: ConfiguracaoSuricataDados | None = None,
    status_stack: dict[str, object] | None = None,
) -> dict[str, object]:
    """Gera cards usando exatamente o mesmo snapshot da API quando fornecido."""
    st_stack = status_stack or obter_status_stack_completo(configuracao)

    st_s = st_stack.get("suricata", {})
    st_m = st_stack.get("monitor", {})
    regras = st_s.get("regras", {}) if isinstance(st_s, dict) else {}
    moon = regras.get("moonshield", {}) if isinstance(regras, dict) else {}
    et = regras.get("et_open", {}) if isinstance(regras, dict) else {}

    moon_ok = bool(
        moon.get("instaladas", moon.get("instalado", False))
        if isinstance(moon, dict)
        else False
    )
    et_ok = bool(
        et.get("instalada", et.get("instalado", False))
        if isinstance(et, dict)
        else False
    )

    eve = st_m.get("eve", {}) if isinstance(st_m, dict) else {}

    return {
        "suricata": {
            "titulo": "Suricata",
            "status": st_s.get("status", STATUS_DESCONHECIDO),
            "valor": "Ativo" if st_s.get("ativo") else "Inativo",
            "detalhe": (
                f"Suricata {st_s.get('versao')}"
                if st_s.get("versao")
                else "Versão não identificada"
            ),
            "icone": "shield",
        },
        "monitor": {
            "titulo": "Monitor",
            "status": st_m.get("status", STATUS_DESCONHECIDO),
            "valor": "Ativo" if st_m.get("ativo") else "Inativo",
            "detalhe": "Lendo eve.json" if st_m.get("lendo_eve") else "Leitura não confirmada",
            "icone": "activity",
        },
        "eve": {
            "titulo": "EVE JSON",
            "status": eve.get("status", STATUS_DESCONHECIDO),
            "valor": "Atualizando" if eve.get("atualizando") else "Sem atualização recente",
            "detalhe": (
                f"Idade {int(eve['idade_segundos'])}s"
                if eve.get("idade_segundos") is not None
                else "Idade desconhecida"
            ),
            "icone": "file-text",
        },
        "regras": {
            "titulo": "Regras",
            "status": STATUS_OK if moon_ok and et_ok else STATUS_AVISO if moon_ok else STATUS_ERRO,
            "valor": "Carregadas" if moon_ok else "Ausentes",
            "detalhe": "MoonShield + ET Open" if et_ok else "Somente MoonShield",
            "icone": "list",
        },
    }


def obter_status_onboarding(
    configuracao: ConfiguracaoSuricataDados | None = None,
    status_stack: dict[str, object] | None = None,
) -> dict[str, object]:
    """Determina o estado do onboarding sem executar diagnóstico profundo."""
    st = status_stack or obter_status_stack_completo(
        configuracao,
        incluir_diagnostico=False,
    )

    amb = st.get("ambiente", {})
    suri = st.get("suricata", {})

    etapas = {
        "verificar_ambiente": {"concluida": False, "disponivel": True, "status": STATUS_ERRO},
        "selecionar_topologia": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "configurar_interfaces": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "instalar_regras": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "configurar_suricata": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "iniciar_servicos": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "validar_instalacao": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
    }

    sistema = amb.get("sistema", {}) if isinstance(amb, dict) else {}

    if not (sistema.get("linux") and sistema.get("root")):
        return {
            "concluido": False,
            "etapa_atual": "verificar_ambiente",
            "etapas": etapas,
            "proxima_acao": "Corrigir ambiente Linux/permissões.",
            "bloqueios": ["Ambiente Linux/root não confirmado."],
            "avisos": [],
        }

    etapas["verificar_ambiente"].update(concluida=True, status=STATUS_OK)
    etapas["selecionar_topologia"]["disponivel"] = True

    topologia = suri.get("topologia", {}) if isinstance(suri, dict) else {}
    tem_wan = bool(
        topologia.get("wan_sugerida")
        or getattr(configuracao, "interface_wan", None)
    )
    tem_lan = bool(
        topologia.get("lan_sugerida")
        or getattr(configuracao, "interface_lan", None)
    )

    if not (tem_wan and tem_lan):
        return {
            "concluido": False,
            "etapa_atual": "selecionar_topologia",
            "etapas": etapas,
            "proxima_acao": "Definir WAN e LAN.",
            "bloqueios": [],
            "avisos": [],
        }

    etapas["selecionar_topologia"].update(concluida=True, status=STATUS_OK)
    etapas["configurar_interfaces"]["disponivel"] = True

    interfaces_ok = bool(
        configuracao
        and getattr(configuracao, "interfaces_monitoradas", None)
        and getattr(configuracao, "home_net", None)
    )
    if not interfaces_ok:
        return {
            "concluido": False,
            "etapa_atual": "configurar_interfaces",
            "etapas": etapas,
            "proxima_acao": "Revisar interfaces monitoradas e HOME_NET.",
            "bloqueios": [],
            "avisos": [],
        }

    etapas["configurar_interfaces"].update(concluida=True, status=STATUS_OK)
    etapas["instalar_regras"]["disponivel"] = True

    moon = (
        suri.get("regras", {}).get("moonshield", {})
        if isinstance(suri, dict)
        else {}
    )
    if not moon.get("instaladas", moon.get("instalado", False)):
        return {
            "concluido": False,
            "etapa_atual": "instalar_regras",
            "etapas": etapas,
            "proxima_acao": "Instalar regras MoonShield.",
            "bloqueios": [],
            "avisos": [],
        }

    etapas["instalar_regras"].update(concluida=True, status=STATUS_OK)
    etapas["configurar_suricata"]["disponivel"] = True

    if not suri.get("configurado"):
        return {
            "concluido": False,
            "etapa_atual": "configurar_suricata",
            "etapas": etapas,
            "proxima_acao": "Aplicar configuração do Suricata.",
            "bloqueios": [],
            "avisos": [],
        }

    etapas["configurar_suricata"].update(concluida=True, status=STATUS_OK)
    etapas["iniciar_servicos"]["disponivel"] = True

    if not st.get("stack_ativa"):
        return {
            "concluido": False,
            "etapa_atual": "iniciar_servicos",
            "etapas": etapas,
            "proxima_acao": "Iniciar Suricata e monitor.",
            "bloqueios": [],
            "avisos": [],
        }

    etapas["iniciar_servicos"].update(concluida=True, status=STATUS_OK)
    etapas["validar_instalacao"]["disponivel"] = True

    # A conclusão formal continua sendo persistida pela view/modelo.
    onboarding_persistido = bool(
        getattr(configuracao, "onboarding_concluido", False)
        if configuracao
        else False
    )
    instalacao_persistida = bool(
        getattr(configuracao, "instalacao_concluida", False)
        if configuracao
        else False
    )

    if onboarding_persistido and instalacao_persistida and st.get("stack_pronta"):
        etapas["validar_instalacao"].update(concluida=True, status=STATUS_OK)
        return {
            "concluido": True,
            "etapa_atual": "concluido",
            "etapas": etapas,
            "proxima_acao": "Monitorar tráfego.",
            "bloqueios": [],
            "avisos": [],
        }

    return {
        "concluido": False,
        "etapa_atual": "validar_instalacao",
        "etapas": etapas,
        "proxima_acao": "Concluir a validação final do onboarding.",
        "bloqueios": [],
        "avisos": [
            "A validação profunda não é executada automaticamente pelo endpoint de status."
        ],
    }


def obter_status_para_api(
    configuracao: ConfiguracaoSuricataDados | None = None,
    incluir_diagnostico: bool = False,
) -> dict[str, object]:
    """
    Payload oficial do painel Suricata.

    Um único snapshot alimenta stack, cards e onboarding, evitando que a mesma
    requisição exiba estados divergentes por consultar o SO várias vezes.
    """
    try:
        st = obter_status_stack_completo(
            configuracao,
            incluir_diagnostico=incluir_diagnostico,
        )

        cards = obter_resumo_cards(
            configuracao,
            status_stack=st,
        )

        onboarding = obter_status_onboarding(
            configuracao,
            status_stack=st,
        )

        config_serializada = None
        if configuracao is not None:
            config_serializada = _validar_serializacao_status(
                {"configuracao": configuracao}
            ).get("configuracao")

        return {
            "ok": True,
            "status": st.get("status", STATUS_DESCONHECIDO),
            "mensagem": st.get("mensagem", ""),
            "dados": _validar_serializacao_status(
                {
                    "stack": st,
                    "cards": cards,
                    "onboarding": onboarding,
                    "configuracao": config_serializada,
                    "resumo_saude": st.get("resumo_saude", {}),
                    "verificado_em": st.get("verificado_em"),
                }
            ),
        }

    except Exception:
        logger.exception("Falha ao gerar payload de status da stack Suricata.")
        return {
            "ok": False,
            "status": STATUS_ERRO,
            "mensagem": "Erro interno ao coletar o estado da stack Suricata.",
            "dados": {},
        }

def obter_status_sensores() -> list[dict[str, object]]:
    """Gera um Mock-Up dinâmico (Memory DB) de um objeto 'Sensor' equivalente a API Remote antiga."""
    st = obter_status_stack_completo()
    suri = st["suricata"]
    mon = st["monitor"]

    online = (mon["ativo"] and mon["lendo_eve"])
    last_act = "-"
    
    if st["ambiente"]["sistema"]["linux"]:
        eve_age = mon["eve"]["idade_segundos"]
        if eve_age is not None:
            # Reverte pra timestamp simples, o JS/Frontend costuma tratar. Formato legível pra backup
            dt = datetime.fromtimestamp(datetime.now().timestamp() - eve_age)
            last_act = dt.isoformat()

    # Define a inteface principal representativa
    iface_main = "local_node"
    if suri["topologia"].get("lan_sugerida"):
        iface_main = suri["topologia"]["lan_sugerida"]
        
    return [{
        "id": "suricata-local",
        "nome": "Suricata Local",
        "tipo": "suricata",
        "online": online,
        "status": STATUS_OK if online else STATUS_AVISO,
        "interface": iface_main,
        "interfaces": [iface["nome"] for iface in suri["topologia"].get("interfaces", [])],
        "ultima_atividade": last_act,
        "eventos": None,
        "detalhes": {
            "motor": "suricata",
            "host_os": st["ambiente"]["sistema"]["nome"]
        },
    }]


def gerar_checks_status(configuracao: ConfiguracaoSuricataDados | None = None) -> list[DiagnosticoItem]:
    """Cria os checks high-level do painel de operações, abstraindo a tecnicalidade do Diagnostico bruto."""
    st = obter_status_stack_completo(configuracao)
    itens = []
    
    itens.append(DiagnosticoItem(
        id="stack_suricata_ativa", grupo="Status Geral", titulo="Daemons de Monitoramento Ativos",
        ok=st["stack_ativa"], detalhe="Serviços subiram com sucesso." if st["stack_ativa"] else "Mecanismo parado.",
        acao="Ative o conjunto C + Python", critico=True
    ))

    itens.append(DiagnosticoItem(
        id="stack_suricata_pronta", grupo="Status Geral", titulo="Arquitetura Geral",
        ok=st["stack_pronta"], detalhe="Todos os bins e scripts injetados." if st["stack_pronta"] else "Existem dependências não instaladas.",
        acao="Complete a fase técnica do painel.", critico=True
    ))

    eve = st["monitor"]["eve"]
    itens.append(DiagnosticoItem(
        id="eve_atualizando", grupo="Status Geral", titulo="Captura de Tráfego de Rede",
        ok=eve["atualizando"], detalhe="Processando tráfego real." if eve["atualizando"] else "Ociosidade (Normal em Labs).",
        acao="Dê ping em alvos externos pra confirmar." if not eve["atualizando"] else "", critico=False
    ))

    cur = st["monitor"]["cursor"]
    itens.append(DiagnosticoItem(
        id="cursor_acompanhando", grupo="Status Geral", titulo="Fila de Conversão Local",
        ok=cur["acompanhando"], detalhe="Fila em dia." if cur["acompanhando"] else "Backlog gerado, ingerindo lotes pendentes.",
        acao="Aguarde o zeramento do offset caso um atraso exista." if not cur["acompanhando"] else "", critico=False
    ))

    itens.append(DiagnosticoItem(
        id="configuracao_pronta", grupo="Status Geral", titulo="Mestre YAML Customizado",
        ok=st["suricata"]["configurado"], detalhe="Padrão MoonShield Ativo.", acao="", critico=True
    ))

    itens.append(DiagnosticoItem(
        id="regras_prontas", grupo="Status Geral", titulo="Threat Intelligence (Regras)",
        ok=st["suricata"]["regras"]["moonshield"]["instaladas"], detalhe="Drop False-Positive habilitados.", acao="", critico=True
    ))

    return itens


# ==============================================================================
# COMPATIBILIDADE (LEGACY V1 BRIDGE)
# ==============================================================================

def obter_status_legado(configuracao: ConfiguracaoSuricataDados | None = None) -> dict[str, object]:
    """Adapter Wrapper que emula o formato exato esperado pela View Django antiga do Moonshield V1."""
    novo_st = obter_status_stack_completo(configuracao)
    
    return _validar_serializacao_status({
        "ativo": novo_st["suricata"]["ativo"],
        "instalado": novo_st["suricata"]["instalado"],
        "status": novo_st["status"],
        "versao": novo_st["suricata"]["versao"] or "Desconhecido",
        "servico": "ativo" if novo_st["suricata"]["ativo"] else "inativo",
        "eve": {
            "existe": novo_st["monitor"]["eve"]["existe"],
            "tamanho": novo_st["monitor"]["eve"]["tamanho"],
            "atualizado": novo_st["monitor"]["eve"]["atualizando"]
        },
        "monitor": {
            "ativo": novo_st["monitor"]["ativo"],
            "cursor": novo_st["monitor"]["cursor"]["posicao"],
            "saudavel": novo_st["monitor"]["saudavel"]
        },
        "mensagem": novo_st["mensagem"],
        "erro": novo_st["erros"][0] if novo_st["erros"] else "",
        
        # O "novo mundo" inserido de forma aninhada como fallback incremental
        "novo_status": novo_st
    })