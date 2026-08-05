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


def ler_cursor(cursor_path: str | Path) -> int | None:
    """Extrai apenas a posição do offset numérico bruto do payload JSON de cursor."""
    path_obj = Path(cursor_path)
    if not path_obj.is_file() or not os.access(path_obj, os.R_OK):
        return None
        
    try:
        # Lê apenas uma pequena porção do arquivo (por segurança contra injection via FS local)
        with open(path_obj, "r", encoding="utf-8", errors="ignore") as f:
            conteudo = f.read(128)
            dados = json.loads(conteudo)
            offset = dados.get("offset")
            if isinstance(offset, int) and offset >= 0:
                return offset
    except Exception:
        pass
        
    return None


def obter_status_cursor(cursor_path: str | Path, eve_path: str | Path) -> dict[str, object]:
    """Correlaciona o ponteiro lógico do worker Django com a realidade física do log EVE."""
    info = {
        "caminho": str(cursor_path),
        "existe": False,
        "legivel": False,
        "posicao": 0,
        "tamanho_eve": 0,
        "atraso_bytes": 0,
        "idade_segundos": 0.0,
        "valido": False,
        "acompanhando": False,
        "status": STATUS_OK,
        "mensagem": "Cursor perfeitamente sincronizado com o fluxo de eventos.",
    }

    st_cursor = obter_status_arquivo(cursor_path)
    info["existe"] = st_cursor["existe"]
    info["legivel"] = st_cursor["legivel"]
    info["idade_segundos"] = st_cursor["idade_segundos"] or 0.0

    st_eve = obter_status_arquivo(eve_path)
    info["tamanho_eve"] = st_eve["tamanho"]
    
    if not info["existe"]:
        info["status"] = STATUS_AVISO
        info["mensagem"] = "Cursor ainda não criado. O monitor lerá do final quando acionado."
        return info

    pos = ler_cursor(cursor_path)
    if pos is None:
        info["status"] = STATUS_ERRO
        info["mensagem"] = "O arquivo de cursor está corrompido ou possui um valor ilegítimo."
        return info

    info["valido"] = True
    info["posicao"] = pos
    
    info["atraso_bytes"] = info["tamanho_eve"] - info["posicao"]
    
    # Validações semânticas de sincronia
    if info["posicao"] > info["tamanho_eve"] and info["tamanho_eve"] > 0:
        info["status"] = STATUS_ERRO
        info["mensagem"] = "Inconsistência fatal: Offset do cursor ultrapassa o tamanho do arquivo EVE atual."
    elif info["atraso_bytes"] > LIMITE_ATRASO_CURSOR_BYTES:
        info["status"] = STATUS_AVISO
        info["mensagem"] = f"Atraso acentuado de ingestão: {info['atraso_bytes'] // 1024 // 1024} MB represados na fila."
    elif st_eve["idade_segundos"] is not None and st_eve["idade_segundos"] < 10 and info["idade_segundos"] > 60:
         info["status"] = STATUS_ERRO
         info["mensagem"] = "Log sendo bombardeado ativamente mas o cursor não evolui (O worker parece ter travado)."
    else:
         info["acompanhando"] = True

    return info


def obter_status_monitor_local(
    eve_path: str | Path | None = None,
    cursor_path: str | Path | None = None,
    base_dir: str | Path | None = None,
) -> dict[str, object]:
    """Calcula a saúde holística e unificada apenas da parcela consumidora do cluster."""
    svc_status = obter_status_servicos().get("moonshield-suricata-monitor")
    # Caso a busca retorne dict (por conta da serialização final) ou objeto
    svc_dict = _validar_serializacao_status({"s": svc_status})["s"] if svc_status else {}
    
    caminho_eve = eve_path or localizar_eve_json() or EVE_JSON_PADRAO
    caminho_cur = obter_caminho_cursor(cursor_path, base_dir)
    
    st_eve = obter_status_eve(caminho_eve)
    st_cur = obter_status_cursor(caminho_cur, caminho_eve)
    
    is_ativo = svc_dict.get("ativo", False)
    is_instalado = svc_dict.get("instalado", False)

    saudavel = (
        is_instalado and 
        is_ativo and 
        st_eve["status"] in (STATUS_OK, STATUS_AVISO) and 
        st_cur["status"] in (STATUS_OK, STATUS_AVISO) and
        st_cur["acompanhando"]
    )

    info = {
        "servico": svc_dict,
        "eve": st_eve,
        "cursor": st_cur,
        "ativo": is_ativo,
        "lendo_eve": st_cur["acompanhando"],
        "saudavel": saudavel,
        "status": STATUS_OK if saudavel else STATUS_ERRO,
        "mensagem": "Worker em plena operação.",
    }

    if not is_instalado:
        info["status"] = STATUS_ERRO
        info["mensagem"] = "Serviço do worker não implantado no sistema."
    elif not is_ativo:
        info["status"] = STATUS_ERRO
        info["mensagem"] = "O serviço de monitoramento não está executando no systemd."
    elif not st_cur["existe"]:
        info["status"] = STATUS_AVISO
        info["mensagem"] = "O monitor está ativo mas ainda aguarda a chegada dos primeiros pacotes para registrar o offset no cursor."

    return info


def obter_status_suricata_local(configuracao: ConfiguracaoSuricataDados | None = None) -> dict[str, object]:
    """Compila e avalia unicamente o braço produtor e de inteligência do cluster."""
    ambiente = detectar_ambiente_completo()
    
    path_yaml = configuracao.yaml_path if configuracao else None
    
    st_config = obter_status_configuracao(path_yaml)
    st_regras = obter_status_regras_completo()
    st_topologia = obter_topologia_detectada(incluir_virtuais=True).to_dict()
    
    svc_status = obter_status_servicos().get("suricata")
    svc_dict = _validar_serializacao_status({"s": svc_status})["s"] if svc_status else {}
    
    path_eve = configuracao.eve_path if configuracao else None
    st_eve = obter_status_eve(path_eve)

    is_instalado = ambiente["suricata"]["instalado"]
    is_yaml_ok = st_config["moonshield_configurado"]
    is_ativo = svc_dict.get("ativo", False)
    is_regras_ms_ok = st_regras["moonshield"]["instaladas"]
    
    pronto = (
        ambiente["sistema"]["linux"] and
        is_instalado and
        st_config["existe"] and
        is_yaml_ok and
        is_regras_ms_ok and
        is_ativo and
        st_eve["existe"] and st_eve["legivel"]
    )

    status_final = STATUS_OK
    msg_final = "Motor Suricata está parametrizado, validado e rodando."

    if not ambiente["sistema"]["linux"]:
        status_final = STATUS_ERRO
        msg_final = "Sistema host não compatível com o binário nativo Suricata."
    elif not is_instalado:
        status_final = STATUS_ERRO
        msg_final = "Binário Core do Suricata não localizado no PATH."
    elif not st_config["existe"]:
        status_final = STATUS_ERRO
        msg_final = "O suricata.yaml mestre não foi achado."
    elif not is_yaml_ok:
        status_final = STATUS_ERRO
        msg_final = "Divergência técnica no arquivo de configuração do IDS perante as necessidades do MS."
    elif not is_regras_ms_ok:
        status_final = STATUS_ERRO
        msg_final = "O core ruleset do MoonShield não está acoplado."
    elif not is_ativo:
        status_final = STATUS_ERRO
        msg_final = "Daemon primário desativado ou crashado."

    return {
        "instalado": is_instalado,
        "versao": ambiente["suricata"]["versao"],
        "binario": ambiente["suricata"]["binario"],
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
        "mensagem": msg_final,
    }


def obter_status_stack_completo(
    configuracao: ConfiguracaoSuricataDados | None = None,
    cursor_path: str | Path | None = None,
    base_dir: str | Path | None = None,
    incluir_diagnostico: bool = False,
) -> dict[str, object]:
    """Combina todas as pernas lógicas gerando o Master-Status API Payload da aplicação local."""
    ambiente = detectar_ambiente_completo()
    st_servicos = obter_status_stack()
    
    st_suri = obter_status_suricata_local(configuracao)
    st_mon = obter_status_monitor_local(
        eve_path=configuracao.eve_path if configuracao else None,
        cursor_path=cursor_path,
        base_dir=base_dir
    )

    stack_ativa = st_suri["ativo"] and st_mon["ativo"]
    stack_pronta = st_suri["pronto"] and st_mon["servico"]["instalado"]
    
    saudavel = stack_ativa and st_suri["eve"]["atualizando"] and st_mon["cursor"]["acompanhando"]

    avisos = []
    erros = []
    
    if st_suri["status"] == STATUS_ERRO:
        erros.append(f"Problemas no Motor IDS: {st_suri['mensagem']}")
    elif st_suri["status"] == STATUS_AVISO:
        avisos.append(st_suri["mensagem"])

    if st_mon["status"] == STATUS_ERRO:
        erros.append(f"Problemas no Integrador de Dados: {st_mon['mensagem']}")
    elif st_mon["status"] == STATUS_AVISO:
        avisos.append(st_mon["mensagem"])

    if stack_ativa and not saudavel:
        avisos.append("Os serviços constam operantes, porém os arquivos indicam ociosidade e falta de tráfego de ingestão.")

    status_final = calcular_status_geral(erros, avisos, stack_ativa)
    msg_final = gerar_mensagem_status(status_final, "Stack Integradora")

    dados = {
        "suricata": st_suri,
        "monitor": st_mon,
        "servicos": _validar_serializacao_status(st_servicos),
        "ambiente": ambiente,
        "diagnostico": None,
        "stack_ativa": stack_ativa,
        "stack_pronta": stack_pronta,
        "saudavel": saudavel,
        "status": status_final,
        "mensagem": msg_final,
        "avisos": avisos,
        "erros": erros,
        "verificado_em": datetime.now().isoformat(),
    }

    if incluir_diagnostico:
        c_eve = configuracao.eve_path if configuracao else None
        c_yaml = configuracao.yaml_path if configuracao else None
        c_cur = obter_caminho_cursor(cursor_path, base_dir)
        dados["diagnostico"] = _validar_serializacao_status(executar_diagnostico_resumido(configuracao))

    return _validar_serializacao_status(dados)


# ==============================================================================
# LÓGICAS COMERCIAIS / FRONTEND UI HELPERS
# ==============================================================================

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


def obter_resumo_cards(configuracao: ConfiguracaoSuricataDados | None = None) -> dict[str, object]:
    """Formatações simplificadas para alimentar diretamente Dashboards ou Widgets."""
    st_stack = obter_status_stack_completo(configuracao)
    
    st_s = st_stack["suricata"]
    st_m = st_stack["monitor"]

    cards = {
        "suricata": {
            "titulo": "Suricata",
            "status": st_s["status"],
            "valor": "Ativo" if st_s["ativo"] else "Inativo",
            "detalhe": f"Motor {st_s['versao']}" if st_s["versao"] else "Não detectado",
            "icone": "shield",
        },
        "monitor": {
            "titulo": "Monitor",
            "status": st_m["status"],
            "valor": "Ativo" if st_m["ativo"] else "Inativo",
            "detalhe": "Lendo eve.json" if st_m["lendo_eve"] else "Sem leitura ativa",
            "icone": "activity",
        },
        "eve": {
            "titulo": "EVE JSON",
            "status": st_m["eve"]["status"],
            "valor": "Atualizando" if st_m["eve"]["atualizando"] else "Paralisado",
            "detalhe": f"Idade {int(st_m['eve']['idade_segundos'])}s" if st_m["eve"]["idade_segundos"] is not None else "Desconhecido",
            "icone": "file-text",
        },
        "regras": {
            "titulo": "Regras",
            "status": STATUS_OK if st_s["regras"]["moonshield"]["instaladas"] else STATUS_ERRO,
            "valor": "Carregadas" if st_s["regras"]["moonshield"]["instaladas"] else "Ausentes",
            "detalhe": "MS + ET Open" if st_s["regras"]["et_open"]["instalada"] else "Somente MS",
            "icone": "list",
        },
    }
    return cards


def obter_status_onboarding(configuracao: ConfiguracaoSuricataDados | None = None) -> dict[str, object]:
    """Workflow state machine: Decide que tela apresentar pro usario ao clicar para 'Instalar/Configurar'."""
    st = obter_status_stack_completo(configuracao, incluir_diagnostico=True)
    amb = st["ambiente"]
    suri = st["suricata"]

    etapas = {
        "verificar_ambiente": {"concluida": False, "disponivel": True, "status": STATUS_ERRO},
        "selecionar_topologia": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "configurar_interfaces": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "instalar_regras": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "configurar_suricata": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "iniciar_servicos": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
        "validar_instalacao": {"concluida": False, "disponivel": False, "status": STATUS_DESCONHECIDO},
    }

    # 1. Ambiente / Root
    if amb["sistema"]["linux"] and amb["sistema"]["root"]:
        etapas["verificar_ambiente"]["concluida"] = True
        etapas["verificar_ambiente"]["status"] = STATUS_OK
        etapas["selecionar_topologia"]["disponivel"] = True
    else:
        return {"concluido": False, "etapa_atual": "verificar_ambiente", "etapas": etapas, "proxima_acao": "Corrigir ambiente Linux/Root.", "bloqueios": ["Sistema Windows ou acesso negado."], "avisos": []}

    # 2. Topologia Detectada WAN/LAN
    tem_wan = bool(suri["topologia"].get("wan_sugerida"))
    tem_lan = bool(suri["topologia"].get("lan_sugerida"))
    if tem_wan and tem_lan:
        etapas["selecionar_topologia"]["concluida"] = True
        etapas["selecionar_topologia"]["status"] = STATUS_OK
        etapas["configurar_interfaces"]["disponivel"] = True
    else:
        return {"concluido": False, "etapa_atual": "selecionar_topologia", "etapas": etapas, "proxima_acao": "Definir WAN/LAN.", "bloqueios": [], "avisos": []}

    # 3. Interfaces / Configuracao preenchida (Não aplicadas)
    if configuracao and configuracao.interfaces_monitoradas and configuracao.home_net:
        etapas["configurar_interfaces"]["concluida"] = True
        etapas["configurar_interfaces"]["status"] = STATUS_OK
        etapas["instalar_regras"]["disponivel"] = True
    else:
        return {"concluido": False, "etapa_atual": "configurar_interfaces", "etapas": etapas, "proxima_acao": "Revisar/Definir portas AF-Packet.", "bloqueios": [], "avisos": []}

    # 4. Regras (Check físico)
    if suri["regras"]["moonshield"]["instaladas"]:
        etapas["instalar_regras"]["concluida"] = True
        etapas["instalar_regras"]["status"] = STATUS_OK
        etapas["configurar_suricata"]["disponivel"] = True
    else:
        return {"concluido": False, "etapa_atual": "instalar_regras", "etapas": etapas, "proxima_acao": "Descarregar regras para o SO.", "bloqueios": [], "avisos": []}

    # 5. Configuração Suricata (YAML)
    if suri["configurado"]:
        etapas["configurar_suricata"]["concluida"] = True
        etapas["configurar_suricata"]["status"] = STATUS_OK
        etapas["iniciar_servicos"]["disponivel"] = True
    else:
        return {"concluido": False, "etapa_atual": "configurar_suricata", "etapas": etapas, "proxima_acao": "Injetar patches yaml no SO.", "bloqueios": [], "avisos": []}

    # 6. Serviços
    if st["stack_ativa"]:
        etapas["iniciar_servicos"]["concluida"] = True
        etapas["iniciar_servicos"]["status"] = STATUS_OK
        etapas["validar_instalacao"]["disponivel"] = True
    else:
        return {"concluido": False, "etapa_atual": "iniciar_servicos", "etapas": etapas, "proxima_acao": "Bounce Cluster.", "bloqueios": [], "avisos": []}

    # 7. Diagnóstico Final
    falhas_crit = st.get("diagnostico", {}).get("total_criticos", 1)
    if falhas_crit == 0:
        etapas["validar_instalacao"]["concluida"] = True
        etapas["validar_instalacao"]["status"] = STATUS_OK
        return {"concluido": True, "etapa_atual": "concluido", "etapas": etapas, "proxima_acao": "Monitorar tráfego.", "bloqueios": [], "avisos": []}
    else:
        return {"concluido": False, "etapa_atual": "validar_instalacao", "etapas": etapas, "proxima_acao": "Corrigir Doctor Healthchecks.", "bloqueios": ["Existem anomalias na infraestrutura"], "avisos": []}


def obter_status_para_api(
    configuracao: ConfiguracaoSuricataDados | None = None,
    incluir_diagnostico: bool = False,
) -> dict[str, object]:
    """Monta Payload blindado/higienizado para transpor direto num HttpResponse Django via View."""
    try:
        st = obter_status_stack_completo(configuracao, incluir_diagnostico=incluir_diagnostico)
        cards = obter_resumo_cards(configuracao)
        onb = obter_status_onboarding(configuracao)
        
        return {
            "ok": True,
            "status": st["status"],
            "mensagem": st["mensagem"],
            "dados": _validar_serializacao_status({
                "stack": st,
                "cards": cards,
                "onboarding": onb,
            })
        }
    except Exception as e:
        logger.exception("Catástrofe ao gerar payload de status API Suricata.")
        return {
            "ok": False,
            "status": STATUS_ERRO,
            "mensagem": "Erro interno do servidor ao colher telemetria.",
            "dados": {}
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