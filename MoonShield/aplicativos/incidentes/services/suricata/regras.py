"""
Módulo responsável pela orquestração, sincronização e auditoria das assinaturas IDS.
Gerencia tanto o conjunto interno de regras MoonShield quanto as dependências
da fundação ET Open via suricata-update, operando de forma passiva e segura.
"""

import os
import re
import hashlib
import shutil
import logging
from pathlib import Path
from datetime import datetime

from .tipos import (
    ResultadoEtapa,
    StatusEtapa,
    NivelLog,
    DiagnosticoItem,
)
from .comandos import (
    executar_comando,
    comando_existe,
    localizar_comando,
)
from .ambiente import (
    detectar_gerenciador_pacotes,
    obter_comando_instalacao,
    localizar_suricata_yaml,
    eh_linux,
    usuario_e_root,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES
# ==============================================================================

REGRAS_DEST_DIR = Path("/var/lib/suricata/rules/moonshield")
REGRAS_DEST = REGRAS_DEST_DIR / "ms.rules"

REGRAS_DEST_ETC_DIR = Path("/etc/suricata/rules/moonshield")
REGRAS_DEST_ETC = REGRAS_DEST_ETC_DIR / "ms.rules"

REGRAS_ET_OPEN = Path("/var/lib/suricata/rules/suricata.rules")
REGRAS_ET_OPEN_ETC = Path("/etc/suricata/rules/suricata.rules")

FONTES_SURICATA_UPDATE = ("et/open",)
NOME_FONTE_ET_OPEN = "et/open"

TAMANHO_MAXIMO_REGRAS = 50 * 1024 * 1024  # 50 MB
PERMISSAO_PADRAO_REGRAS = 0o644


# ==============================================================================
# LEITURA E VALIDAÇÃO DE ARQUIVOS (HELPERS)
# ==============================================================================

def localizar_regras_moonshield_origem(caminho_preferido: str | Path | None = None) -> Path | None:
    """Busca o arquivo de assinaturas nativo do MoonShield no repositório."""
    if caminho_preferido:
        p = Path(caminho_preferido)
        if p.is_file():
            return p

    base_dir = Path(__file__).resolve().parent

    candidatos = [
        base_dir / "regras_ms.rules",
        base_dir / "ms.rules",
        base_dir / "rules" / "ms.rules",
        base_dir / "assets" / "ms.rules",
        base_dir.parent.parent.parent / "MoonShield-Agent" / "suricata" / "regras_ms.rules",
    ]

    for cand in candidatos:
        if cand.is_file():
            return cand

    return None


def arquivo_regras_valido(caminho: str | Path) -> tuple[bool, str]:
    """Checa se o arquivo preenche requisitos básicos de uma coleção de regras Suricata."""
    path_obj = Path(caminho)

    if not path_obj.exists():
        return False, "Arquivo não existe."
    if not path_obj.is_file():
        return False, "Caminho não é um arquivo."
    if not os.access(path_obj, os.R_OK):
        return False, "Arquivo sem permissão de leitura."

    tamanho = path_obj.stat().st_size
    if tamanho == 0:
        return False, "Arquivo de regras vazio."
    if tamanho > TAMANHO_MAXIMO_REGRAS:
        return False, f"Arquivo excede limite de segurança ({TAMANHO_MAXIMO_REGRAS} bytes)."

    # Análise sintática superficial (evita carregar 50MB inteiros se não precisar)
    valido = False
    try:
        with open(path_obj, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(5000):  # Testa o topo buscando padrões óbvios
                linha = f.readline()
                if not linha:
                    break
                linha = linha.strip()
                if not linha or linha.startswith("#"):
                    continue
                if "sid:" in linha and "msg:" in linha and "(" in linha and ")" in linha:
                    valido = True
                    break
    except Exception as e:
        return False, f"Falha na leitura do arquivo: {str(e)}"

    if valido:
        return True, "Arquivo contém estrutura aparentemente válida."
    return False, "Nenhuma assinatura IDS padrão identificada no arquivo."


def calcular_hash_arquivo(caminho: str | Path, algoritmo: str = "sha256") -> str:
    """Retorna o checksum criptográfico seguro de um arquivo (default SHA-256)."""
    permitidos = {"sha256", "sha1", "md5"}
    if algoritmo not in permitidos:
        raise ValueError(f"Algoritmo '{algoritmo}' não permitido.")

    path_obj = Path(caminho)
    if not path_obj.is_file() or not os.access(path_obj, os.R_OK):
        return ""

    hash_func = getattr(hashlib, algoritmo)()
    
    try:
        with open(path_obj, "rb") as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        logger.debug(f"Falha ao processar hash de {caminho}: {e}")
        return ""


def regras_moonshield_instaladas() -> bool:
    """Informa passivamente se os artefatos nativos constam no disco e são válidos."""
    if REGRAS_DEST.exists() and arquivo_regras_valido(REGRAS_DEST)[0]:
        return True
    if REGRAS_DEST_ETC.exists() and arquivo_regras_valido(REGRAS_DEST_ETC)[0]:
        return True
    return False


def contar_regras(caminho: str | Path) -> int:
    """Extrai heurísticamente a volumetria de assinaturas dentro do arquivo."""
    path_obj = Path(caminho)
    if not path_obj.is_file():
        return 0

    try:
        if path_obj.stat().st_size > TAMANHO_MAXIMO_REGRAS:
            return 0
    except OSError:
        return 0

    total = 0
    try:
        with open(path_obj, "r", encoding="utf-8", errors="ignore") as f:
            for linha in f:
                linha = linha.strip()
                if not linha or linha.startswith("#"):
                    continue
                if "sid:" in linha and "msg:" in linha:
                    total += 1
    except Exception as e:
        logger.debug(f"Erro ao contar regras de {caminho}: {e}")
    return total


def listar_sids(caminho: str | Path, limite: int | None = None) -> list[int]:
    """Desempacota a lista de Signature IDs (SIDs) ativos de um arquivo de regras."""
    path_obj = Path(caminho)
    if not path_obj.is_file():
        return []

    sids = set()
    regex_sid = re.compile(r"sid:\s*(\d+)\s*;")

    try:
        with open(path_obj, "r", encoding="utf-8", errors="ignore") as f:
            for linha in f:
                linha = linha.strip()
                if not linha or linha.startswith("#"):
                    continue
                
                match = regex_sid.search(linha)
                if match:
                    sids.add(int(match.group(1)))
                    
                if limite and len(sids) >= limite:
                    break
    except Exception as e:
        logger.debug(f"Erro ao extrair SIDs de {caminho}: {e}")

    return sorted(list(sids))


def _mtime_iso(caminho: str | Path | None) -> str:
    """Retorna a data de modificação de um arquivo em ISO-8601, sem lançar erro."""
    if not caminho:
        return ""
    path_obj = Path(caminho)
    try:
        if path_obj.is_file():
            return datetime.fromtimestamp(path_obj.stat().st_mtime).astimezone().isoformat()
    except OSError:
        pass
    return ""


def obter_referencias_rule_files(
    yaml_path: str | Path | None = None,
) -> dict[str, object]:
    """
    Lê passivamente default-rule-path e rule-files do suricata.yaml.

    Não usa PyYAML de propósito: precisamos apenas das duas diretivas e queremos
    manter este módulo leve, previsível e sem dependência adicional.
    """
    yaml_real = localizar_suricata_yaml(yaml_path)
    resultado = {
        "yaml_path": str(yaml_real) if yaml_real else "",
        "existe": bool(yaml_real and yaml_real.is_file()),
        "default_rule_path": "",
        "rule_files": [],
        "arquivos_resolvidos": [],
    }

    if not yaml_real or not yaml_real.is_file():
        return resultado

    default_rule_path = ""
    rule_files: list[str] = []
    dentro_rule_files = False
    indent_rule_files = -1

    try:
        with open(yaml_real, "r", encoding="utf-8", errors="replace") as f:
            for linha_original in f:
                sem_comentario = linha_original.split("#", 1)[0].rstrip()
                if not sem_comentario.strip():
                    continue

                stripped = sem_comentario.strip()

                match_default = re.match(
                    r"^default-rule-path\s*:\s*(.+?)\s*$",
                    stripped,
                    flags=re.IGNORECASE,
                )
                if match_default:
                    default_rule_path = match_default.group(1).strip().strip("'\"")
                    continue

                indent = len(sem_comentario) - len(sem_comentario.lstrip())

                if re.match(r"^rule-files\s*:\s*$", stripped, flags=re.IGNORECASE):
                    dentro_rule_files = True
                    indent_rule_files = indent
                    continue

                if dentro_rule_files:
                    if indent <= indent_rule_files and not stripped.startswith("-"):
                        dentro_rule_files = False
                    else:
                        match_item = re.match(r"^-\s*(.+?)\s*$", stripped)
                        if match_item:
                            valor = match_item.group(1).strip().strip("'\"")
                            if valor:
                                rule_files.append(valor)
                            continue

    except Exception as e:
        logger.debug("Falha ao interpretar rule-files de %s: %s", yaml_real, e)
        return resultado

    resolvidos = []
    base = Path(default_rule_path) if default_rule_path else None
    for item in rule_files:
        item_path = Path(item)
        if item_path.is_absolute():
            resolvidos.append(str(item_path))
        elif base:
            resolvidos.append(str(base / item_path))
        else:
            resolvidos.append(item)

    resultado.update({
        "default_rule_path": default_rule_path,
        "rule_files": rule_files,
        "arquivos_resolvidos": resolvidos,
    })
    return resultado


def _regra_referenciada(
    referencias: dict[str, object],
    candidatos_relativos: tuple[str, ...],
    candidatos_absolutos: tuple[Path, ...],
) -> tuple[bool, str]:
    """Confere se um artefato aparece efetivamente em rule-files."""
    rule_files = [str(x).strip() for x in referencias.get("rule_files", [])]
    resolvidos = [str(x).strip() for x in referencias.get("arquivos_resolvidos", [])]

    relativos_normalizados = {x.replace("\\", "/") for x in candidatos_relativos}
    absolutos_normalizados = {str(x).replace("\\", "/") for x in candidatos_absolutos}

    for item in rule_files:
        normalizado = item.replace("\\", "/")
        if normalizado in relativos_normalizados:
            return True, item

    for item in resolvidos:
        normalizado = item.replace("\\", "/")
        if normalizado in absolutos_normalizados:
            return True, item

    return False, ""


# ============================================================================== 
# AUDITORIA DE REGRAS E CONFLITOS
# ============================================================================== 

def detectar_sids_duplicados(caminhos: list[str | Path]) -> dict[int, list[str]]:
    """Mapeia assinaturas colidentes que existem em múltiplos arquivos simultâneos."""
    mapa_sids = {}
    
    for caminho in caminhos:
        path_obj = Path(caminho)
        if not path_obj.is_file():
            continue
            
        sids = listar_sids(path_obj)
        for sid in sids:
            mapa_sids.setdefault(sid, []).append(str(path_obj))

    # Filtra apenas aqueles que apareceram em mais de um arquivo
    duplicados = {sid: arquivos for sid, arquivos in mapa_sids.items() if len(arquivos) > 1}
    return dict(sorted(duplicados.items()))


def obter_status_regras_moonshield(
    origem: str | Path | None = None,
    yaml_path: str | Path | None = None,
) -> dict[str, object]:
    """
    Compila o retrato operacional das regras MoonShield.

    Mantém o contrato detalhado antigo (origem/destino_var/destino_etc) e
    acrescenta campos diretos para o painel: arquivo, total, referenciadas,
    sincronizado, status e mensagem.
    """

    def _analisar_ponta(caminho_obj: Path | None, hash_ref: str = "") -> dict[str, object]:
        info: dict[str, object] = {
            "caminho": str(caminho_obj) if caminho_obj else "",
            "existe": False,
            "valido": False,
            "tamanho": 0,
            "hash": "",
            "sincronizado": False,
            "quantidade_regras": 0,
            "total": 0,
            "atualizado_em": "",
        }

        if caminho_obj and caminho_obj.is_file():
            info["existe"] = True
            try:
                info["tamanho"] = caminho_obj.stat().st_size
                valido, _ = arquivo_regras_valido(caminho_obj)
                info["valido"] = valido
                info["atualizado_em"] = _mtime_iso(caminho_obj)

                if valido:
                    h = calcular_hash_arquivo(caminho_obj)
                    qtd = contar_regras(caminho_obj)
                    info["hash"] = h
                    info["quantidade_regras"] = qtd
                    info["total"] = qtd
                    if hash_ref:
                        info["sincronizado"] = h == hash_ref
            except OSError:
                pass

        return info

    path_origem = localizar_regras_moonshield_origem(origem)
    stat_origem = _analisar_ponta(path_origem)
    hash_base = str(stat_origem.get("hash") or "") if stat_origem.get("valido") else ""

    stat_var = _analisar_ponta(REGRAS_DEST, hash_ref=hash_base)
    stat_etc = _analisar_ponta(REGRAS_DEST_ETC, hash_ref=hash_base)

    instaladas = bool(stat_var["valido"] or stat_etc["valido"])

    # O caminho primário de runtime é /var/lib. /etc é mantido como cópia/fallback.
    if stat_var["valido"]:
        ativo = stat_var
    elif stat_etc["valido"]:
        ativo = stat_etc
    else:
        ativo = stat_var if stat_var["existe"] else stat_etc

    referencias = obter_referencias_rule_files(yaml_path)
    referenciadas, referencia_encontrada = _regra_referenciada(
        referencias,
        candidatos_relativos=(
            "moonshield/ms.rules",
            "ms.rules",
        ),
        candidatos_absolutos=(
            REGRAS_DEST,
            REGRAS_DEST_ETC,
        ),
    )

    sincronizado = bool(
        stat_origem["valido"]
        and (
            (stat_var["valido"] and stat_var["sincronizado"])
            or (stat_etc["valido"] and stat_etc["sincronizado"])
        )
    )

    total = int(ativo.get("quantidade_regras") or 0)
    arquivo = str(ativo.get("caminho") or "")
    valido = bool(ativo.get("valido"))
    pronto = bool(instaladas and referenciadas and valido)

    avisos: list[str] = []
    if not stat_origem["valido"]:
        avisos.append("Arquivo original das regras MoonShield ausente ou inválido.")
    if not instaladas:
        avisos.append("Regras MoonShield não estão instaladas em um destino válido.")
    if instaladas and not referenciadas:
        avisos.append("Regras MoonShield estão instaladas, mas não aparecem em rule-files do suricata.yaml.")
    if instaladas and stat_origem["valido"] and not sincronizado:
        avisos.append("A cópia instalada das regras MoonShield difere do artefato original do projeto.")

    status = "ok" if pronto and sincronizado else "warning" if instaladas else "error"
    mensagem = (
        "Regras MoonShield instaladas, referenciadas e sincronizadas."
        if status == "ok"
        else avisos[0] if avisos else "Estado das regras MoonShield requer atenção."
    )

    return {
        # Contrato detalhado legado
        "origem": stat_origem,
        "destino_var": stat_var,
        "destino_etc": stat_etc,

        # Contrato direto/estável para UI e status.py
        "instaladas": instaladas,
        "instalada": instaladas,
        "instalado": instaladas,
        "arquivo": arquivo,
        "caminho": arquivo,
        "valido": valido,
        "referenciadas": referenciadas,
        "referenciada": referenciadas,
        "referenciado": referenciadas,
        "referencia": referencia_encontrada,
        "total": total,
        "quantidade_regras": total,
        "tamanho": int(ativo.get("tamanho") or 0),
        "hash": str(ativo.get("hash") or ""),
        "sincronizado": sincronizado,
        "atualizado_em": str(ativo.get("atualizado_em") or ""),
        "yaml_path": str(referencias.get("yaml_path") or ""),
        "default_rule_path": str(referencias.get("default_rule_path") or ""),
        "rule_files": list(referencias.get("rule_files") or []),
        "pronto": pronto,
        "status": status,
        "mensagem": mensagem,
        "avisos": avisos,
    }


def verificar_conflitos_regras() -> ResultadoEtapa:
    """Verifica possíveis redundâncias graves nas regras aplicadas à engine (ET Open vs MoonShield)."""
    etapa_id = "verificar_conflitos_regras"
    
    arquivos_ativos = []
    for artefato in [REGRAS_DEST, REGRAS_DEST_ETC, REGRAS_ET_OPEN]:
        if artefato.is_file() and arquivo_regras_valido(artefato)[0]:
            arquivos_ativos.append(artefato)

    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.SUCESSO,
        sucesso=True,
        mensagem="Análise de conflitos concluída.",
        iniciado_em=datetime.now()
    )

    duplicados = detectar_sids_duplicados(arquivos_ativos)
    
    # Classifica severidade do conflito
    conflitos_ms_ms = 0
    conflitos_et_ms = 0
    
    str_dest = str(REGRAS_DEST)
    str_etc = str(REGRAS_DEST_ETC)
    str_et = str(REGRAS_ET_OPEN)

    for sid, lista_arqs in duplicados.items():
        if str_et in lista_arqs and (str_dest in lista_arqs or str_etc in lista_arqs):
            conflitos_et_ms += 1
        elif str_dest in lista_arqs and str_etc in lista_arqs:
            conflitos_ms_ms += 1

    res.dados = {
        "arquivos_analisados": [str(a) for a in arquivos_ativos],
        "sids_duplicados_total": len(duplicados),
        "conflitos_et_vs_moonshield": conflitos_et_ms,
        "duplicidade_moonshield_interna": conflitos_ms_ms,
        "detalhes_sids": duplicados
    }

    if conflitos_et_ms > 0:
        res.finalizar_erro(
            mensagem="Conflitos detectados entre assinaturas.",
            erro=f"As regras da fundação ET Open contém {conflitos_et_ms} SIDs idênticos às regras nativas MoonShield."
        )
    else:
        if conflitos_ms_ms > 0:
            res.adicionar_log("Cópia de segurança detectada: as regras MoonShield estão operando duplicadas em /var/lib e /etc.", NivelLog.AVISO)
        res.finalizar_sucesso("Nenhum conflito grave detectado entre provedores.")

    return res


def obter_status_regras_completo(
    origem_moonshield: str | Path | None = None,
    yaml_path: str | Path | None = None,
) -> dict[str, object]:
    """
    Compila o retrato operacional global do subsistema de assinaturas IDS.

    O payload mantém as chaves antigas e fornece aliases simples consumíveis
    pelo painel sem precisar inferir estado a partir de objetos profundamente
    aninhados.
    """
    ms_status = obter_status_regras_moonshield(origem_moonshield, yaml_path=yaml_path)

    up_disponivel = suricata_update_disponivel()
    up_resultado = obter_versao_suricata_update() if up_disponivel else None
    up_versao = ""
    if up_resultado and up_resultado.sucesso:
        up_versao = str(up_resultado.dados.get("versao", "") or "")

    referencias = obter_referencias_rule_files(yaml_path)
    et_referenciada, et_referencia = _regra_referenciada(
        referencias,
        candidatos_relativos=("suricata.rules",),
        candidatos_absolutos=(REGRAS_ET_OPEN, REGRAS_ET_OPEN_ETC),
    )

    et_info: dict[str, object] = {
        "instalada": False,
        "instalado": False,
        "arquivo": str(REGRAS_ET_OPEN),
        "caminho": str(REGRAS_ET_OPEN),
        "valido": False,
        "referenciada": et_referenciada,
        "referenciado": et_referenciada,
        "referencia": et_referencia,
        "tamanho": 0,
        "quantidade_regras": 0,
        "total": 0,
        "hash": "",
        "atualizado_em": "",
        "status": "error",
        "mensagem": "Dataset ET Open não encontrado.",
    }

    # Preferimos o masterfile do suricata-update. O /etc pode ser link/fallback.
    et_arquivo = REGRAS_ET_OPEN if REGRAS_ET_OPEN.is_file() else REGRAS_ET_OPEN_ETC
    if et_arquivo.is_file():
        et_info["instalada"] = True
        et_info["instalado"] = True
        et_info["arquivo"] = str(et_arquivo)
        et_info["caminho"] = str(et_arquivo)
        try:
            et_info["tamanho"] = et_arquivo.stat().st_size
            valido, _ = arquivo_regras_valido(et_arquivo)
            et_info["valido"] = valido
            et_info["atualizado_em"] = _mtime_iso(et_arquivo)
            if valido:
                et_info["hash"] = calcular_hash_arquivo(et_arquivo)
                qtd = contar_regras(et_arquivo)
                et_info["quantidade_regras"] = qtd
                et_info["total"] = qtd
        except OSError:
            pass

    et_pronto = bool(et_info["instalada"] and et_info["valido"])
    if et_pronto:
        et_info["status"] = "ok" if et_referenciada else "warning"
        et_info["mensagem"] = (
            "ET Open instalado, válido e referenciado pelo Suricata."
            if et_referenciada
            else "ET Open está válido, mas a referência em rule-files não foi confirmada."
        )
    elif et_info["instalada"]:
        et_info["status"] = "error"
        et_info["mensagem"] = "O arquivo ET Open existe, porém não passou na validação básica."

    conflitos_res = verificar_conflitos_regras()
    avisos: list[str] = []

    if not ms_status["instaladas"]:
        avisos.append("Regras exclusivas do MoonShield não estão instaladas no SO.")
    if not ms_status["origem"]["valido"]:
        avisos.append("Arquivo de assinaturas original do MoonShield ausente ou inválido no projeto base.")
    if ms_status["instaladas"] and not ms_status["referenciadas"]:
        avisos.append("Regras MoonShield instaladas, porém não referenciadas em rule-files.")
    if not up_disponivel:
        avisos.append("O utilitário suricata-update não está instalado no servidor.")
    if not et_info["instalada"]:
        avisos.append("Assinaturas da comunidade Emerging Threats (ET Open) ausentes.")
    elif not et_info["valido"]:
        avisos.append("O arquivo de regras da ET Open baixado está corrompido ou inválido.")
    if not conflitos_res.sucesso:
        avisos.append("Existem conflitos numéricos graves (SIDs) aplicados entre arquivos de regras.")

    pronto = bool(
        ms_status["pronto"]
        and et_pronto
        and up_disponivel
        and conflitos_res.sucesso
    )

    return {
        "moonshield": ms_status,
        "et_open": et_info,
        "suricata_update": {
            "instalado": up_disponivel,
            "disponivel": up_disponivel,
            "versao": up_versao,
            "status": "ok" if up_disponivel else "warning",
        },
        "conflitos": conflitos_res.dados,
        "referencias_yaml": referencias,

        # aliases para contratos legados/status.py
        "moonshield_instalado": bool(ms_status["instaladas"]),
        "moonshield_referenciado": bool(ms_status["referenciadas"]),
        "et_open_instalado": bool(et_info["instalada"]),
        "total_moonshield": int(ms_status["total"]),
        "total_et_open": int(et_info["total"]),

        "pronto": pronto,
        "status": "ok" if pronto else "warning" if (ms_status["instaladas"] or et_info["instalada"]) else "error",
        "avisos": avisos,
    }


def gerar_checks_regras(
    origem_moonshield: str | Path | None = None,
    yaml_path: str | Path | None = None,
) -> list[DiagnosticoItem]:
    """Interpreta as métricas do sistema de assinaturas para o diagnóstico."""
    itens: list[DiagnosticoItem] = []
    status = obter_status_regras_completo(origem_moonshield, yaml_path=yaml_path)

    ms = status["moonshield"]
    et = status["et_open"]
    up = status["suricata_update"]
    conf = status["conflitos"]

    # 1. Origem
    ok_origem = bool(ms["origem"]["valido"])
    itens.append(DiagnosticoItem(
        id="regras_moonshield_origem",
        grupo="Regras MoonShield",
        titulo="Arquivo Original Base do Sistema",
        ok=ok_origem,
        detalhe=f"Presente em {ms['origem']['caminho']}" if ok_origem else "Artefato core ausente.",
        acao="Reinstale ou atualize o pacote do backend MoonShield." if not ok_origem else "",
        critico=True,
        dados={
            "arquivo": ms["origem"]["caminho"],
            "valido": ok_origem,
            "total": ms["origem"].get("total", 0),
        },
    ))

    # 2. Instalação + referência efetiva na engine
    ok_inst_ms = bool(ms["instaladas"] and ms["referenciadas"])
    itens.append(DiagnosticoItem(
        id="regras_moonshield_instaladas",
        grupo="Regras MoonShield",
        titulo="Propagação de Regras Nativas",
        ok=ok_inst_ms,
        detalhe=(
            f"Ativo no pipeline Suricata ({ms['referencia']})."
            if ok_inst_ms
            else "Arquivo instalado, mas não referenciado em rule-files."
            if ms["instaladas"]
            else "Regras não aplicadas na máquina hospedeira."
        ),
        acao=(
            "Inclua moonshield/ms.rules em rule-files e valide com suricata -T."
            if ms["instaladas"] and not ms["referenciadas"]
            else "Complete a configuração/onboarding para garantir detecções customizadas."
            if not ms["instaladas"]
            else ""
        ),
        critico=True,
        dados={
            "instaladas": ms["instaladas"],
            "referenciadas": ms["referenciadas"],
            "arquivo": ms["arquivo"],
            "total": ms["total"],
        },
    ))

    # 3. Sincronia MS
    sync = bool(ms["sincronizado"])
    itens.append(DiagnosticoItem(
        id="regras_moonshield_sincronizadas",
        grupo="Regras MoonShield",
        titulo="Assinaturas Atualizadas (Sincronia Hash)",
        ok=sync,
        detalhe="Hashes SHA256 em paridade." if sync else ("Necessita atualização." if ms["instaladas"] else "-"),
        acao="Reaplique as regras MoonShield para sincronizar o dataset ativo." if not sync else "",
        critico=False,
        dados={
            "sincronizado": sync,
            "arquivo": ms["arquivo"],
            "total": ms["total"],
        },
    ))

    # 4. Suricata Update
    ok_up = bool(up["instalado"])
    itens.append(DiagnosticoItem(
        id="suricata_update_instalado",
        grupo="ET Open",
        titulo="Utilitário de Gestão de Regras",
        ok=ok_up,
        detalhe=f"Versão {up['versao']}" if ok_up and up.get("versao") else "Instalado." if ok_up else "Pacote 'suricata-update' ausente.",
        acao="Instale a dependência para manter o ruleset ET Open atualizado." if not ok_up else "",
        critico=False,
        dados=up,
    ))

    # 5. Instalação ET
    ok_et = bool(et["instalada"])
    itens.append(DiagnosticoItem(
        id="regras_et_open_instaladas",
        grupo="ET Open",
        titulo="Dataset da Comunidade ET Open",
        ok=ok_et,
        detalhe=f"{int(et['quantidade_regras']):,} regras detectadas." if ok_et else "Dataset não baixado.",
        acao="Atualize a ET Open pelo painel para baixar o dataset." if not ok_et else "",
        critico=False,
        dados={
            "arquivo": et["arquivo"],
            "total": et["total"],
            "referenciada": et["referenciada"],
            "atualizado_em": et["atualizado_em"],
        },
    ))

    # 6. Validade ET
    ok_et_val = bool(ok_et and et["valido"])
    itens.append(DiagnosticoItem(
        id="regras_et_open_validas",
        grupo="ET Open",
        titulo="Integridade do Dataset ET Open",
        ok=ok_et_val,
        detalhe="Assinaturas válidas." if ok_et_val else ("Corrompido ou inválido." if ok_et else "-"),
        acao="Baixe novamente o ruleset e execute suricata -T." if not ok_et_val else "",
        critico=False,
        dados={"valido": et["valido"], "hash": et["hash"]},
    ))

    # 7. Conflitos SIDs globais
    ok_conf = conf.get("conflitos_et_vs_moonshield", 0) == 0
    itens.append(DiagnosticoItem(
        id="conflitos_sids",
        grupo="Regras",
        titulo="Conflitos Cruzados de Assinaturas (SIDs)",
        ok=ok_conf,
        detalhe="Zero conflitos entre provedores." if ok_conf else f"{conf.get('conflitos_et_vs_moonshield')} colisões ativas.",
        acao="Remova SIDs conflitantes ou desative blocos redundantes antes de recarregar o IDS." if not ok_conf else "",
        critico=True,
        dados=conf,
    ))

    return itens


# ==============================================================================
# ORQUESTRAÇÃO ATIVA (TRANSAÇÕES)
# ==============================================================================

def validar_regras_com_suricata(yaml_path: str | Path) -> ResultadoEtapa:
    """Testa formalmente a sintaxe completa das regras orquestradas contra a máquina hospedeira."""
    etapa_id = "validar_regras_suricata"
    path_obj = Path(yaml_path)

    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Iniciando inspeção profunda (-T) baseada em {path_obj.name}",
        iniciado_em=datetime.now()
    )

    if not path_obj.is_file():
        res.finalizar_erro("Mestre suricata.yaml não encontrado para o teste.", erro=str(path_obj))
        return res

    if not comando_existe("suricata"):
        res.finalizar_erro("Binário suricata não localizado. Impossível validar.")
        return res

    # Executa a dry-run do Suricata
    resultado_cmd = executar_comando(["suricata", "-T", "-c", str(path_obj)], timeout=180.0)
    
    saida_completa = resultado_cmd.saida.strip()
    erros_linhas = [l.strip() for l in saida_completa.split("\n") if l.strip().startswith("E:")]
    warns_linhas = [l.strip() for l in saida_completa.split("\n") if l.strip().startswith("W:")]

    res.dados = {
        "stdout": resultado_cmd.stdout,
        "stderr": resultado_cmd.stderr,
        "erros": erros_linhas,
        "warnings": warns_linhas
    }

    if resultado_cmd.sucesso:
        res.adicionar_log("Inspeção (-T) passou sem erros fatais.", NivelLog.SUCESSO)
        res.finalizar_sucesso("Todas as regras e configs foram aprovadas pela engine do Suricata.")
    else:
        res.adicionar_log("Inspeção acusou falhas de semântica nas assinaturas ou yaml.", NivelLog.ERRO)
        res.finalizar_erro(
            mensagem="Validação suricata -T encontrou erros impeditivos.",
            erro=erros_linhas[0] if erros_linhas else "Falha não classificada (Veja logs)"
        )

    return res


def _copiar_arquivo_atomico(origem: Path, destino: Path) -> None:
    """
    Copia um arquivo de regras de forma atômica e remove BOM UTF-8.

    O Suricata pode interpretar o BOM no início do arquivo como parte de uma
    assinatura e rejeitar até mesmo uma primeira linha comentada.
    """
    if not origem.is_file():
        raise FileNotFoundError(f"Origem não existe ou não é arquivo: {origem}")

    destino.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destino.with_suffix(destino.suffix + ".tmp")

    try:
        dados = origem.read_bytes()

        if dados.startswith(b"\xef\xbb\xbf"):
            dados = dados[3:]
            logger.warning(
                "BOM UTF-8 removido automaticamente do arquivo de regras: %s",
                origem,
            )

        temp_path.write_bytes(dados)

        if eh_linux():
            os.chmod(temp_path, PERMISSAO_PADRAO_REGRAS)
            try:
                identidade = usuario_e_root()
                if identidade.get("root"):
                    import pwd
                    import grp

                    usr = pwd.getpwnam("root")
                    grp_info = grp.getgrnam("root")
                    os.chown(temp_path, usr.pw_uid, grp_info.gr_gid)
            except Exception as e:
                logger.debug(f"Falha amena ao ajustar chown em {temp_path}: {e}")

        os.replace(temp_path, destino)

    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise

def copiar_regras_moonshield(origem: str | Path | None = None, copiar_para_etc: bool = True) -> ResultadoEtapa:
    """Implementa o deploy persistente e seguro das assinaturas do backend base pro disco Linux."""
    etapa_id = "copiar_regras_moonshield"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Iniciando propagação das regras nativas MoonShield.",
        iniciado_em=datetime.now()
    )

    # 1. Origem
    path_origem = localizar_regras_moonshield_origem(origem)
    if not path_origem:
        res.finalizar_erro("Artefato de regras MS (.rules) não encontrado no projeto.")
        return res

    valido, msg_val = arquivo_regras_valido(path_origem)
    if not valido:
        res.finalizar_erro(f"Artefato local MoonShield corrompido: {msg_val}")
        return res

    # 2. Privilégios FS
    if eh_linux() and not usuario_e_root().get("root"):
        res.finalizar_erro("Requer privilégios administrativos (root) para escrever em /var e /etc.")
        return res

    res.adicionar_log(f"Origem validada ({path_origem.stat().st_size} bytes). Operando deploy...")

    # Snapshots para payload final
    status_antes = obter_status_regras_moonshield(path_origem)
    res.dados["status_antes"] = status_antes

    # 3. Executa a cópia
    falhas = []
    
    try:
        _copiar_arquivo_atomico(path_origem, REGRAS_DEST)
        res.adicionar_log(f"Cópia atômica primária efetuada com sucesso: {REGRAS_DEST}")
    except Exception as e:
        falhas.append(f"Falha em {REGRAS_DEST}: {str(e)}")

    if copiar_para_etc:
        try:
            _copiar_arquivo_atomico(path_origem, REGRAS_DEST_ETC)
            res.adicionar_log(f"Cópia atômica secundária efetuada com sucesso: {REGRAS_DEST_ETC}")
        except Exception as e:
            falhas.append(f"Falha em {REGRAS_DEST_ETC}: {str(e)}")

    status_depois = obter_status_regras_moonshield(path_origem)
    res.dados["status_depois"] = status_depois

    # 4. Finalização
    if not falhas:
        res.finalizar_sucesso("Deploy unificado de regras MS concluído sem erros.")
    elif len(falhas) == (2 if copiar_para_etc else 1):
        res.finalizar_erro("Falha massiva no deploy das regras.", erro="; ".join(falhas))
    else:
        res.finalizar_erro("Deploy sofreu interrupções (Falha Parcial).", erro="; ".join(falhas))

    return res


def suricata_update_disponivel() -> bool:
    """Validador isolado da presença do manager da ET."""
    return comando_existe("suricata-update")


def obter_versao_suricata_update() -> ResultadoEtapa:
    """Busca o payload versionado do utilitário python extra (suricata-update)."""
    etapa_id = "versao_suricata_update"
    
    if not suricata_update_disponivel():
        return ResultadoEtapa(
            etapa=etapa_id,
            status=StatusEtapa.ERRO,
            sucesso=False,
            mensagem="Utilitário ausente.",
            erro="suricata-update não existe no PATH.",
            dados={"instalado": False}
        )
        
    resultado_cmd = executar_comando(["suricata-update", "--version"], timeout=15.0)
    
    if resultado_cmd.sucesso:
        linha_util = resultado_cmd.saida.splitlines()[0] if resultado_cmd.saida else "Desconhecido"
        res = ResultadoEtapa(
            etapa=etapa_id,
            status=StatusEtapa.SUCESSO,
            sucesso=True,
            mensagem="Versão verificada com sucesso.",
            dados={
                "instalado": True,
                "caminho": localizar_comando("suricata-update"),
                "versao": linha_util.strip()
            }
        )
        return res

    return ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.ERRO,
        sucesso=False,
        mensagem="Falha ao extrair versão do suricata-update.",
        erro=resultado_cmd.erro or resultado_cmd.saida,
        dados={"instalado": True}
    )


def instalar_suricata_update() -> ResultadoEtapa:
    """Provê a instalação em background do package base da ferramenta via gerenciador host."""
    etapa_id = "instalar_suricata_update"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Processando pré-requisitos de instalação do utilitário.",
        iniciado_em=datetime.now()
    )

    if suricata_update_disponivel():
        res.finalizar_sucesso("O utilitário suricata-update já se encontra instalado no PATH.")
        return res

    if not eh_linux():
        res.finalizar_erro("A instalação automática só é suportada em servidores Linux nativos.")
        return res
        
    if not usuario_e_root().get("root"):
        res.finalizar_erro("Instalações via package manager requerem privilégios de root.")
        return res

    gerenciador = detectar_gerenciador_pacotes()
    if not gerenciador:
        res.finalizar_erro("Nenhum gerenciador de pacotes suportado foi encontrado (apt, dnf, yum, pacman).")
        return res

    pacote_alvo = "suricata-update"
    if gerenciador in ("dnf", "yum"):
        pacote_alvo = "python3-suricata-update"

    argumentos_install = obter_comando_instalacao(pacote_alvo, gerenciador)
    if not argumentos_install:
        res.finalizar_erro("Não foi possível derivar sintaxe de instalação segura.", erro=f"Gerenciador: {gerenciador}")
        return res

    res.adicionar_log(f"Acionando sistema local de pacotes: {' '.join(argumentos_install)}", NivelLog.INFO)
    
    resultado_cmd = executar_comando(argumentos_install, timeout=600.0) # 10min pra apt-get ser gentil
    
    if resultado_cmd.sucesso:
        if suricata_update_disponivel():
            res.adicionar_log("Binário instalado e acoplado ao PATH nativo com sucesso.", NivelLog.SUCESSO)
            res.finalizar_sucesso("Instalação do pacote finalizada.")
        else:
            res.adicionar_log(resultado_cmd.saida, NivelLog.DEBUG)
            res.finalizar_erro("O gerenciador não retornou falha, mas o executável ainda está ausente.")
    else:
        motivo = resultado_cmd.erro if resultado_cmd.erro else resultado_cmd.saida
        res.adicionar_log(f"Erro do empacotador: {motivo}", NivelLog.ERRO)
        res.finalizar_erro("A instalação estruturada pelo package manager falhou.", erro=motivo)

    return res


def habilitar_fonte_et_open() -> ResultadoEtapa:
    """Aciona a source nativa padrão (Emerging Threats Open) dentro do registry do utilitário."""
    etapa_id = "habilitar_et_open"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Acoplando provedor primário: {NOME_FONTE_ET_OPEN}",
        iniciado_em=datetime.now()
    )

    if not suricata_update_disponivel():
        res.finalizar_erro("Requer suricata-update instalado.")
        return res

    resultado_cmd = executar_comando(["suricata-update", "enable-source", NOME_FONTE_ET_OPEN], timeout=120.0)
    
    res.dados = {
        "stdout": resultado_cmd.stdout,
        "stderr": resultado_cmd.stderr
    }

    if resultado_cmd.sucesso or "already enabled" in resultado_cmd.saida.lower():
        res.adicionar_log(f"Source {NOME_FONTE_ET_OPEN} ativado/pronto para sync.", NivelLog.SUCESSO)
        res.finalizar_sucesso("Fonte cadastrada nos índices do Suricata Update.")
    else:
        motivo = resultado_cmd.erro if resultado_cmd.erro else resultado_cmd.saida
        res.finalizar_erro("Não foi possível vincular o registry et/open.", erro=motivo)

    return res


def garantir_link_regras_et_open() -> ResultadoEtapa:
    """
    Garante que o caminho usado pelo suricata.yaml encontre o ruleset gerado
    pelo suricata-update em /var/lib/suricata/rules/suricata.rules.
    """
    etapa_id = "garantir_link_regras_et_open"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Sincronizando caminho das regras ET Open.",
        iniciado_em=datetime.now(),
    )

    if not REGRAS_ET_OPEN.is_file():
        res.finalizar_erro(
            "Arquivo principal da ET Open não foi encontrado.",
            erro=str(REGRAS_ET_OPEN),
        )
        return res

    if eh_linux() and not usuario_e_root().get("root"):
        res.finalizar_erro(
            "Requer privilégios administrativos para preparar o link das regras ET Open."
        )
        return res

    try:
        REGRAS_ET_OPEN_ETC.parent.mkdir(parents=True, exist_ok=True)

        if REGRAS_ET_OPEN_ETC.is_symlink():
            try:
                if REGRAS_ET_OPEN_ETC.resolve() == REGRAS_ET_OPEN.resolve():
                    res.dados = {
                        "origem": str(REGRAS_ET_OPEN),
                        "destino": str(REGRAS_ET_OPEN_ETC),
                        "ja_existia": True,
                    }
                    res.finalizar_sucesso("Link das regras ET Open já estava correto.")
                    return res
            except OSError:
                pass
            REGRAS_ET_OPEN_ETC.unlink()
        elif REGRAS_ET_OPEN_ETC.exists():
            # Preserva um arquivo regular válido já existente.
            if REGRAS_ET_OPEN_ETC.is_file() and arquivo_regras_valido(REGRAS_ET_OPEN_ETC)[0]:
                res.dados = {
                    "origem": str(REGRAS_ET_OPEN),
                    "destino": str(REGRAS_ET_OPEN_ETC),
                    "arquivo_regular_preservado": True,
                }
                res.finalizar_sucesso(
                    "Arquivo regular de regras ET Open já existe no caminho esperado."
                )
                return res
            REGRAS_ET_OPEN_ETC.unlink()

        REGRAS_ET_OPEN_ETC.symlink_to(REGRAS_ET_OPEN)
        res.dados = {
            "origem": str(REGRAS_ET_OPEN),
            "destino": str(REGRAS_ET_OPEN_ETC),
            "ja_existia": False,
        }
        res.finalizar_sucesso("Link das regras ET Open criado com sucesso.")

    except Exception as e:
        res.finalizar_erro(
            "Não foi possível preparar o caminho das regras ET Open.",
            erro=str(e),
        )

    return res


def atualizar_et_open(habilitar_fonte: bool = True) -> ResultadoEtapa:
    """Faz a puxada full do artefato ET Open atualizado (Sync das ~40k regras) sem reload do serviço."""
    etapa_id = "atualizar_et_open"
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Acionando link externo para fetch das assinaturas ET Open.",
        iniciado_em=datetime.now()
    )

    if not suricata_update_disponivel():
        res.finalizar_erro("Requer suricata-update instalado no PATH.")
        return res

    if habilitar_fonte:
        res_fonte = habilitar_fonte_et_open()
        if not res_fonte.sucesso:
            res.finalizar_erro("Dependência falhou: registro de fonte et/open não concretizado.", erro=res_fonte.erro)
            return res

    res.adicionar_log("Comunicação HTTP em background autorizada (Estimativa: 1-5min).", NivelLog.INFO)
    
    # Roda sem reload do systemd. O reload será forçado via master step na orquestração se precisar.
    resultado_cmd = executar_comando(["suricata-update", "--no-reload"], timeout=900.0)
    
    res.dados = {
        "stdout": resultado_cmd.stdout,
        "stderr": resultado_cmd.stderr,
        "fonte": NOME_FONTE_ET_OPEN
    }

    if resultado_cmd.sucesso:
        # Pós sync validator (Garantiu download real?)
        if not REGRAS_ET_OPEN.is_file():
            res.finalizar_erro("O utilitário retornou sucesso, mas o masterfile suricata.rules não subiu pro FS.")
            return res

        resultado_link = garantir_link_regras_et_open()
        if not resultado_link.sucesso:
            res.finalizar_erro(
                "As regras ET Open foram atualizadas, mas o caminho usado pelo Suricata não foi preparado.",
                erro=resultado_link.erro,
            )
            return res

        res.dados["link_etc"] = resultado_link.dados
        res.dados["arquivo"] = str(REGRAS_ET_OPEN)
        res.dados["tamanho"] = REGRAS_ET_OPEN.stat().st_size
        res.dados["quantidade_regras"] = contar_regras(REGRAS_ET_OPEN)
        res.dados["atualizado_em"] = datetime.now().isoformat()

        res.adicionar_log(f"Dataset baixado: ~{res.dados['quantidade_regras']} rules empacotados.", NivelLog.SUCESSO)
        res.finalizar_sucesso("Regras de rede atualizadas para a última versão disponível.")
    else:
        motivo = resultado_cmd.erro if resultado_cmd.erro else resultado_cmd.saida
        res.adicionar_log(f"Download abortado/Timeout. Erro: {motivo}", NivelLog.ERRO)
        res.finalizar_erro("Comunicação ou gravação do sync falhou.", erro=motivo)

    return res