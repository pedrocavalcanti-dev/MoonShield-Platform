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


def obter_status_regras_moonshield(origem: str | Path | None = None) -> dict[str, object]:
    """Compila o retrato de sincronia dos artefatos core do MoonShield entre base/repo e /var e /etc."""
    def _analisar_ponta(caminho_obj: Path | None, hash_ref: str = "") -> dict:
        info = {
            "caminho": str(caminho_obj) if caminho_obj else "",
            "existe": False,
            "valido": False,
            "tamanho": 0,
            "hash": "",
            "sincronizado": False
        }
        if caminho_obj and caminho_obj.is_file():
            info["existe"] = True
            try:
                info["tamanho"] = caminho_obj.stat().st_size
                valido, _ = arquivo_regras_valido(caminho_obj)
                info["valido"] = valido
                if valido:
                    h = calcular_hash_arquivo(caminho_obj)
                    info["hash"] = h
                    if hash_ref:
                        info["sincronizado"] = (h == hash_ref)
            except OSError:
                pass
        return info

    path_origem = localizar_regras_moonshield_origem(origem)
    stat_origem = _analisar_ponta(path_origem)
    
    hash_base = stat_origem["hash"] if stat_origem["valido"] else ""

    stat_var = _analisar_ponta(REGRAS_DEST, hash_ref=hash_base)
    stat_etc = _analisar_ponta(REGRAS_DEST_ETC, hash_ref=hash_base)

    # Considera instalado se alguma ponta final estiver saudável
    instaladas = stat_var["valido"] or stat_etc["valido"]

    return {
        "origem": stat_origem,
        "destino_var": stat_var,
        "destino_etc": stat_etc,
        "instaladas": instaladas,
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


def obter_status_regras_completo(origem_moonshield: str | Path | None = None) -> dict[str, object]:
    """Compila o retrato operacional global do subsistema de assinaturas IDS."""
    ms_status = obter_status_regras_moonshield(origem_moonshield)
    
    # Status do Update
    up_disponivel = suricata_update_disponivel()
    up_versao = obter_versao_suricata_update().dados.get("versao", "") if up_disponivel else ""

    # Status ET Open
    et_info = {
        "instalada": False,
        "arquivo": str(REGRAS_ET_OPEN),
        "valido": False,
        "tamanho": 0,
        "quantidade_regras": 0,
        "hash": "",
    }
    
    if REGRAS_ET_OPEN.is_file():
        et_info["instalada"] = True
        try:
            et_info["tamanho"] = REGRAS_ET_OPEN.stat().st_size
            valido, _ = arquivo_regras_valido(REGRAS_ET_OPEN)
            et_info["valido"] = valido
            if valido:
                et_info["hash"] = calcular_hash_arquivo(REGRAS_ET_OPEN)
                et_info["quantidade_regras"] = contar_regras(REGRAS_ET_OPEN)
        except OSError:
            pass

    conflitos_res = verificar_conflitos_regras()
    avisos = []
    
    if not ms_status["instaladas"]:
        avisos.append("Regras exclusivas do MoonShield não estão instaladas no SO.")
    if not ms_status["origem"]["valido"]:
        avisos.append("Arquivo de assinaturas original do MoonShield ausente ou inválido no projeto base.")
    if not up_disponivel:
        avisos.append("O utilitário suricata-update não está instalado no servidor.")
    if not et_info["instalada"]:
        avisos.append("Assinaturas da comunidade Emerging Threats (ET Open) ausentes.")
    elif not et_info["valido"]:
        avisos.append("O arquivo de regras da ET Open baixado está corrompido.")
    if not conflitos_res.sucesso:
        avisos.append("Existem conflitos numéricos graves (SIDs) aplicados entre arquivos de regras.")

    return {
        "moonshield": ms_status,
        "et_open": et_info,
        "suricata_update": {
            "instalado": up_disponivel,
            "versao": up_versao,
        },
        "conflitos": conflitos_res.dados,
        "pronto": len(avisos) == 0,
        "avisos": avisos,
    }


def gerar_checks_regras(origem_moonshield: str | Path | None = None) -> list[DiagnosticoItem]:
    """Interpreta as métricas do sistema de assinaturas para a interface de Diagnóstico."""
    itens = []
    status = obter_status_regras_completo(origem_moonshield)

    ms = status["moonshield"]
    et = status["et_open"]
    up = status["suricata_update"]
    conf = status["conflitos"]

    # 1. Origem
    ok_origem = ms["origem"]["valido"]
    itens.append(DiagnosticoItem(
        id="regras_moonshield_origem",
        grupo="Regras MoonShield",
        titulo="Arquivo Original Base do Sistema",
        ok=ok_origem,
        detalhe=f"Presente em {ms['origem']['caminho']}" if ok_origem else "Artefato core ausente.",
        acao="Reinstale ou atualize o pacote do backend MoonShield." if not ok_origem else "",
        critico=True
    ))

    # 2. Instalação MS
    ok_inst_ms = ms["instaladas"]
    itens.append(DiagnosticoItem(
        id="regras_moonshield_instaladas",
        grupo="Regras MoonShield",
        titulo="Propagação de Regras Nativas",
        ok=ok_inst_ms,
        detalhe="Ativo no pipeline Suricata." if ok_inst_ms else "Regras não aplicadas na máquina hospedeira.",
        acao="Complete a configuração/onboarding para garantir detecções customizadas." if not ok_inst_ms else "",
        critico=True
    ))

    # 3. Sincronia MS
    sync = False
    if ms["origem"]["valido"]:
        if ms["destino_var"]["valido"] and ms["destino_var"]["sincronizado"]:
            sync = True
        elif ms["destino_etc"]["valido"] and ms["destino_etc"]["sincronizado"]:
            sync = True
            
    itens.append(DiagnosticoItem(
        id="regras_moonshield_sincronizadas",
        grupo="Regras MoonShield",
        titulo="Assinaturas Atualizadas (Sincronia Hash)",
        ok=sync,
        detalhe="Hashes SHA256 em paridade." if sync else ("Necessita atualização." if ok_inst_ms else "-"),
        acao="Regere a cópia das regras no assistente para aplicar o último dataset." if not sync else "",
        critico=False # Warning
    ))

    # 4. Suricata Update Bin
    ok_up = up["instalado"]
    itens.append(DiagnosticoItem(
        id="suricata_update_instalado",
        grupo="ET Open",
        titulo="Utilitário de Gestão de Regras",
        ok=ok_up,
        detalhe=f"Versão {up['versao']}" if ok_up else "Pacote 'suricata-update' ausente.",
        acao="Instale a dependência para manter o IDS ciente de ataques zero-day." if not ok_up else "",
        critico=False # Warning, MS rules funciona sem ele.
    ))

    # 5. Instalação ET
    ok_et = et["instalada"]
    itens.append(DiagnosticoItem(
        id="regras_et_open_instaladas",
        grupo="ET Open",
        titulo="Dataset da Comunidade ET Open",
        ok=ok_et,
        detalhe=f"{et['quantidade_regras']:,} regras detectadas." if ok_et else "Dataset não baixado.",
        acao="Rode a configuração inicial e permita o download base." if not ok_et else "",
        critico=False
    ))

    # 6. Validade ET
    ok_et_val = ok_et and et["valido"]
    itens.append(DiagnosticoItem(
        id="regras_et_open_validas",
        grupo="ET Open",
        titulo="Integridade do Dataset ET Open",
        ok=ok_et_val,
        detalhe="Assinaturas válidas." if ok_et_val else ("Corrompido." if ok_et else "-"),
        acao="Realize o download do ruleset novamente caso as assinaturas falhem na inspeção suricata -T." if not ok_et_val else "",
        critico=False
    ))

    # 7. Conflitos SIDs globais
    ok_conf = conf.get("conflitos_et_vs_moonshield", 0) == 0
    itens.append(DiagnosticoItem(
        id="conflitos_sids",
        grupo="Regras",
        titulo="Conflitos Cruzados de Assinaturas (SIDs)",
        ok=ok_conf,
        detalhe="Zero conflitos entre provedores." if ok_conf else f"{conf.get('conflitos_et_vs_moonshield')} colisões ativas.",
        acao="Remova SIDs conflitantes ou desative temporariamente blocos redundantes em et/open." if not ok_conf else "",
        critico=True
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
    """Realiza overwrite isolando falhas de FS usando temporários para evitar rules truncados."""
    if not origem.is_file():
        raise FileNotFoundError(f"Origem não existe ou não é arquivo: {origem}")

    destino.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destino.with_suffix(".tmp")
    
    try:
        shutil.copy2(origem, temp_path)
        if eh_linux():
            os.chmod(temp_path, PERMISSAO_PADRAO_REGRAS)
            try:
                # Tenta unificar a identidade (Fallback seguro se root)
                identidade = usuario_e_root()
                if identidade.get("root"):
                    import pwd, grp
                    usr = pwd.getpwnam("root")
                    grp_info = grp.getgrnam("root")
                    os.chown(temp_path, usr.pw_uid, grp_info.gr_gid)
            except Exception as e:
                logger.debug(f"Falha amena ao ajustar chown em {temp_path}: {e}")

        # Atomica! Substitui o artefato ao inves de write chunked
        os.replace(temp_path, destino)
    except Exception as e:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise e


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