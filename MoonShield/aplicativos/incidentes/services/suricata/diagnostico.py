"""
Módulo orquestrador de diagnóstico do Suricata.
Agrega verificações de sistema, infraestrutura, logs e regras num payload consolidado
e determinístico para orientar o painel visual (Onboarding/Doctor) do MoonShield.
"""

import os
import json
import time
import logging
from pathlib import Path
from datetime import datetime

from .tipos import (
    DiagnosticoItem,
    ResultadoDiagnostico,
    ConfiguracaoSuricataDados,
    ResultadoEtapa,
)

# Importações dos geradores especialistas já implementados
from .ambiente import (
    gerar_checks_ambiente,
    localizar_suricata_yaml,
    localizar_eve_json,
    detectar_ambiente_completo,
)
from .interfaces import (
    gerar_checks_interfaces,
    obter_topologia_detectada,
)
from .regras import (
    gerar_checks_regras,
    obter_status_regras_completo,
)
from .configurador import (
    gerar_checks_configuracao,
    validar_configuracao,
    obter_status_configuracao,
)
from .servicos import (
    gerar_checks_servicos,
    obter_status_stack,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

GRUPOS_PADRAO = (
    "Sistema",
    "Suricata",
    "Interfaces",
    "Topologia",
    "Configuração",
    "Captura",
    "EVE",
    "Regras MoonShield",
    "ET Open",
    "Regras",
    "Serviços",
    "Monitor MoonShield",
    "Worker de Tarefas",
)

TIPOS_EVE_OBRIGATORIOS = {
    "alert",
    "dns",
    "http",
    "tls",
}

TEMPO_MAXIMO_EVE_ATUALIZACAO = 300
LIMITE_LEITURA_EVE = 5 * 1024 * 1024  # 5 MB


# ==============================================================================
# HELPERS PRIVADOS
# ==============================================================================

def _idade_arquivo(caminho: Path) -> float | None:
    """Calcula há quantos segundos o arquivo foi modificado."""
    if not caminho.is_file():
        return None
    try:
        mtime = caminho.stat().st_mtime
        agora = time.time()
        return max(0.0, agora - mtime)
    except OSError:
        return None


def _ler_ultimas_linhas(caminho: Path, max_linhas: int, limite_bytes: int = LIMITE_LEITURA_EVE) -> list[str]:
    """Lê do final para o início um número seguro de linhas sem carregar o log inteiro na RAM."""
    if not caminho.is_file():
        return []

    try:
        tamanho = caminho.stat().st_size
        if tamanho == 0:
            return []

        chunk_size = min(tamanho, limite_bytes)
        with open(caminho, 'rb') as f:
            f.seek(tamanho - chunk_size)
            dados = f.read(chunk_size).decode('utf-8', errors='replace')

        linhas = dados.splitlines()
        # Descarta a primeira que pode ser parcial devido ao seek
        if len(linhas) > 1 and caminho.stat().st_size > limite_bytes:
            linhas = linhas[1:]
            
        # Pega do final
        linhas_uteis = []
        for linha in reversed(linhas):
            l_limpa = linha.strip()
            if l_limpa:
                linhas_uteis.append(l_limpa)
            if len(linhas_uteis) >= max_linhas:
                break
                
        return linhas_uteis
    except Exception as e:
        logger.debug(f"Falha ao ler ultimas linhas do {caminho.name}: {e}")
        return []


def _criar_check_erro_interno(grupo: str, detalhe_erro: str) -> DiagnosticoItem:
    """Fallback para quando um dos módulos especialistas crashea durante o diagnóstico."""
    return DiagnosticoItem(
        id=f"erro_interno_{grupo.lower().replace(' ', '_')}",
        grupo=grupo,
        titulo=f"Falha na Coleta: {grupo}",
        ok=False,
        detalhe=f"Erro interno do Python: {detalhe_erro}",
        acao="Verifique os logs do servidor Django para investigar a falha do módulo.",
        critico=True,
    )


def _converter_resultado_etapa_em_check(res: ResultadoEtapa, id_check: str, grupo: str, critico: bool = True) -> DiagnosticoItem:
    """Converte o DTO genérico de transação/etapa em formato visualizável do Doctor."""
    acao = ""
    if not res.sucesso:
        if res.erro:
            acao = f"Correção sugerida ou logs: {res.erro[:100]}"
        else:
            acao = "Revise a configuração fornecida."
            
    return DiagnosticoItem(
        id=id_check,
        grupo=grupo,
        titulo=res.mensagem,
        ok=res.sucesso,
        detalhe="Sem erros detectados." if res.sucesso else "Falha reportada na execução do teste.",
        acao=acao,
        critico=critico,
        dados=res.dados,
    )


# ==============================================================================
# HIGIENIZAÇÃO DE RESULTADOS GLOBAIS
# ==============================================================================

def ordenar_checks(itens: list[DiagnosticoItem]) -> list[DiagnosticoItem]:
    """Classifica ordenando por Grupo (Core -> Custom) e então por Severidade (Critico -> Aviso -> OK)."""
    
    # Mapeia os grupos conhecidos para dar prioridade visual lógica. Grupos desconhecidos vão pro final.
    ordem_grupo = {grupo: idx for idx, grupo in enumerate(GRUPOS_PADRAO)}
    
    def chave_ordenacao(item: DiagnosticoItem):
        peso_grupo = ordem_grupo.get(item.grupo, 999)
        
        # 1. Falha critica, 2. Falha aviso, 3. OK
        if item.ok:
            peso_status = 3
        elif item.critico:
            peso_status = 1
        else:
            peso_status = 2
            
        return (peso_grupo, peso_status, item.titulo)
        
    return sorted(itens, key=chave_ordenacao)


def remover_checks_duplicados(itens: list[DiagnosticoItem]) -> list[DiagnosticoItem]:
    """Elimina colisão de IDs de checks priorizando exibir as falhas/críticas sobre cenários positivos."""
    mapa = {}
    
    for item in itens:
        existente = mapa.get(item.id)
        if existente:
            # Substitui se o atual for falha e o antigo OK
            if existente.ok and not item.ok:
                mapa[item.id] = item
            # Substitui se ambos falharam mas o atual é CRITICO e o antigo não
            elif not existente.ok and not item.ok:
                if not existente.critico and item.critico:
                    mapa[item.id] = item
        else:
            mapa[item.id] = item
            
    return list(mapa.values())


def _resumir_resultado(resultado: ResultadoDiagnostico) -> dict[str, object]:
    """
    Consolida os contadores do diagnóstico usando uma única fonte de verdade.

    Um check não aprovado e não crítico é AVISO. Um check não aprovado e
    crítico é FALHA CRÍTICA. Dessa forma a soma sempre fecha:

        total = saudáveis + avisos + falhas críticas
    """
    itens = list(resultado.itens or [])

    total_checks = len(itens)
    total_ok = sum(1 for item in itens if item.ok)
    total_criticos = sum(1 for item in itens if not item.ok and item.critico)
    total_avisos = sum(1 for item in itens if not item.ok and not item.critico)
    total_falhas = total_criticos + total_avisos

    score_integridade = (
        round((total_ok / total_checks) * 100)
        if total_checks > 0
        else 0
    )

    grupos_resumo: dict[str, dict[str, object]] = {}
    for grupo_nome, checks in resultado.grupos.items():
        checks_lista = list(checks or [])
        grupo_total = len(checks_lista)
        grupo_ok = sum(1 for item in checks_lista if item.ok)
        grupo_criticos = sum(
            1 for item in checks_lista if not item.ok and item.critico
        )
        grupo_avisos = sum(
            1 for item in checks_lista if not item.ok and not item.critico
        )
        grupo_falhas = grupo_criticos + grupo_avisos
        grupo_score = (
            round((grupo_ok / grupo_total) * 100)
            if grupo_total > 0
            else 0
        )

        grupos_resumo[grupo_nome] = {
            "total": grupo_total,
            "ok": grupo_ok,
            "saudaveis": grupo_ok,
            "avisos": grupo_avisos,
            "criticos": grupo_criticos,
            "falhas": grupo_falhas,
            "score": grupo_score,
        }

    falhas_criticas = [
        item.to_dict()
        for item in itens
        if not item.ok and item.critico
    ]
    avisos = [
        item.to_dict()
        for item in itens
        if not item.ok and not item.critico
    ]

    executado_em = getattr(resultado, "executado_em", None)
    executado_em_iso = (
        executado_em.isoformat()
        if hasattr(executado_em, "isoformat")
        else ""
    )

    return {
        "pronto": bool(resultado.pronto),
        "total_checks": total_checks,
        "total_ok": total_ok,
        "total_saudaveis": total_ok,
        "total_avisos": total_avisos,
        "total_falhas": total_falhas,
        "total_criticos": total_criticos,
        "score_integridade": score_integridade,
        "score": score_integridade,
        "falhas_criticas": falhas_criticas,
        "avisos": avisos,
        "grupos": grupos_resumo,
        "duracao_segundos": float(getattr(resultado, "duracao_segundos", 0.0) or 0.0),
        "executado_em": executado_em_iso,
        "mensagem": (
            "Infraestrutura pronta; existem apenas avisos operacionais."
            if resultado.pronto and total_avisos > 0
            else "Infraestrutura pronta e sem falhas críticas."
            if resultado.pronto
            else "Existem falhas críticas determinísticas que exigem correção."
        ),
    }


def _serializar_resultado(resultado: ResultadoDiagnostico) -> dict[str, object]:
    """
    Serializa ResultadoDiagnostico adicionando aliases estáveis para o painel.

    Mantém o contrato legado de ``to_dict()`` e acrescenta os contadores que o
    frontend precisa, sem obrigar o JavaScript a inferir severidade.
    """
    payload = resultado.to_dict()
    if not isinstance(payload, dict):
        payload = {}

    resumo = _resumir_resultado(resultado)

    payload["pronto"] = resumo["pronto"]
    payload["total_checks"] = resumo["total_checks"]
    payload["total_ok"] = resumo["total_ok"]
    payload["total_saudaveis"] = resumo["total_saudaveis"]
    payload["total_avisos"] = resumo["total_avisos"]
    payload["total_falhas"] = resumo["total_falhas"]
    payload["total_criticos"] = resumo["total_criticos"]
    payload["score_integridade"] = resumo["score_integridade"]
    payload["score"] = resumo["score"]
    payload["resumo"] = resumo

    return payload


# ==============================================================================
# CHECKS ESPECÍFICOS DO EVE.JSON / MONITOR
# ==============================================================================


def check_eve_existe(eve_path: str | Path) -> DiagnosticoItem:
    """
    Verifica a presença do EVE.

    Logo após o restart do Suricata, o eve.json pode ainda não ter sido criado
    ou pode estar vazio. Isso é transitório e não deve reprovar a instalação.
    """
    path_obj = Path(eve_path)
    existe = path_obj.is_file()
    legivel = os.access(path_obj, os.R_OK) if existe else False

    tamanho = 0
    try:
        tamanho = path_obj.stat().st_size if existe else 0
    except OSError:
        pass

    if existe and legivel:
        return DiagnosticoItem(
            id="eve_existe",
            grupo="EVE",
            titulo="Detecção do Log de Telemetria (eve.json)",
            ok=True,
            detalhe=f"{tamanho:,} bytes.",
            acao="",
            critico=False,
            dados={"existe": True, "legivel": True, "tamanho": tamanho},
        )

    return DiagnosticoItem(
        id="eve_existe",
        grupo="EVE",
        titulo="Detecção do Log de Telemetria (eve.json)",
        ok=False,
        detalhe=(
            "Arquivo existe, mas ainda não está legível."
            if existe
            else "Arquivo ainda não foi criado após o restart."
        ),
        acao=(
            "Aguarde alguns segundos e gere tráfego de rede. "
            "Se continuar ausente, revise o serviço Suricata e o output eve-log."
        ),
        critico=False,
        dados={"existe": existe, "legivel": legivel, "tamanho": tamanho},
    )

def check_eve_atualizacao(eve_path: str | Path, limite_segundos: int = TEMPO_MAXIMO_EVE_ATUALIZACAO) -> DiagnosticoItem:
    path_obj = Path(eve_path)
    idade = _idade_arquivo(path_obj)
    
    if idade is None:
        return DiagnosticoItem(
            id="eve_atualizando", grupo="EVE", titulo="Recebimento de Eventos (Atualização)",
            ok=False, detalhe="Arquivo inalcançável ou inexistente.", acao="Garanta a criação do arquivo.", critico=False
        )

    tamanho = path_obj.stat().st_size
    if tamanho == 0:
        return DiagnosticoItem(
            id="eve_atualizando", grupo="EVE", titulo="Recebimento de Eventos (Atualização)",
            ok=False, detalhe="O log foi criado, mas permanece em 0 bytes.", acao="Se for uma instalação nova, gere algum tráfego de rede (ex: ping, nslookup) e aguarde o Suricata carregar.", critico=False
        )
        
    ok = (idade <= limite_segundos)
    detalhe = f"Atualizado há {int(idade)} segundos."
    if not ok:
        detalhe += " (Estagnado)"

    return DiagnosticoItem(
        id="eve_atualizando",
        grupo="EVE",
        titulo="Recebimento de Eventos (Atualização)",
        ok=ok,
        detalhe=detalhe,
        acao=f"Sem atividade há mais de {limite_segundos}s. Em redes silenciosas isso é normal. Se não for, cheque o serviço do Suricata." if not ok else "",
        critico=False, # Falta de atualização muitas vezes é apenas falta de tráfego, não um erro
        dados={"idade": idade, "tamanho": tamanho}
    )



def check_eve_json_valido(eve_path: str | Path, max_linhas: int = 100) -> DiagnosticoItem:
    """
    Valida o NDJSON do EVE quando houver amostra.

    Sem eventos logo após a instalação é aviso, não falha crítica. Se houver
    linhas reais e nenhuma puder ser parseada, aí sim há corrupção/formato
    incompatível e o check se torna crítico.
    """
    path_obj = Path(eve_path)
    linhas = _ler_ultimas_linhas(path_obj, max_linhas=max_linhas)

    if not linhas:
        return DiagnosticoItem(
            id="eve_json_valido",
            grupo="EVE",
            titulo="Integridade JSON do Log",
            ok=False,
            detalhe="Ainda não há eventos suficientes para validar o NDJSON.",
            acao="Gere tráfego de rede e execute o diagnóstico novamente.",
            critico=False,
            dados={
                "linhas_analisadas": 0,
                "validas": 0,
                "invalidas": 0,
                "ultimo_event_type": "",
            },
        )

    validas = 0
    invalidas = 0
    ultimo_type = ""

    for linha in linhas:
        try:
            obj = json.loads(linha)
            if isinstance(obj, dict):
                validas += 1
                if "event_type" in obj and not ultimo_type:
                    ultimo_type = str(obj["event_type"])
            else:
                invalidas += 1
        except json.JSONDecodeError:
            invalidas += 1

    ok = validas > 0

    return DiagnosticoItem(
        id="eve_json_valido",
        grupo="EVE",
        titulo="Integridade JSON do Log",
        ok=ok,
        detalhe=(
            f"{validas} linha(s) JSON válida(s) nas últimas {len(linhas)} amostras."
            if ok
            else f"Nenhuma linha JSON válida em {len(linhas)} amostras."
        ),
        acao="O formato do eve.json não parece NDJSON compatível." if not ok else "",
        critico=(not ok and len(linhas) > 0),
        dados={
            "linhas_analisadas": len(linhas),
            "validas": validas,
            "invalidas": invalidas,
            "ultimo_event_type": ultimo_type,
        },
    )

def check_tipos_eve(eve_path: str | Path, max_linhas: int = 1000) -> DiagnosticoItem:
    path_obj = Path(eve_path)
    linhas = _ler_ultimas_linhas(path_obj, max_linhas=max_linhas)
    
    encontrados = set()
    total = len(linhas)
    
    for linha in linhas:
        try:
            obj = json.loads(linha)
            if isinstance(obj, dict) and "event_type" in obj:
                encontrados.add(obj["event_type"])
        except json.JSONDecodeError:
            pass

    faltando = TIPOS_EVE_OBRIGATORIOS - encontrados
    has_alert = "alert" in encontrados
    
    ok = has_alert
    
    # Detalhe condicional para não apavorar usuário se só faltou um "tls" na amostra
    if missing_str := ", ".join(faltando):
        if total == 0:
            detalhe = "Sem amostras. "
        else:
            detalhe = f"Não identificados na amostragem: {missing_str}."
    else:
        detalhe = "Todos os tipos obrigatórios encontrados na amostragem."

    return DiagnosticoItem(
        id="eve_tipos",
        grupo="EVE",
        titulo="Disponibilidade de Metadados Core no Log",
        ok=ok,
        detalhe=detalhe,
        acao="Gere tráfego malicioso controlado (teste de IDS) para assegurar que 'alerts' estejam sendo escritos." if not ok else "",
        critico=False, # Não é critico porque depende puramente da janela de tráfego do cliente
        dados={"encontrados": list(encontrados), "faltando": list(faltando), "total_eventos": total}
    )



def check_permissao_eve(eve_path: str | Path) -> DiagnosticoItem:
    """
    Permissão só é crítica quando o arquivo existe e o processo não consegue lê-lo.
    Arquivo ainda inexistente é condição transitória coberta por check_eve_existe.
    """
    path_obj = Path(eve_path)

    if not path_obj.exists():
        return DiagnosticoItem(
            id="eve_permissao",
            grupo="EVE",
            titulo="Concessão de Leitura do EVE",
            ok=False,
            detalhe="Arquivo ainda não foi gerado; permissão não pode ser avaliada.",
            acao="Aguarde a criação do eve.json e rode o diagnóstico novamente.",
            critico=False,
            dados={"modo_octal": "", "leitura_ok": False, "diretorio_ok": False},
        )

    r_ok = os.access(path_obj, os.R_OK)
    parent_ok = os.access(path_obj.parent, os.X_OK | os.R_OK)

    modo_str = ""
    try:
        modo_str = oct(path_obj.stat().st_mode & 0o777)
    except OSError:
        pass

    ok = r_ok and parent_ok

    return DiagnosticoItem(
        id="eve_permissao",
        grupo="EVE",
        titulo="Concessão de Leitura do EVE",
        ok=ok,
        detalhe=(
            f"Legível pelo processo (modo {modo_str})."
            if ok
            else "O eve.json existe, porém o processo não possui acesso adequado."
        ),
        acao=(
            f"Revise proprietário/permissões de {path_obj} e {path_obj.parent}."
            if not ok else ""
        ),
        critico=not ok,
        dados={"modo_octal": modo_str, "leitura_ok": r_ok, "diretorio_ok": parent_ok},
    )

def check_cursor_monitor(cursor_path: str | Path, eve_path: str | Path) -> DiagnosticoItem:
    c_obj = Path(cursor_path)
    e_obj = Path(eve_path)

    if not c_obj.is_file():
        return DiagnosticoItem(
            id="cursor_monitor", grupo="Monitor MoonShield", titulo="Cursor de Sincronismo do Worker",
            ok=False, detalhe="Ausente.", acao="Se o monitor acabou de ligar, um cursor será gerado após o primeiro pacote lido.", critico=False
        )

    if not os.access(c_obj, os.R_OK):
        return DiagnosticoItem(
            id="cursor_monitor", grupo="Monitor MoonShield", titulo="Cursor de Sincronismo do Worker",
            ok=False, detalhe="Arquivo de cursor existe, mas não está legível.", acao="Ajuste permissões na pasta var/cursors e reinicie o monitor.", critico=False
        )

    offset = -1
    try:
        with open(c_obj, "r", encoding="utf-8") as f:
            dados = json.load(f)
            offset = dados.get("offset", -1)
    except Exception as e:
        return DiagnosticoItem(
            id="cursor_monitor", grupo="Monitor MoonShield", titulo="Cursor de Sincronismo do Worker",
            ok=False, detalhe="Cursor ainda não pôde ser interpretado.", acao=f"Recrie o cursor se o monitor não se recuperar sozinho. Erro: {e}", critico=False
        )

    if not isinstance(offset, int) or offset < 0:
        return DiagnosticoItem(
            id="cursor_monitor", grupo="Monitor MoonShield", titulo="Cursor de Sincronismo do Worker",
            ok=False, detalhe="Offset ainda não inicializado ou inválido.", acao="O monitor deve recriar/ajustar o cursor; se persistir, resete-o.", critico=False
        )

    tam_eve = 0
    try:
        if e_obj.is_file():
            tam_eve = e_obj.stat().st_size
    except OSError:
        pass

    if tam_eve > 0 and offset > tam_eve:
         return DiagnosticoItem(
            id="cursor_monitor", grupo="Monitor MoonShield", titulo="Cursor de Sincronismo do Worker",
            ok=False, detalhe=f"Extravasamento: Offset ({offset}) é maior que o Arquivo EVE ({tam_eve}).",
            acao="Provável rotação/truncamento do eve.json. Se persistir, resete o cursor.", critico=False
        )

    return DiagnosticoItem(
        id="cursor_monitor", grupo="Monitor MoonShield", titulo="Cursor de Sincronismo do Worker",
        ok=True, detalhe=f"Sintaxe Válida (Posição: {offset:,} bytes).", acao="", critico=False,
        dados={"offset": offset}
    )


def check_monitor_lendo_eve(cursor_path: str | Path, eve_path: str | Path) -> DiagnosticoItem:
    c_obj = Path(cursor_path)
    e_obj = Path(eve_path)

    if not c_obj.is_file() or not e_obj.is_file():
        return DiagnosticoItem(
            id="monitor_lendo_eve", grupo="Monitor MoonShield", titulo="Consumo Contínuo de Dados",
            ok=False, detalhe="Arquivos ainda não gerados.", acao="", critico=False
        )

    idade_c = _idade_arquivo(c_obj) or 0.0
    idade_e = _idade_arquivo(e_obj) or 0.0
    
    offset = 0
    try:
        with open(c_obj, "r") as f:
            offset = json.load(f).get("offset", 0)
    except Exception:
        pass

    tam_eve = 0
    try:
        tam_eve = e_obj.stat().st_size
    except OSError:
        pass

    atraso_bytes = tam_eve - offset
    
    # Regras Lógicas de Atraso
    ok = True
    crit = False
    detalhe = "Worker devidamente engatado no pipeline."
    acao = ""
    
    if offset > tam_eve:
        ok = False
        crit = True
        detalhe = "Dissonância: Cursor avançado alem do log."
    elif atraso_bytes > 0:
        # Se tem bytes novos e o cursor for mt velho e o eve mt novo (log avançou mas o worker parou)
        if idade_c > 60 and idade_e < 10:
            ok = False
            crit = False
            detalhe = f"Backlog de {atraso_bytes:,} bytes ainda não processados."
            acao = (
                "O monitor pode estar inicializando ou recuperando backlog. "
                "Se persistir por vários minutos, veja journalctl -u moonshield-suricata-monitor."
            )
        elif atraso_bytes > (50 * 1024 * 1024): # 50MB
            ok = False
            crit = False # Aviso
            detalhe = f"Alto volume pendente ({atraso_bytes // 1024 // 1024} MB)."
            acao = "Sistema ingerindo pacote pesado. O BD pode estar afunilando a conversão."
    
    return DiagnosticoItem(
        id="monitor_lendo_eve",
        grupo="Monitor MoonShield",
        titulo="Consumo Contínuo de Dados",
        ok=ok,
        detalhe=detalhe,
        acao=acao,
        critico=crit,
        dados={"cursor": offset, "tamanho_eve": tam_eve, "atraso_bytes": atraso_bytes, "idade_cursor": idade_c, "idade_eve": idade_e}
    )


# ==============================================================================
# TOPOLOGIA EXTRA / CUSTOMS DO ANTIGO DIAGNÓSTICO
# ==============================================================================

def check_dns_interno(configuracao: ConfiguracaoSuricataDados | None) -> DiagnosticoItem:
    if not configuracao:
        return DiagnosticoItem(
            id="dns_interno", grupo="Topologia", titulo="Bypass de DNS Interno",
            ok=False, detalhe="Configuração não submetida.", acao="", critico=False
        )
        
    dns = configuracao.dns_interno
    if not dns:
        return DiagnosticoItem(
            id="dns_interno", grupo="Topologia", titulo="Bypass de DNS Interno",
            ok=False, detalhe="Opcional: Não definido.", acao="Configure o IP do Gateway caso seu router spamme alertas de DNS constantes.", critico=False
        )

    import ipaddress
    try:
        ip_obj = ipaddress.IPv4Address(dns)
        # Bate IP do DNS dentro de alguma rede do HomeNet
        pertence = False
        for net in configuracao.home_net:
            if ip_obj in ipaddress.IPv4Network(net, strict=False):
                pertence = True
                break
                
        if pertence:
            return DiagnosticoItem(
                id="dns_interno", grupo="Topologia", titulo="Bypass de DNS Interno",
                ok=True, detalhe=f"IP Valido e contido no HOME_NET ({dns}).", acao="", critico=False
            )
        else:
            return DiagnosticoItem(
                id="dns_interno", grupo="Topologia", titulo="Bypass de DNS Interno",
                ok=False, detalhe=f"IP {dns} é válido porém não está dentro do address-group do HOME_NET.", acao="Forneça um IP coerente com as interfaces LAN ou ajuste o HOME_NET.", critico=False
            )
    except ValueError:
        return DiagnosticoItem(
            id="dns_interno", grupo="Topologia", titulo="Bypass de DNS Interno",
            ok=False, detalhe=f"String '{dns}' não compõe um endereço de IPv4 legítimo.", acao="Corrija a formatação do IP.", critico=False
        )


def check_bypass_dns_configurado(yaml_path: str | Path, dns_interno: str = "") -> DiagnosticoItem:
    if not dns_interno:
        return DiagnosticoItem(
            id="bypass_dns", grupo="Configuração", titulo="Regras de Isenção DNS no YAML",
            ok=False, detalhe="Não requerido (DNS interno não preenchido).", acao="", critico=False
        )

    p_obj = Path(yaml_path)
    if not p_obj.is_file():
        return DiagnosticoItem(
            id="bypass_dns", grupo="Configuração", titulo="Regras de Isenção DNS no YAML",
            ok=False, detalhe="Arquivo Mestre ausente.", acao="", critico=False
        )

    try:
        conteudo = p_obj.read_text(encoding="utf-8", errors="ignore")
        if "moonshield/ms.rules" in conteudo:
            return DiagnosticoItem(
                id="bypass_dns", grupo="Configuração", titulo="Regras de Isenção DNS no YAML",
                ok=True, detalhe="Assinaturas MS customizadas devidamente acopladas na Engine.", acao="", critico=False
            )
        return DiagnosticoItem(
            id="bypass_dns", grupo="Configuração", titulo="Regras de Isenção DNS no YAML",
            ok=False, detalhe="rule-files não chama ms.rules. Os drops de false-positive não atuarão.", acao="Ative as MS rules via Onboarding.", critico=False
        )
    except OSError:
        return DiagnosticoItem(
            id="bypass_dns", grupo="Configuração", titulo="Regras de Isenção DNS no YAML",
            ok=False, detalhe="Leitura bloqueada por disco/SO.", acao="", critico=False
        )


def check_validacao_suricata(yaml_path: str | Path) -> DiagnosticoItem:
    if not Path(yaml_path).is_file():
         return DiagnosticoItem(
            id="suricata_t", grupo="Configuração", titulo="Integração (Dry-Run / Suricata -T)",
            ok=False, detalhe="YAML ausente, impossivel testar Engine.", acao="Aguardando deploy de configurações.", critico=True
        )
         
    res_val = validar_configuracao(yaml_path)
    return _converter_resultado_etapa_em_check(res_val, "suricata_t", "Configuração", critico=True)


# ==============================================================================
# ORQUESTRADORES DE ROTINAS DE DIAGNÓSTICO
# ==============================================================================


def _criar_check_aviso_interno(grupo: str, detalhe_erro: str) -> DiagnosticoItem:
    """Falha de coleta de telemetria não deve invalidar a instalação base."""
    return DiagnosticoItem(
        id=f"aviso_interno_{grupo.lower().replace(' ', '_')}",
        grupo=grupo,
        titulo=f"Coleta temporariamente indisponível: {grupo}",
        ok=False,
        detalhe=f"A telemetria não pôde ser coletada nesta tentativa: {detalhe_erro}",
        acao="Repita o diagnóstico após alguns segundos.",
        critico=False,
    )


def diagnosticar_eve(
    eve_path: str | Path,
    cursor_path: str | Path | None = None,
) -> list[DiagnosticoItem]:
    """
    Health-checks da malha EVE/monitor.

    EVE e cursor dependem de tráfego e timing pós-start. Condições transitórias
    ficam como aviso. Erros determinísticos de engine/configuração/serviço
    continuam críticos nos módulos especialistas.
    """
    checks: list[DiagnosticoItem] = []

    try:
        checks.append(check_eve_existe(eve_path))
    except Exception as e:
        checks.append(_criar_check_aviso_interno("EVE", str(e)))

    try:
        checks.append(check_eve_atualizacao(eve_path))
    except Exception as e:
        checks.append(_criar_check_aviso_interno("EVE", str(e)))

    try:
        checks.append(check_eve_json_valido(eve_path))
    except Exception as e:
        checks.append(_criar_check_aviso_interno("EVE", str(e)))

    try:
        checks.append(check_tipos_eve(eve_path))
    except Exception as e:
        checks.append(_criar_check_aviso_interno("EVE", str(e)))

    try:
        checks.append(check_permissao_eve(eve_path))
    except Exception as e:
        checks.append(_criar_check_aviso_interno("EVE", str(e)))

    if cursor_path:
        try:
            checks.append(check_cursor_monitor(cursor_path, eve_path))
        except Exception as e:
            checks.append(_criar_check_aviso_interno("Monitor MoonShield", str(e)))

        try:
            checks.append(check_monitor_lendo_eve(cursor_path, eve_path))
        except Exception as e:
            checks.append(_criar_check_aviso_interno("Monitor MoonShield", str(e)))

    return checks

def executar_diagnostico(
    configuracao: ConfiguracaoSuricataDados | None = None,
    yaml_path: str | Path | None = None,
    eve_path: str | Path | None = None,
    cursor_path: str | Path | None = None,
    incluir_validacao_suricata: bool = True,
    incluir_checks_eve: bool = True,
    incluir_checks_servicos: bool = True,
) -> ResultadoDiagnostico:
    """Invoca globalmente as inspeções de TODOS os módulos do microsserviço."""
    iniciado = time.monotonic()
    diag = ResultadoDiagnostico()
    
    # Resolvers Inteligentes de Caminho
    if not yaml_path:
        yaml_path = configuracao.yaml_path if configuracao else None
        yaml_path = localizar_suricata_yaml(yaml_path)
    
    if not eve_path:
        eve_path = configuracao.eve_path if configuracao else None
        eve_path = localizar_eve_json(eve_path) or "/var/log/suricata/eve.json"

    if not cursor_path:
        # ConfiguracaoSuricataDados atual não possui cursor_path.
        # Resolve de forma compatível com versões futuras do DTO e usa
        # o cursor padrão do projeto quando o campo não estiver disponível.
        cursor_raw = getattr(configuracao, "cursor_path", "") if configuracao else ""

        raiz_projeto = (
            Path(__file__)
            .resolve()
            .parent
            .parent
            .parent
            .parent
            .parent
        )

        if cursor_raw:
            cursor_resolvido = Path(str(cursor_raw)).expanduser()
            if not cursor_resolvido.is_absolute():
                cursor_resolvido = raiz_projeto / cursor_resolvido
            cursor_path = cursor_resolvido
        else:
            cursor_path = raiz_projeto / "var/cursors/suricata_eve.cursor"

    # ================== MÓDULOS BASE ==================
    try:
        diag.itens.extend(gerar_checks_ambiente())
    except Exception as e:
        diag.adicionar(_criar_check_erro_interno("Sistema", str(e)))

    try:
        diag.itens.extend(gerar_checks_interfaces(configuracao))
    except Exception as e:
        diag.adicionar(_criar_check_erro_interno("Interfaces", str(e)))

    try:
        diag.itens.extend(gerar_checks_regras())
    except Exception as e:
        diag.adicionar(_criar_check_erro_interno("Regras", str(e)))

    try:
        # A API do check aceita os argumentos mesmo que sejam nulos, a inteligencia ta dentro dela.
        esperados_home = configuracao.home_net if configuracao else None
        esperados_mon = configuracao.interfaces_monitoradas if configuracao else None
        diag.itens.extend(gerar_checks_configuracao(yaml_path, esperados_home, esperados_mon))
    except Exception as e:
        diag.adicionar(_criar_check_erro_interno("Configuração", str(e)))

    # ================== OPCIONAIS CONDICIONADOS ==================
    if incluir_checks_servicos:
        try:
            diag.itens.extend(gerar_checks_servicos())
        except Exception as e:
            diag.adicionar(_criar_check_erro_interno("Serviços", str(e)))

    if incluir_checks_eve:
        diag.itens.extend(diagnosticar_eve(eve_path, cursor_path))

    if incluir_validacao_suricata and yaml_path:
        try:
            diag.adicionar(check_validacao_suricata(yaml_path))
        except Exception as e:
            diag.adicionar(_criar_check_erro_interno("Configuração", str(e)))

    # ================== CUSTOM TOPOLOGIA ==================
    try:
        diag.adicionar(check_dns_interno(configuracao))
        dns_str = configuracao.dns_interno if configuracao else ""
        if yaml_path:
            diag.adicionar(check_bypass_dns_configurado(yaml_path, dns_str))
    except Exception as e:
        diag.adicionar(_criar_check_erro_interno("Topologia", str(e)))

    # ================== LIMPEZA E FORMATAÇÃO ==================
    diag.itens = remover_checks_duplicados(diag.itens)
    diag.itens = ordenar_checks(diag.itens)
    diag.duracao_segundos = time.monotonic() - iniciado
    
    return diag



def executar_diagnostico_resumido(
    configuracao: ConfiguracaoSuricataDados | None = None,
) -> dict[str, object]:
    """
    Executa o diagnóstico uma vez e devolve um resumo matematicamente
    consistente para o painel.
    """
    resultado = executar_diagnostico(configuracao)
    return _resumir_resultado(resultado)


def obter_acoes_recomendadas(resultado: ResultadoDiagnostico) -> list[dict[str, object]]:
    """Gera um log sequencial de intervenção do usuário extraído dos checks não passados."""
    acoes = []
    vistos = set()
    
    for item in resultado.itens:
        if item.ok or not item.acao:
            continue
            
        assinatura = f"{item.grupo}_{item.acao}"
        if assinatura in vistos:
            continue
        vistos.add(assinatura)
        
        prioridade = 3
        if item.critico:
            prioridade = 1
        elif not item.ok:
            prioridade = 2
            
        acoes.append({
            "check_id": item.id,
            "grupo": item.grupo,
            "titulo": item.titulo,
            "acao": item.acao,
            "critico": item.critico,
            "prioridade": prioridade,
        })
        
    acoes.sort(key=lambda a: (a["prioridade"], a["grupo"]))
    return acoes


def obter_status_diagnostico(
    configuracao: ConfiguracaoSuricataDados | None = None,
) -> dict[str, object]:
    """
    Integra dados operacionais e diagnóstico usando a MESMA execução.

    Antes este método executava o diagnóstico e, ao montar ``resumo``, executava
    tudo novamente. Isso podia gerar contadores divergentes e dobrava o custo de
    I/O. Agora o snapshot é único.
    """
    resultado = executar_diagnostico(configuracao)
    resumo = _resumir_resultado(resultado)

    return {
        "resultado": _serializar_resultado(resultado),
        "resumo": resumo,
        "acoes_recomendadas": obter_acoes_recomendadas(resultado),
        "ambiente": detectar_ambiente_completo(),
        "topologia": obter_topologia_detectada(incluir_virtuais=True).to_dict(),
        "regras": obter_status_regras_completo(),
        "configuracao": obter_status_configuracao(),
        "servicos": obter_status_stack(),
    }


def diagnostico_para_api(
    configuracao: ConfiguracaoSuricataDados | None = None,
) -> dict[str, object]:
    """
    Contrato REST estável para a interface de diagnóstico do Suricata.

    O frontend recebe contadores explícitos de saudáveis, avisos e críticos.
    Nenhuma severidade precisa ser inferida no JavaScript.
    """
    try:
        resultado = executar_diagnostico(configuracao)
        resumo = _resumir_resultado(resultado)
        acoes = obter_acoes_recomendadas(resultado)

        return {
            "ok": True,
            "pronto": bool(resultado.pronto),
            "mensagem": resumo["mensagem"],
            "diagnostico": _serializar_resultado(resultado),
            "resumo": resumo,
            "acoes": acoes,
            # Alias para consumidores antigos.
            "acoes_recomendadas": acoes,
        }

    except Exception as e:
        logger.exception(
            "Falha não tratada ao compor diagnóstico para API web."
        )
        return {
            "ok": False,
            "pronto": False,
            "mensagem": (
                "Erro estrutural interno durante consolidação de health-checks."
            ),
            "diagnostico": {},
            "resumo": {
                "pronto": False,
                "total_checks": 0,
                "total_ok": 0,
                "total_saudaveis": 0,
                "total_avisos": 0,
                "total_falhas": 0,
                "total_criticos": 0,
                "score_integridade": 0,
                "score": 0,
                "falhas_criticas": [],
                "avisos": [],
                "grupos": {},
                "duracao_segundos": 0.0,
                "executado_em": "",
                "mensagem": "Falha ao executar o diagnóstico.",
            },
            "acoes": [],
            "acoes_recomendadas": [],
            "erro": str(e),
        }