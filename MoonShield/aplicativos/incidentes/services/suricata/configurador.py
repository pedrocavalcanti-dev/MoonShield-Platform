"""
Módulo para gerenciamento, validação e manipulação do arquivo mestre suricata.yaml.
Todas as alterações no arquivo são feitas de forma atômica e idempotente,
com suporte a rollback automático caso o Suricata recuse a nova configuração.
"""

import os
import re
import shutil
import logging
import ipaddress
from datetime import datetime
from pathlib import Path

from .tipos import (
    ResultadoEtapa,
    StatusEtapa,
    NivelLog,
    DiagnosticoItem,
    ConfiguracaoSuricataDados,
)
from .comandos import executar_comando
from .ambiente import eh_linux, verificar_privilegios, localizar_suricata_yaml
from .interfaces import validar_topologia
from .regras import regras_moonshield_instaladas, REGRAS_DEST, REGRAS_DEST_ETC

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES
# ==============================================================================

MARCADOR_MOONSHIELD = "# == MOONSHIELD =="
MARCADOR_EVE = "# == MOONSHIELD: eve-log =="
MARCADOR_AF_PACKET = "# == MOONSHIELD: af-packet =="

NOME_REGRA_MOONSHIELD = "moonshield/ms.rules"
EVE_JSON_PADRAO = Path("/var/log/suricata/eve.json")
PCAP_DESABILITADO = "none"

TAMANHO_MAXIMO_YAML = 10 * 1024 * 1024  # 10 MB
BACKUP_SUFFIX = ".moonshield.bak"


# ==============================================================================
# LEITURA E ANÁLISE DO YAML
# ==============================================================================

def ler_yaml_suricata(caminho: str | Path) -> str:
    """Lê o arquivo de configuração mestre garantindo limites de segurança."""
    path_obj = Path(caminho)
    
    if not path_obj.exists():
        raise FileNotFoundError(f"Arquivo YAML não encontrado: {path_obj}")
    if not path_obj.is_file():
        raise ValueError(f"Caminho não é um arquivo regular: {path_obj}")
        
    tamanho = path_obj.stat().st_size
    if tamanho > TAMANHO_MAXIMO_YAML:
        raise ValueError(f"Arquivo excede limite de segurança ({TAMANHO_MAXIMO_YAML} bytes).")
        
    try:
        return path_obj.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        raise OSError(f"Erro ao ler arquivo YAML: {e}")


def analisar_yaml_suricata(conteudo: str) -> dict[str, object]:
    """Extrai passivamente os componentes vitais sem depender de uma biblioteca de parsing YAML estrita."""
    analise = {
        "home_net": [],
        "rule_files": [],
        "eve_log": {
            "presente": False,
            "enabled": False,
            "filename": "",
            "tipos": [],
        },
        "af_packet": {
            "presente": False,
            "interfaces": [],
        },
        "pcap": {
            "presente": False,
            "interfaces": [],
        },
        "referencia_moonshield": False,
        "marcadores_moonshield": [],
    }

    # 1. HOME_NET
    m_home = re.search(r"^[ \t]*HOME_NET:\s*(.+)$", conteudo, flags=re.MULTILINE)
    if m_home:
        valor_limpo = m_home.group(1).strip().strip('"').strip("'").strip("[").strip("]")
        if valor_limpo and valor_limpo.lower() != "any":
            analise["home_net"] = [v.strip() for v in valor_limpo.split(",") if v.strip()]

    # 2. rule-files e referência MS
    analise["referencia_moonshield"] = NOME_REGRA_MOONSHIELD in conteudo
    bloco_rules_match = re.search(r"^rule-files:\n(?:^[ \t]+-.*\n)*", conteudo, flags=re.MULTILINE)
    if bloco_rules_match:
        linhas = bloco_rules_match.group(0).splitlines()[1:]
        for linha in linhas:
            m_rule = re.match(r"^[ \t]+-\s+(.+)$", linha)
            if m_rule:
                analise["rule_files"].append(m_rule.group(1).strip())

    # 3. af-packet
    bloco_af_match = re.search(r"^af-packet:\n(?:^[ \t].*\n)*", conteudo, flags=re.MULTILINE)
    if bloco_af_match:
        analise["af_packet"]["presente"] = True
        linhas_af = bloco_af_match.group(0).splitlines()[1:]
        for linha in linhas_af:
            m_iface = re.match(r"^[ \t]+-\s+interface:\s+(.+)$", linha)
            if m_iface:
                analise["af_packet"]["interfaces"].append(m_iface.group(1).strip())

    # 4. pcap
    bloco_pcap_match = re.search(r"^pcap:\n(?:^[ \t].*\n)*", conteudo, flags=re.MULTILINE)
    if bloco_pcap_match:
        analise["pcap"]["presente"] = True
        linhas_pcap = bloco_pcap_match.group(0).splitlines()[1:]
        for linha in linhas_pcap:
            m_iface = re.match(r"^[ \t]+-\s+interface:\s+(.+)$", linha)
            if m_iface:
                analise["pcap"]["interfaces"].append(m_iface.group(1).strip())

    # 5. eve-log
    # Pega qualquer bloco que declare `- eve-log:` até a próxima saída top-level ou output novo
    m_eve = re.search(r"^[ \t]+-\s+eve-log:\n(?:^[ \t]{4,}.*\n)*", conteudo, flags=re.MULTILINE)
    if m_eve:
        bloco_eve = m_eve.group(0)
        analise["eve_log"]["presente"] = True
        
        m_enabled = re.search(r"^[ \t]+enabled:\s+(yes|no)", bloco_eve, flags=re.MULTILINE | re.IGNORECASE)
        if m_enabled and m_enabled.group(1).lower() == "yes":
            analise["eve_log"]["enabled"] = True
            
        m_file = re.search(r"^[ \t]+filename:\s+(.+)$", bloco_eve, flags=re.MULTILINE)
        if m_file:
            analise["eve_log"]["filename"] = m_file.group(1).strip()
            
        # Tenta extrair tipos listados rudimentarmente
        m_types = re.search(r"^[ \t]+types:\n((?:^[ \t]+-.*\n)*)", bloco_eve, flags=re.MULTILINE)
        if m_types:
            for linha in m_types.group(1).splitlines():
                m_t = re.match(r"^[ \t]+-\s+([a-zA-Z0-9_]+)", linha)
                if m_t:
                    analise["eve_log"]["tipos"].append(m_t.group(1).lower())

    # 6. Marcadores
    if MARCADOR_MOONSHIELD in conteudo:
        analise["marcadores_moonshield"].append(MARCADOR_MOONSHIELD)
    if MARCADOR_EVE in conteudo:
        analise["marcadores_moonshield"].append(MARCADOR_EVE)
    if MARCADOR_AF_PACKET in conteudo:
        analise["marcadores_moonshield"].append(MARCADOR_AF_PACKET)

    return analise


# ==============================================================================
# GESTÃO DE REDES (NORMALIZAÇÃO)
# ==============================================================================

def validar_home_net(redes: list[str]) -> list[str]:
    """Valida a integridade semântica dos blocos CIDR sugeridos para o HOME_NET."""
    erros = []
    if not redes:
        erros.append("A lista de redes está vazia.")
        return erros

    vistos = set()
    for rede in redes:
        rede_limpa = str(rede).strip()
        if not rede_limpa:
            erros.append("Entrada de rede vazia detectada.")
            continue
            
        if rede_limpa in vistos:
            erros.append(f"Rede duplicada na lista: {rede_limpa}")
            continue
            
        vistos.add(rede_limpa)
        try:
            ipaddress.IPv4Network(rede_limpa, strict=False)
        except ValueError as e:
            erros.append(f"Rede IPv4 inválida ({rede_limpa}): {e}")
            
    return erros


def normalizar_home_net(redes: list[str]) -> list[str]:
    """Formata os CIDRs padronizando as notações de sub-rede e ordenando-as."""
    limpas = set()
    for rede in redes:
        r_str = str(rede).strip()
        if not r_str:
            continue
        try:
            net_obj = ipaddress.IPv4Network(r_str, strict=False)
            limpas.add(str(net_obj))
        except ValueError as e:
            raise ValueError(f"CIDR inválido ({r_str}): {e}")
            
    if not limpas:
        raise ValueError("Nenhuma rede válida após normalização.")
        
    return sorted(list(limpas))


def normalizar_interfaces(interfaces: list[str]) -> list[str]:
    """Sanitiza e valida nomes físicos ou lógicos de placas de rede fornecidos."""
    from .interfaces import validar_nome_interface
    limpas = []
    vistas = set()
    
    for iface in interfaces:
        nome = str(iface).strip()
        if not nome:
            continue
        if not validar_nome_interface(nome):
            raise ValueError(f"Nome de interface inválido: {nome}")
        if nome not in vistas:
            limpas.append(nome)
            vistas.add(nome)
            
    if not limpas:
        raise ValueError("A lista de interfaces requer ao menos um dispositivo válido.")
        
    return limpas


def gerar_valor_home_net(redes: list[str]) -> str:
    """Prepara a string do container (lista) exigida pela sintaxe do YAML Suricata."""
    redes_norm = normalizar_home_net(redes)
    return "[" + ",".join(redes_norm) + "]"


# ==============================================================================
# PATCHERS YAML (FUNÇÕES PURAS - IDEMPOTENTES)
# ==============================================================================

def patch_home_net(conteudo: str, home_net: list[str]) -> str:
    """Injeta a variável de HOME_NET dentro do bloco vars->address-groups."""
    valor_fmt = gerar_valor_home_net(home_net)
    nova_line = f'    HOME_NET: "{valor_fmt}"'

    # 1. Tenta substituir diretamente se já existir
    if re.search(r"^[ \t]*HOME_NET:", conteudo, flags=re.MULTILINE):
        return re.sub(
            r"^[ \t]*HOME_NET:\s*.*$",
            nova_line,
            conteudo,
            flags=re.MULTILINE
        )
        
    # 2. Insere dentro do address-groups caso o HOME_NET estivesse deletado
    if re.search(r"^[ \t]*address-groups:", conteudo, flags=re.MULTILINE):
        return re.sub(
            r"(^[ \t]*address-groups:\n)",
            r"\g<1>" + nova_line + "\n",
            conteudo,
            flags=re.MULTILINE,
            count=1
        )
        
    # 3. Reconstrói o namespace se nada existir (Cenário improvável mas seguro)
    return conteudo + "\nvars:\n  address-groups:\n" + nova_line + "\n"


def patch_rule_files(conteudo: str, regra: str = NOME_REGRA_MOONSHIELD) -> str:
    """Acopla as regras core do MoonShield à lista de carregamento do IDS."""
    entrada = f"  - {regra}"
    
    if entrada in conteudo or regra in conteudo:
        return conteudo
        
    bloco_vazio = "\nrule-files:\n" + entrada + "\n"
    
    if re.search(r"^rule-files:", conteudo, flags=re.MULTILINE):
        return re.sub(
            r"(^rule-files:\n)",
            r"\g<1>" + entrada + "\n",
            conteudo,
            flags=re.MULTILINE,
            count=1
        )
        
    return conteudo + bloco_vazio


def patch_eve_log(conteudo: str, eve_path: str | Path = EVE_JSON_PADRAO) -> str:
    """Implementa o sink JSON padrão para que o worker do Django possa ingerir os alertas e fluxos."""
    path_str = str(eve_path)
    if MARCADOR_EVE in conteudo and path_str in conteudo:
        # Se os marcadores existirem e o caminho bater, assume-se que está ok para manter idempotência simples
        if "alert" in conteudo and "dns:" in conteudo and "http:" in conteudo and "tls:" in conteudo:
            return conteudo

    EVE_BLOCK = (
        f"\n  {MARCADOR_EVE}\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      filetype: regular\n"
        f"      filename: {path_str}\n"
        "      types:\n"
        "        - alert\n"
        "        - dns:\n"
        "            query: yes\n"
        "            answer: yes\n"
        "        - http:\n"
        "            extended: yes\n"
        "        - tls:\n"
        "            extended: yes\n"
    )

    if re.search(r"^outputs:", conteudo, flags=re.MULTILINE):
        # Para evitar deletar fast.log/syslog, nós PREPEND no bloco de outputs
        return re.sub(
            r"(^outputs:\n)",
            r"\g<1>" + EVE_BLOCK,
            conteudo,
            flags=re.MULTILINE,
            count=1
        )
        
    return conteudo + "\noutputs:" + EVE_BLOCK


def gerar_bloco_af_packet(interfaces: list[str]) -> str:
    """Constrói os listeners em anel (cluster) para garantir captura multi-thread nas interfaces."""
    linhas = [
        "af-packet:",
        f"  {MARCADOR_AF_PACKET}"
    ]
    
    for i, iface in enumerate(interfaces):
        linhas.extend([
            f"  - interface: {iface}",
            "    threads: auto",
            f"    cluster-id: {99 + i}",
            "    cluster-type: cluster_flow",
            "    defrag: yes"
        ])
        
    return "\n".join(linhas) + "\n"


def patch_af_packet(conteudo: str, interfaces: list[str]) -> str:
    """Sobrescreve a configuração de captura física mantendo outras diretivas intactas."""
    ifaces_norm = normalizar_interfaces(interfaces)
    novo_bloco = gerar_bloco_af_packet(ifaces_norm)
    
    # Substitui af-packet top-level até a próxima chave top-level ou o fim
    if re.search(r"(?m)^af-packet:", conteudo):
        conteudo = re.sub(
            r"(?m)^af-packet:\n(?:^[ \t].*\n)*",
            novo_bloco,
            conteudo
        )
    else:
        conteudo += f"\n{novo_bloco}"
        
    return conteudo


def patch_pcap_desabilitado(conteudo: str) -> str:
    """Desativa a captura PCAP fallback evitando conflitos com o Ring do AF-Packet."""
    bloco_pcap = f"pcap:\n  - interface: {PCAP_DESABILITADO}\n"
    
    if re.search(r"(?m)^pcap:", conteudo):
        conteudo = re.sub(
            r"(?m)^pcap:\n(?:^[ \t].*\n)*",
            bloco_pcap,
            conteudo
        )
    else:
        conteudo += f"\n{bloco_pcap}"
        
    return conteudo


def gerar_yaml_configurado(
    conteudo_original: str,
    home_net: list[str],
    interfaces_monitoradas: list[str],
    eve_path: str | Path = EVE_JSON_PADRAO,
) -> str:
    """Cadeia funcional pura que aplica todos os patches MoonShield num payload textual de yaml."""
    c = conteudo_original
    c = patch_home_net(c, home_net)
    c = patch_rule_files(c)
    c = patch_eve_log(c, eve_path)
    c = patch_af_packet(c, interfaces_monitoradas)
    c = patch_pcap_desabilitado(c)
    
    if not c.endswith("\n"):
        c += "\n"
        
    return c


# ==============================================================================
# MANIPULAÇÃO DE BACKUPS E I/O ATÔMICO
# ==============================================================================

def criar_backup(caminho: str | Path, sobrescrever: bool = True) -> ResultadoEtapa:
    """Gera um snapshot idêntico do arquivo mestre para caso de failover da engine."""
    etapa_id = "backup_suricata"
    path_orig = Path(caminho)
    
    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Preparando backup para {path_orig.name}",
        iniciado_em=datetime.now()
    )

    if eh_linux() and not verificar_privilegios().sucesso:
        res.finalizar_erro("Privilégios insuficientes para criar backup de arquivos de sistema.")
        return res

    if not path_orig.is_file():
        res.finalizar_erro("O arquivo de origem não existe ou não é regular.", erro=str(path_orig))
        return res

    path_bak = path_orig.with_suffix(BACKUP_SUFFIX)
    
    if path_bak.exists() and not sobrescrever:
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        path_bak = path_orig.with_suffix(f"{BACKUP_SUFFIX}.{ts}")

    try:
        shutil.copy2(path_orig, path_bak)
        res.dados = {
            "origem": str(path_orig),
            "backup": str(path_bak),
            "tamanho": path_bak.stat().st_size
        }
        res.adicionar_log(f"Backup gravado em: {path_bak}", NivelLog.SUCESSO)
        res.finalizar_sucesso("Backup do suricata.yaml criado com sucesso.")
    except Exception as e:
        logger.exception("Falha na criação do backup.")
        res.finalizar_erro("Erro ao tentar copiar o arquivo de configuração.", erro=str(e))
        
    return res


def restaurar_backup(caminho_original: str | Path, caminho_backup: str | Path) -> ResultadoEtapa:
    """Mecanismo de Rollback: Restaura a cópia mestre do sistema."""
    etapa_id = "restaurar_backup_suricata"
    p_orig = Path(caminho_original)
    p_bak = Path(caminho_backup)

    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Iniciando processo de rollback.",
        iniciado_em=datetime.now()
    )

    if eh_linux() and not verificar_privilegios().sucesso:
        res.finalizar_erro("Privilégios insuficientes para aplicar rollback no sistema.")
        return res

    if not p_bak.is_file():
        res.finalizar_erro("O arquivo de backup não existe ou está inacessível.", erro=str(p_bak))
        return res

    temp_path = p_orig.with_suffix(".restoring.tmp")
    
    try:
        shutil.copy2(p_bak, temp_path)
        os.replace(temp_path, p_orig)
        
        res.dados = {"caminho_restaurado": str(p_orig)}
        res.adicionar_log("Cópia de backup promovida a arquivo principal.", NivelLog.SUCESSO)
        res.finalizar_sucesso("Rollback do suricata.yaml efetuado com sucesso.")
    except Exception as e:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        logger.exception("Falha catastrófica ao tentar reverter arquivo de configuração.")
        res.finalizar_erro("Falha ao restaurar o backup.", erro=str(e))

    return res


def _escrever_yaml_atomico(caminho: Path, conteudo: str) -> None:
    """Persiste as alterações textuais garantindo integridade e anti-corrupção FS."""
    if not caminho.parent.exists():
        raise FileNotFoundError(f"O diretório destino não existe: {caminho.parent}")
        
    temp_path = caminho.with_suffix(".writing.tmp")
    
    try:
        # Prepara modo base em caso de novo arquivo
        modo_atual = None
        uid_atual = None
        gid_atual = None
        
        if caminho.exists():
            stat_info = caminho.stat()
            modo_atual = stat_info.st_mode
            uid_atual = stat_info.st_uid
            gid_atual = stat_info.st_gid

        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(conteudo)
            f.flush()
            os.fsync(f.fileno())

        if eh_linux() and modo_atual is not None:
            try:
                os.chmod(temp_path, modo_atual)
                os.chown(temp_path, uid_atual, gid_atual)
            except OSError:
                pass

        os.replace(temp_path, caminho)
    except Exception as e:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise e


# ==============================================================================
# VALIDAÇÃO DO MESTRE (DRY-RUN DA ENGINE)
# ==============================================================================

def validar_configuracao(yaml_path: str | Path, timeout: float = 180.0) -> ResultadoEtapa:
    """Aciona a engine do Suricata localmente para compilar as regras e validar o YAML modificado."""
    etapa_id = "validar_configuracao_suricata"
    path_obj = Path(yaml_path)

    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem=f"Validando arquivo: {path_obj.name}",
        iniciado_em=datetime.now()
    )

    if not path_obj.is_file():
        res.finalizar_erro("Arquivo YAML inexistente.", erro=str(path_obj))
        return res

    resultado_cmd = executar_comando(
        ["suricata", "-T", "-c", str(path_obj)],
        timeout=timeout
    )
    
    saida = resultado_cmd.saida.strip()
    erros = [l.strip() for l in saida.split("\n") if l.strip().startswith("E:")]
    warns = [l.strip() for l in saida.split("\n") if l.strip().startswith("W:")]

    res.dados = {
        "yaml_path": str(path_obj),
        "stdout": resultado_cmd.stdout,
        "stderr": resultado_cmd.stderr,
        "erros": erros,
        "warnings": warns,
        "duracao": resultado_cmd.duracao_segundos
    }

    if resultado_cmd.sucesso:
        res.adicionar_log("Configuração YAML aceita pelo Suricata.", NivelLog.SUCESSO)
        res.finalizar_sucesso("Validação suricata -T concluída com sucesso.")
    else:
        msg_erro = erros[0] if erros else "Falha estrutural (timeout ou travamento)."
        res.adicionar_log(f"Erros de configuração: {msg_erro}", NivelLog.ERRO)
        res.finalizar_erro("Validação reprovou o arquivo de configuração.", erro=msg_erro)

    return res


# ==============================================================================
# ORQUESTRAÇÃO DE CONFIGURAÇÃO (ENTRYPOINTS DE ALTO NÍVEL)
# ==============================================================================

def aplicar_configuracao(
    yaml_path: str | Path,
    home_net: list[str],
    interfaces_monitoradas: list[str],
    eve_path: str | Path = EVE_JSON_PADRAO,
    criar_backup_antes: bool = True,
    validar_depois: bool = True,
    rollback_automatico: bool = True,
) -> ResultadoEtapa:
    """
    Fluxo transacional que lê, altera, persiste e testa a configuração base da máquina.
    Implementa Rollback em caso de rejeição pela engine do Suricata.
    """
    etapa_id = "aplicar_configuracao_suricata"
    path_obj = Path(yaml_path)

    res = ResultadoEtapa(
        etapa=etapa_id,
        status=StatusEtapa.EXECUTANDO,
        sucesso=False,
        mensagem="Iniciando aplicação controlada da configuração local.",
        iniciado_em=datetime.now()
    )

    # 1. Privilégios
    if eh_linux() and not verificar_privilegios().sucesso:
        res.finalizar_erro("Privilégios administrativos requeridos para manipular configurações.")
        return res

    # 2. Leitura
    try:
        conteudo_original = ler_yaml_suricata(path_obj)
    except Exception as e:
        res.finalizar_erro("Falha ao ler YAML fonte.", erro=str(e))
        return res

    estado_anterior = analisar_yaml_suricata(conteudo_original)
    
    res.dados = {
        "yaml_path": str(path_obj),
        "backup_path": "",
        "alterado": False,
        "rollback_executado": False,
        "estado_anterior": estado_anterior,
        "estado_final": {},
        "validacao": {}
    }

    # 3. Patching Lógico
    try:
        conteudo_novo = gerar_yaml_configurado(
            conteudo_original=conteudo_original,
            home_net=home_net,
            interfaces_monitoradas=interfaces_monitoradas,
            eve_path=eve_path
        )
    except Exception as e:
        res.finalizar_erro("Falha na formatação dos parâmetros.", erro=str(e))
        return res

    # 4. Idempotência
    if conteudo_novo == conteudo_original:
        res.dados["estado_final"] = estado_anterior
        res.finalizar_sucesso("Configuração idêntica a existente. Nenhuma alteração aplicada.")
        return res

    # 5. Backup Prévio
    if criar_backup_antes:
        res_bak = criar_backup(path_obj)
        if not res_bak.sucesso:
            res.finalizar_erro("Abortado pois o Snapshot/Backup de segurança falhou.", erro=res_bak.erro)
            return res
        res.dados["backup_path"] = res_bak.dados.get("backup", "")

    # 6. Aplicação (Escrita)
    try:
        _escrever_yaml_atomico(path_obj, conteudo_novo)
        res.dados["alterado"] = True
        res.adicionar_log("Arquivo mestre atualizado no disco.", NivelLog.INFO)
    except Exception as e:
        res.finalizar_erro("Falha na persistência atômica da configuração.", erro=str(e))
        return res

    # 7. Validação e Rollback
    if validar_depois:
        res_val = validar_configuracao(path_obj)
        res.dados["validacao"] = res_val.dados

        if not res_val.sucesso:
            res.adicionar_log("Engine reprovou a nova sintaxe/parametros.", NivelLog.ERRO)
            
            if rollback_automatico and res.dados["backup_path"]:
                res.adicionar_log("Acionando rotina de rollback automático...", NivelLog.AVISO)
                res_rb = restaurar_backup(path_obj, res.dados["backup_path"])
                res.dados["rollback_executado"] = res_rb.sucesso
                
                if res_rb.sucesso:
                    res.finalizar_erro("Configuração rejeitada. Rollback aplicado para proteger o serviço.", erro=res_val.erro)
                else:
                    res.finalizar_erro("Configuração rejeitada e Rollback FALHOU. Serviço comprometido.", erro=res_rb.erro)
            else:
                res.finalizar_erro("Configuração rejeitada. Rollback automático desativado.", erro=res_val.erro)
            return res

    # 8. Sucesso Final
    try:
        estado_final = analisar_yaml_suricata(conteudo_novo)
        res.dados["estado_final"] = estado_final
    except Exception:
        pass

    res.finalizar_sucesso("Nova topologia aplicada e validada com sucesso.")
    return res


def aplicar_configuracao_dados(configuracao: ConfiguracaoSuricataDados) -> ResultadoEtapa:
    """Orquestrador DTO->System. Traduz as escolhas validadas do Frontend/API para o FS."""
    erros = configuracao.validar()
    if erros:
        res = ResultadoEtapa("aplicar_configuracao_dados", StatusEtapa.ERRO, False, "Payload Inválido", iniciado_em=datetime.now())
        res.finalizar_erro("Dados estruturais rejeitados.", erro="; ".join(erros))
        return res
        
    return aplicar_configuracao(
        yaml_path=configuracao.yaml_path,
        home_net=configuracao.home_net,
        interfaces_monitoradas=configuracao.interfaces_monitoradas,
        eve_path=configuracao.eve_path
    )


# ==============================================================================
# AUDITORIA PASSIVA
# ==============================================================================

def obter_status_configuracao(yaml_path: str | Path | None = None) -> dict[str, object]:
    """Levantamento read-only de alinhamento entre o yaml físico e o compliance MoonShield."""
    path_obj = localizar_suricata_yaml(yaml_path)
    
    info = {
        "yaml_path": str(path_obj) if path_obj else "",
        "existe": False,
        "legivel": False,
        "tamanho": 0,
        "analise": {},
        "backup": {
            "caminho": "",
            "existe": False,
            "tamanho": 0,
        },
        "moonshield_configurado": False,
        "avisos": [],
    }

    if not path_obj or not path_obj.is_file():
        info["avisos"].append("Arquivo YAML principal não foi detectado no sistema.")
        return info

    info["existe"] = True
    info["legivel"] = os.access(path_obj, os.R_OK)
    
    if not info["legivel"]:
        info["avisos"].append("Arquivo existe mas o acesso de leitura é negado (PermissionError).")
        return info

    info["tamanho"] = path_obj.stat().st_size
    
    try:
        conteudo = ler_yaml_suricata(path_obj)
        info["analise"] = analisar_yaml_suricata(conteudo)
    except Exception as e:
        info["avisos"].append(f"Falha técnica ao analisar conteúdo do YAML: {e}")
        return info

    # Compliance
    an = info["analise"]
    chk_home = bool(an.get("home_net"))
    chk_regras = bool(an.get("referencia_moonshield"))
    chk_eve = an.get("eve_log", {}).get("enabled")
    
    chk_tipos_eve = False
    tipos = an.get("eve_log", {}).get("tipos", [])
    if "alert" in tipos and "dns" in tipos and "http" in tipos and "tls" in tipos:
        chk_tipos_eve = True

    chk_af = an.get("af_packet", {}).get("presente") and len(an.get("af_packet", {}).get("interfaces", [])) > 0
    
    chk_pcap_off = False
    pcap = an.get("pcap", {})
    if pcap.get("presente") and len(pcap.get("interfaces", [])) == 1 and pcap.get("interfaces")[0] == PCAP_DESABILITADO:
        chk_pcap_off = True
    elif not pcap.get("presente"):
        # Se pcap nem existe, também não interfere
        chk_pcap_off = True

    if chk_home and chk_regras and chk_eve and chk_tipos_eve and chk_af and chk_pcap_off:
        info["moonshield_configurado"] = True
    else:
        info["avisos"].append("As configurações internas do YAML estão divergentes ou incompletas perante o Baseline MoonShield.")

    # Status de Backup
    path_bak = path_obj.with_suffix(BACKUP_SUFFIX)
    info["backup"]["caminho"] = str(path_bak)
    if path_bak.is_file():
        info["backup"]["existe"] = True
        info["backup"]["tamanho"] = path_bak.stat().st_size

    return info


def gerar_checks_configuracao(
    yaml_path: str | Path | None = None,
    home_net_esperado: list[str] | None = None,
    interfaces_esperadas: list[str] | None = None,
) -> list[DiagnosticoItem]:
    """Mapeia o compliance estrutural para itens de checkup visual web."""
    itens = []
    status = obter_status_configuracao(yaml_path)
    an = status.get("analise", {})

    # 1. Básico YAML
    ok_yaml = status["existe"]
    itens.append(DiagnosticoItem(
        id="yaml_encontrado", grupo="Configuração", titulo="Arquivo Mestre (suricata.yaml)",
        ok=ok_yaml, detalhe=status["yaml_path"], acao="Crie o arquivo ou aponte o local correto.", critico=True
    ))

    ok_legivel = status["legivel"]
    itens.append(DiagnosticoItem(
        id="yaml_legivel", grupo="Configuração", titulo="Permissões de Leitura",
        ok=ok_legivel, detalhe="Legível.", acao="Altere as permissões do arquivo via chmod.", critico=True
    ))

    if not ok_yaml or not ok_legivel:
        return itens

    # 2. HOME_NET
    home = an.get("home_net", [])
    ok_home = len(home) > 0
    itens.append(DiagnosticoItem(
        id="home_net_configurado", grupo="Configuração", titulo="Detecção de HOME_NET (Topologia Base)",
        ok=ok_home, detalhe=", ".join(home) if ok_home else "Vazio ou ausente.",
        acao="Defina o address-group HOME_NET para validar as assinaturas direcionais.", critico=True
    ))

    if home_net_esperado is not None:
        ok_match_home = sorted(home) == normalizar_home_net(home_net_esperado)
        itens.append(DiagnosticoItem(
            id="home_net_corresponde", grupo="Configuração", titulo="Consistência do HOME_NET com Projeto",
            ok=ok_match_home, detalhe="Configuração alinhada ao Banco de Dados.",
            acao="Aplique os patches ou revise a topologia no painel.", critico=True
        ))

    # 3. Regras
    ok_ref_ms = an.get("referencia_moonshield", False)
    itens.append(DiagnosticoItem(
        id="regra_moonshield_referenciada", grupo="Configuração", titulo="Ativação do Rule-File MoonShield",
        ok=ok_ref_ms, detalhe="moonshield/ms.rules ativado na diretiva rule-files.",
        acao="Inclua a rule no arquivo mestre para utilizar as assinaturas proprietárias.", critico=True
    ))

    # 4. EVE (Log / Pipeline Input)
    eve_log = an.get("eve_log", {})
    ok_eve = eve_log.get("enabled", False)
    itens.append(DiagnosticoItem(
        id="eve_log_presente", grupo="EVE", titulo="Mecanismo de Output JSON (EVE-Log)",
        ok=ok_eve, detalhe=f"Habilitado gravando em {eve_log.get('filename')}",
        acao="Ative a diretiva eve-log para alimentar o banco de incidentes.", critico=True
    ))

    tipos = eve_log.get("tipos", [])
    ok_tipos = all(t in tipos for t in ("alert", "dns", "http", "tls"))
    itens.append(DiagnosticoItem(
        id="eve_tipos_obrigatorios", grupo="EVE", titulo="Metadados de Rede Capturados",
        ok=ok_tipos, detalhe=f"Subprotocolos: {', '.join(tipos)}",
        acao="O MoonShield requer ao menos os logs de alert, dns, http e tls habilitados no output.", critico=True
    ))

    # 5. Captura (AF-Packet)
    af = an.get("af_packet", {})
    ok_af = af.get("presente", False)
    itens.append(DiagnosticoItem(
        id="af_packet_presente", grupo="Captura", titulo="Driver de Aceleração AF-Packet",
        ok=ok_af, detalhe="Configuração base af-packet disponível.",
        acao="Defina blocos af-packet para capturar direto no ring-buffer do Linux.", critico=True
    ))

    if interfaces_esperadas is not None and ok_af:
        ifaces = af.get("interfaces", [])
        try:
            exp_norm = normalizar_interfaces(interfaces_esperadas)
            ok_ifaces = sorted(ifaces) == sorted(exp_norm)
            itens.append(DiagnosticoItem(
                id="interfaces_af_packet", grupo="Captura", titulo="Portas Af-Packet Monitoradas",
                ok=ok_ifaces, detalhe=f"Sincronizado: {', '.join(ifaces)}",
                acao="Há divergência nas interfaces ouvintes.", critico=True
            ))
        except ValueError:
            pass

    # 6. PCAP Fallback
    pcap = an.get("pcap", {})
    ok_pcap = not pcap.get("presente") or (len(pcap.get("interfaces", [])) == 1 and pcap.get("interfaces")[0] == PCAP_DESABILITADO)
    itens.append(DiagnosticoItem(
        id="pcap_desabilitado", grupo="Captura", titulo="Isolamento de Legacy Driver (PCAP)",
        ok=ok_pcap, detalhe="PCAP explicitamente desativado (Safe).",
        acao="A presença do PCAP pode causar double-capture com o AF-Packet.", critico=False
    ))

    # 7. Backup
    ok_bak = status["backup"]["existe"]
    itens.append(DiagnosticoItem(
        id="backup_disponivel", grupo="Configuração", titulo="Snapshot de Segurança (Backup)",
        ok=ok_bak, detalhe=f"{status['backup']['tamanho']:,} bytes protegidos." if ok_bak else "Sem fallback de configuração.",
        acao="Recomendado garantir ao menos um snapshot para rollback seguro.", critico=False
    ))

    return itens