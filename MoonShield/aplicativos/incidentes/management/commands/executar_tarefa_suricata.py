"""
Management Command do Django para executar orquestrações do Suricata.
Atua de forma síncrona na CLI, servindo de ponte direta aos módulos nativos de serviços,
executando regras de privilégios, confirmações seguras (interactive stdin) e output estruturado.
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from enum import Enum

from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections, transaction
from django.utils import timezone as django_timezone

from incidentes.models import (
    ConfiguracaoSuricata,
    LogTarefaSuricata,
    NivelLogSuricata,
    StatusTarefaSuricata,
    TarefaSuricata,
)

from incidentes.services.suricata.tipos import (
    TipoTarefaSuricata,
    ConfiguracaoSuricataDados,
    ModoCaptura,
    StatusEtapa,
)

from incidentes.services.suricata.tarefas import (
    criar_progresso_tarefa,
    executar_tarefa,
    executar_tarefa_seca,
    obter_tipos_tarefa_disponiveis,
    validar_parametros_tarefa,
    converter_tipo_tarefa,
    configuracao_de_dict,
    resumir_tarefa,
)

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTES OBRIGATÓRIAS
# ==============================================================================

TIPOS_COM_CONFIGURACAO = {
    TipoTarefaSuricata.INSTALACAO,
    TipoTarefaSuricata.CONFIGURACAO,
}

TIPOS_PRIVILEGIADOS = {
    TipoTarefaSuricata.INSTALACAO,
    TipoTarefaSuricata.CONFIGURACAO,
    TipoTarefaSuricata.ATUALIZACAO_REGRAS,
    TipoTarefaSuricata.REINICIO_SURICATA,
    TipoTarefaSuricata.REINICIO_MONITOR,
}

FORMATOS_SAIDA = {
    "texto",
    "json",
}

MAX_MENSAGEM_BANCO = 4000
MAX_ERRO_BANCO = 8000
MAX_LOG_MENSAGEM = 1000
MAX_LOG_ETAPA = 100


# ==============================================================================
# HIGIENIZAÇÃO GLOBAL PARA OUTPUT DE CLI
# ==============================================================================

def _sanitizar_para_saida(valor: object) -> object:
    """Higieniza de ponta a ponta mascarando segredos e unificando instâncias p/ JSON Serialization."""
    chaves_sensitivas = {"password", "senha", "token", "secret", "authorization", "api_key"}

    if isinstance(valor, Enum):
        return valor.value
    if isinstance(valor, Path):
        return str(valor)
    if isinstance(valor, datetime):
        return valor.isoformat()
    if hasattr(valor, "to_dict") and callable(getattr(valor, "to_dict")):
        return valor.to_dict()
    if hasattr(valor, "__dataclass_fields__"):
        import dataclasses
        return dataclasses.asdict(valor)
    if isinstance(valor, set):
        return sorted(list(valor))
    if isinstance(valor, bytes):
        return valor.decode("utf-8", errors="replace")
        
    if isinstance(valor, dict):
        limpo = {}
        for k, v in valor.items():
            if str(k).lower() in chaves_sensitivas:
                limpo[k] = "***"
            else:
                limpo[k] = _sanitizar_para_saida(v)
        return limpo
        
    if isinstance(valor, list):
        return [_sanitizar_para_saida(item) for item in valor]
    if isinstance(valor, tuple):
        return tuple(_sanitizar_para_saida(item) for item in valor)
        
    return valor



# ==============================================================================
# PERSISTÊNCIA ORM PARA EXECUÇÃO PELO WORKER
# ==============================================================================

def _campos_modelo(modelo) -> set[str]:
    return {
        campo.name
        for campo in modelo._meta.get_fields()
        if getattr(campo, "concrete", False)
    }


def _valor_enum(valor: object) -> str:
    return str(getattr(valor, "value", valor) or "")


def _status_modelo(status_core: object) -> str:
    valor = _valor_enum(status_core)

    if valor in StatusTarefaSuricata.values:
        return valor

    return StatusTarefaSuricata.ERRO


def _configuracao_modelo_para_dto(
    configuracao: ConfiguracaoSuricata | None,
) -> ConfiguracaoSuricataDados | None:
    if configuracao is None:
        return None

    return configuracao_de_dict(configuracao.to_service_dict())


def _mesclar_configuracao_parametros(
    parametros: dict[str, object],
    tarefa: TarefaSuricata,
) -> dict[str, object]:
    """
    Converte o JSON salvo no banco para os DTOs esperados pela camada service.

    A configuração vinculada à tarefa prevalece sobre detecção automática,
    garantindo que as interfaces escolhidas no painel sejam aplicadas no YAML.
    """
    parametros = dict(parametros or {})

    if "configuracao" in parametros:
        parametros["configuracao"] = configuracao_de_dict(
            parametros.get("configuracao")
        )
    elif tarefa.configuracao_id:
        parametros["configuracao"] = _configuracao_modelo_para_dto(
            tarefa.configuracao
        )

    return parametros


def _adquirir_tarefa_banco(
    tarefa_id: str,
    tipo_esperado: TipoTarefaSuricata,
) -> TarefaSuricata:
    """
    Bloqueia e promove uma tarefa PENDENTE para EXECUTANDO.

    O bloqueio impede que dois workers capturem a mesma tarefa.
    """
    with transaction.atomic():
        tarefa = (
            TarefaSuricata.objects
            .select_for_update(of=("self",))
            .select_related("configuracao")
            .get(pk=tarefa_id)
        )

        if tarefa.tipo != tipo_esperado.value:
            raise CommandError(
                "O tipo informado na CLI não corresponde ao tipo salvo "
                f"na tarefa: CLI={tipo_esperado.value}, banco={tarefa.tipo}."
            )

        if tarefa.status == StatusTarefaSuricata.EXECUTANDO:
            raise CommandError(
                "A tarefa já está sendo processada por outro executor."
            )

        if tarefa.status in {
            StatusTarefaSuricata.SUCESSO,
            StatusTarefaSuricata.ERRO,
            StatusTarefaSuricata.CANCELADO,
            StatusTarefaSuricata.IGNORADO,
        }:
            raise CommandError(
                f"A tarefa já foi finalizada com status '{tarefa.status}'."
            )

        tarefa.status = StatusTarefaSuricata.EXECUTANDO
        tarefa.progresso = max(1, int(tarefa.progresso or 0))
        tarefa.etapa_atual = "iniciando"
        tarefa.mensagem = "Tarefa capturada pelo worker automático."
        tarefa.erro = ""
        tarefa.iniciado_em = tarefa.iniciado_em or django_timezone.now()

        campos = [
            "status",
            "progresso",
            "etapa_atual",
            "mensagem",
            "erro",
            "iniciado_em",
        ]
        if "atualizado_em" in _campos_modelo(TarefaSuricata):
            campos.append("atualizado_em")

        tarefa.save(update_fields=campos)
        return tarefa


def _salvar_logs_incrementais(
    tarefa_id: str,
    progresso,
) -> None:
    """Persiste apenas logs ainda não gravados, sem duplicar sequências."""
    logs = list(getattr(progresso, "logs", []) or [])
    if not logs:
        return

    close_old_connections()
    tarefa = TarefaSuricata.objects.get(pk=tarefa_id)

    ultima_sequencia = (
        tarefa.logs.order_by("-sequencia")
        .values_list("sequencia", flat=True)
        .first()
    )
    proxima = int(ultima_sequencia) + 1 if ultima_sequencia is not None else 0

    registros = []
    for sequencia, log_core in enumerate(logs):
        if sequencia < proxima:
            continue

        nivel_core = _valor_enum(getattr(log_core, "nivel", "info"))
        nivel_modelo = (
            nivel_core
            if nivel_core in NivelLogSuricata.values
            else NivelLogSuricata.INFO
        )

        detalhes = getattr(log_core, "detalhes", {}) or {}
        if hasattr(log_core, "to_dict"):
            try:
                detalhes = log_core.to_dict().get("detalhes", detalhes)
            except Exception:
                pass

        registros.append(
            LogTarefaSuricata(
                tarefa=tarefa,
                sequencia=sequencia,
                nivel=nivel_modelo,
                etapa=str(getattr(log_core, "etapa", "") or "")[
                    :MAX_LOG_ETAPA
                ],
                mensagem=str(
                    getattr(log_core, "mensagem", "") or ""
                )[:MAX_LOG_MENSAGEM],
                detalhes=_sanitizar_para_saida(detalhes),
                criado_em=getattr(
                    log_core,
                    "criado_em",
                    django_timezone.now(),
                ),
            )
        )

    if registros:
        LogTarefaSuricata.objects.bulk_create(
            registros,
            batch_size=200,
            ignore_conflicts=True,
        )


def _persistir_progresso_banco(
    tarefa_id: str,
    progresso,
    resultado=None,
) -> None:
    """Sincroniza tracker, resultado e logs com a tarefa ORM."""
    close_old_connections()

    campos_modelo = _campos_modelo(TarefaSuricata)
    atualizacoes = {
        "status": _status_modelo(getattr(progresso, "status", "")),
        "progresso": max(
            0,
            min(100, int(getattr(progresso, "progresso", 0) or 0)),
        ),
        "etapa_atual": str(
            getattr(progresso, "etapa_atual", "") or ""
        )[:255],
        "mensagem": str(
            getattr(progresso, "mensagem", "") or ""
        )[:MAX_MENSAGEM_BANCO],
        "erro": str(
            getattr(progresso, "erro", "") or ""
        )[:MAX_ERRO_BANCO],
    }

    iniciado = getattr(progresso, "iniciado_em", None)
    finalizado = getattr(progresso, "finalizado_em", None)

    if iniciado:
        atualizacoes["iniciado_em"] = iniciado
    if finalizado:
        atualizacoes["finalizado_em"] = finalizado
    if resultado is not None:
        atualizacoes["resultado"] = _sanitizar_para_saida(resultado)

    atualizacoes = {
        chave: valor
        for chave, valor in atualizacoes.items()
        if chave in campos_modelo
    }

    TarefaSuricata.objects.filter(pk=tarefa_id).update(**atualizacoes)
    _salvar_logs_incrementais(tarefa_id, progresso)


def _cancelamento_solicitado_banco(tarefa_id: str) -> bool:
    """
    Consulta cancelamento sem depender de um nome único de campo.

    Compatível com os nomes mais comuns e com o status CANCELADO aplicado pelo
    método `solicitar_cancelamento` do model.
    """
    close_old_connections()
    tarefa = TarefaSuricata.objects.filter(pk=tarefa_id).first()
    if tarefa is None:
        return True

    if tarefa.status == StatusTarefaSuricata.CANCELADO:
        return True

    candidatos = (
        "cancelamento_solicitado",
        "solicitou_cancelamento",
        "cancelar_solicitado",
        "cancelar",
    )

    for nome in candidatos:
        if hasattr(tarefa, nome) and bool(getattr(tarefa, nome)):
            return True

    return False


def _marcar_falha_executor(
    tarefa_id: str,
    mensagem: str,
) -> None:
    close_old_connections()
    agora = django_timezone.now()

    atualizacoes = {
        "status": StatusTarefaSuricata.ERRO,
        "erro": str(mensagem)[-MAX_ERRO_BANCO:],
        "mensagem": "O executor encontrou uma falha inesperada.",
        "finalizado_em": agora,
    }
    campos = _campos_modelo(TarefaSuricata)
    atualizacoes = {
        chave: valor
        for chave, valor in atualizacoes.items()
        if chave in campos
    }
    TarefaSuricata.objects.filter(pk=tarefa_id).update(**atualizacoes)


# ==============================================================================
# COMANDO PRINCIPAL
# ==============================================================================

class Command(BaseCommand):
    help = (
        "Executa tarefas controladas de instalação, configuração, "
        "diagnóstico e manutenção do Suricata."
    )

    def add_arguments(self, parser):
        # Inferimos as escolhas válidas direto das definições de capability no Enum
        choices_tipo = [t.value for t in TipoTarefaSuricata]
        
        parser.add_argument(
            'tipo',
            choices=choices_tipo,
            help="Tipo de tarefa orquestrada a ser executada no ambiente base."
        )

        parser.add_argument(
            '--tarefa-id',
            type=str,
            help="Identificador opcional da tarefa (UUID override)."
        )

        parser.add_argument(
            '--formato',
            choices=list(FORMATOS_SAIDA),
            default='texto',
            help="Modo de formatação do output (Padrão: texto)."
        )

        parser.add_argument(
            '--dry-run',
            action='store_true',
            help="Valida a tarefa e exibe o plano sem executar operações de sistema."
        )

        parser.add_argument(
            '--mostrar-logs',
            action='store_true',
            help="Exibe os logs estruturados produzidos durante a execução."
        )

        parser.add_argument(
            '--nivel-detalhe',
            choices=['resumido', 'completo'],
            default='resumido',
            help="Detalhamento do output textual."
        )

        parser.add_argument(
            '--nao-confirmar',
            action='store_true',
            help="Executa sem solicitar confirmação interativa."
        )

        # ARGS: TOPOLOGIA
        parser.add_argument('--wan', dest='interface_wan')
        parser.add_argument('--lan', dest='interface_lan')
        parser.add_argument('--mgmt', dest='interface_mgmt')
        parser.add_argument('--interfaces', nargs='+', dest='interfaces_monitoradas')
        parser.add_argument('--home-net', nargs='+', dest='home_net')
        parser.add_argument('--dns-interno')
        parser.add_argument('--yaml-path', default=None)
        parser.add_argument('--eve-path', default=None)
        parser.add_argument(
            '--modo-captura',
            choices=[m.value for m in ModoCaptura],
            default=None
        )

        # GRUPO: INSTALAÇÃO & CONFIGURAÇÃO
        grupo_instalacao = parser.add_argument_group("Instalação e configuração")
        grupo_instalacao.add_argument('--instalar-et-open', action='store_true', default=None)
        grupo_instalacao.add_argument('--sem-et-open', action='store_true', default=False)
        grupo_instalacao.add_argument('--reiniciar-servicos', action='store_true', default=None)
        grupo_instalacao.add_argument('--sem-reiniciar-servicos', action='store_true', default=False)
        grupo_instalacao.add_argument('--sem-diagnostico-final', action='store_true', default=False)

        # GRUPO: ATUALIZAÇÃO DE REGRAS
        grupo_regras = parser.add_argument_group("Atualização de regras")
        grupo_regras.add_argument('--atualizar-et', action='store_true', default=None)
        grupo_regras.add_argument('--nao-atualizar-et', action='store_true', default=False)
        grupo_regras.add_argument('--atualizar-moonshield', action='store_true', default=None)
        grupo_regras.add_argument('--nao-atualizar-moonshield', action='store_true', default=False)
        grupo_regras.add_argument('--origem-moonshield')
        grupo_regras.add_argument('--validar-depois', action='store_true', default=None)
        grupo_regras.add_argument('--sem-validar-depois', action='store_true', default=False)
        grupo_regras.add_argument('--reiniciar-depois', action='store_true', default=False)

        # GRUPO: DIAGNÓSTICO
        grupo_diagnostico = parser.add_argument_group("Diagnóstico")
        grupo_diagnostico.add_argument('--sem-validacao-suricata', action='store_true', default=False)
        grupo_diagnostico.add_argument('--sem-checks-eve', action='store_true', default=False)
        grupo_diagnostico.add_argument('--sem-checks-servicos', action='store_true', default=False)


    # ==========================================================================
    # LÓGICAS PRIVADAS DE MANEJO
    # ==========================================================================

    def _resolver_booleano(
        self,
        positivo: bool | None,
        negativo: bool,
        padrao: bool | None = None,
    ) -> bool | None:
        """Resolve chaves dicotômicas originárias do argparse, impedindo paradoxos."""
        if positivo and negativo:
            raise CommandError("Argumentos incompatíveis fornecidos simultaneamente (Flag Positiva + Flag Negativa).")
            
        if positivo is True:
            return True
        if negativo is True:
            return False
            
        return padrao


    def _montar_configuracao(self, options: dict) -> ConfiguracaoSuricataDados | None:
        """Processa e consolida o footprint DTO que embasará Topologia."""
        dados = {}
        
        # Mapeamento do Request-Option pro Keypair Data
        mapeamentos_diretos = {
            "interface_wan": options.get("interface_wan"),
            "interface_lan": options.get("interface_lan"),
            "interface_mgmt": options.get("interface_mgmt"),
            "interfaces_monitoradas": options.get("interfaces_monitoradas"),
            "home_net": options.get("home_net"),
            "dns_interno": options.get("dns_interno"),
            "modo_captura": options.get("modo_captura"),
        }
        
        for k, v in mapeamentos_diretos.items():
            if v is not None:
                dados[k] = v

        if options.get("yaml_path") is not None:
            dados["yaml_path"] = options.get("yaml_path")
        if options.get("eve_path") is not None:
            dados["eve_path"] = options.get("eve_path")

        # Se literalmente nenhuma chave de topologia pingou, recuamos.
        if not dados:
            return None

        # Resolve os booleans do DTO de acordo com o grupo apropriado
        try:
            dados["instalar_et_open"] = self._resolver_booleano(
                options.get("instalar_et_open"), options.get("sem_et_open")
            )
            dados["reiniciar_servicos"] = self._resolver_booleano(
                options.get("reiniciar_servicos"), options.get("sem_reiniciar_servicos")
            )
        except CommandError as e:
            raise e

        # Transforma pra Dataclass Limpa
        try:
            cfg = configuracao_de_dict(dados)
            erros_cfg = cfg.validar()
            if erros_cfg:
                erros_formato = "\n- ".join(erros_cfg)
                raise CommandError(f"A parametrização de infraestrutura fornecida possui conflitos fatais:\n- {erros_formato}")
            return cfg
        except ValueError as e:
            raise CommandError(f"Erro na coerção dos valores de configuração de rede: {e}")


    def _montar_parametros(self, tipo: TipoTarefaSuricata, options: dict) -> dict[str, object]:
        """Ajusta payloads isolados que cada task mestre enxergará/consumirá."""
        try:
            cfg = self._montar_configuracao(options)
        except CommandError as e:
            raise e

        param_bruto = {}
        
        if tipo == TipoTarefaSuricata.DIAGNOSTICO:
            param_bruto = {
                "configuracao": cfg,
                "incluir_validacao_suricata": not options.get("sem_validacao_suricata"),
                "incluir_checks_eve": not options.get("sem_checks_eve"),
                "incluir_checks_servicos": not options.get("sem_checks_servicos"),
            }

        elif tipo == TipoTarefaSuricata.INSTALACAO:
            # --sem-et-open só faz sentido aqui
            v_et = self._resolver_booleano(options.get("instalar_et_open"), options.get("sem_et_open"))
            v_re = self._resolver_booleano(options.get("reiniciar_servicos"), options.get("sem_reiniciar_servicos"))
            
            param_bruto = {
                "configuracao": cfg,
                "instalar_et_open": v_et,
                "reiniciar_servicos": v_re,
                "executar_diagnostico_final": not options.get("sem_diagnostico_final"),
            }

        elif tipo == TipoTarefaSuricata.CONFIGURACAO:
            if not cfg:
                raise CommandError("Uma operação de CONFIGURAÇÃO exige que parâmetros de interface ou de rede sejam providenciados.")
                
            v_re = self._resolver_booleano(options.get("reiniciar_servicos"), options.get("sem_reiniciar_servicos"))
            param_bruto = {
                "configuracao": cfg,
                "reiniciar_servicos": v_re,
            }

        elif tipo == TipoTarefaSuricata.ATUALIZACAO_REGRAS:
            v_up_et = self._resolver_booleano(options.get("atualizar_et"), options.get("nao_atualizar_et"))
            v_up_ms = self._resolver_booleano(options.get("atualizar_moonshield"), options.get("nao_atualizar_moonshield"))
            
            # Se não indicou nada, assume sync full
            if v_up_et is None and v_up_ms is None:
                v_up_et = True
                v_up_ms = True
                
            if not v_up_et and not v_up_ms:
                raise CommandError("Operação de ruleset vazia: Indique ao menos uma fonte a ser atualizada.")

            v_val = self._resolver_booleano(options.get("validar_depois"), options.get("sem_validar_depois"))
            
            param_bruto = {
                "atualizar_et": v_up_et,
                "atualizar_moonshield": v_up_ms,
                "origem_moonshield": options.get("origem_moonshield"),
                "validar_depois": v_val,
                "yaml_path": options.get("yaml_path"),
                "reiniciar_depois": options.get("reiniciar_depois"),
            }

        elif tipo == TipoTarefaSuricata.VALIDACAO:
            param_bruto = {
                "configuracao": cfg,
            }

        elif tipo in (TipoTarefaSuricata.REINICIO_SURICATA, TipoTarefaSuricata.REINICIO_MONITOR):
            # Recusa config
            if cfg:
                raise CommandError(f"A tarefa de {tipo.value} não aceita redefinições operacionais (topologia).")
            param_bruto = {}

        # 1. Higieniza varrendo falsos None (Deixa o service ditar fallback Default se ausente)
        p_clean = {k: v for k, v in param_bruto.items() if v is not None}
        
        # 2. Varredura pela Whitelist Global de Core Business
        try:
            return validar_parametros_tarefa(tipo, p_clean)
        except ValueError as e:
            raise CommandError(f"Erro lógico em argumento: {e}")


    def _stdin_interativo(self) -> bool:
        """Determina se existe um operador humano engatilhado no tty."""
        try:
            return sys.stdin.isatty()
        except Exception:
            return False


    def _precisa_confirmacao(self, tipo: TipoTarefaSuricata, dry_run: bool, nao_confirmar: bool) -> bool:
        """Alicerça se um bloqueio Y/N deve interromper a stack antes de iniciar danos eventuais."""
        if dry_run:
            return False
        if tipo not in TIPOS_PRIVILEGIADOS:
            return False
        if nao_confirmar:
            return False
        return True


    def _confirmar_execucao(self, tipo: TipoTarefaSuricata, parametros: dict[str, object]) -> bool:
        """Imprime Warning Dialogs e coleta consentimento."""
        self.stdout.write(self.style.WARNING(f"\n--- REVISÃO DE AÇÃO CRÍTICA ({tipo.value.upper()}) ---"))
        
        cfg = parametros.get("configuracao")
        if isinstance(cfg, ConfiguracaoSuricataDados):
            self.stdout.write(f"- WAN Detectada   : {cfg.interface_wan or 'Ausente'}")
            self.stdout.write(f"- LAN Base        : {cfg.interface_lan or 'Ausente'}")
            self.stdout.write(f"- MGMT Out-of-Band: {cfg.interface_mgmt or 'Ausente'}")
            self.stdout.write(f"- Capturando em   : {', '.join(cfg.interfaces_monitoradas) if cfg.interfaces_monitoradas else 'Nenhuma'}")
            self.stdout.write(f"- HOME_NET Ranges : {', '.join(cfg.home_net) if cfg.home_net else 'Vazio'}")
        
        # Prints genéricos para rulesets
        if "atualizar_et" in parametros:
            self.stdout.write(f"- Sync ET Open    : {parametros.get('atualizar_et')}")
        if "atualizar_moonshield" in parametros:
            self.stdout.write(f"- Sync Moonshield : {parametros.get('atualizar_moonshield')}")
            
        self.stdout.write("\n")
        
        try:
            resposta = input("Confirma a execução destas modificações de sistema? [s/N]: ")
            if resposta.strip().lower() in ("s", "sim", "y", "yes"):
                return True
        except (EOFError, KeyboardInterrupt):
            self.stdout.write("\n")
            
        return False


    # ==========================================================================
    # APRESENTAÇÃO / STDOUT
    # ==========================================================================

    def _exibir_dry_run(self, tipo: TipoTarefaSuricata, parametros: dict[str, object], formato: str) -> None:
        """Processa e printa Output puro analítico caso System Execution seja bypassado."""
        res_seco = executar_tarefa_seca(tipo, parametros)
        
        if formato == "json":
            self.stdout.write(json.dumps(_sanitizar_para_saida(res_seco), ensure_ascii=False, indent=2, default=str))
            return

        self.stdout.write(self.style.SUCCESS(f"=== DRY-RUN DA TAREFA: {tipo.value} ==="))
        
        status_val = self.style.SUCCESS('OK') if res_seco.get('valida') else self.style.ERROR('RECUSADA')
        self.stdout.write(f"Integridade Lógica: {status_val}")
        
        if res_seco.get("erros"):
            self.stdout.write(self.style.ERROR("\nErros Interceptados:"))
            for e in res_seco["erros"]:
                self.stdout.write(f"  - {e}")
                
        self.stdout.write(self.style.WARNING(f"\nAviso: {res_seco.get('aviso')}"))


    def _exibir_texto(self, progresso, resultado, mostrar_logs: bool, nivel_detalhe: str) -> None:
        """Dumps user-friendly para o shell humano."""
        self.stdout.write(self.style.NOTICE(f"\n--- RELATÓRIO DO MOTOR ({progresso.tipo.value}) ---") if hasattr(self.style, 'NOTICE') else f"\n--- RELATÓRIO DO MOTOR ({progresso.tipo.value}) ---")
        
        self.stdout.write(f"ID Processo  : {progresso.tarefa_id}")
        self.stdout.write(f"Status Final : {progresso.status.value}")
        self.stdout.write(f"Progresso    : {progresso.progresso}%")
        self.stdout.write(f"Sucesso      : {progresso.status == StatusEtapa.SUCESSO}")
        
        if resultado:
             self.stdout.write(f"Mensagem     : {resultado.mensagem}")
             if resultado.erro:
                 self.stdout.write(self.style.ERROR(f"Erro Crítico : {resultado.erro}"))
        else:
             self.stdout.write(f"Mensagem     : {progresso.mensagem}")
             
        resumo_prg = resumir_tarefa(progresso, resultado)
        duracao = resumo_prg.get('duracao_segundos', 0.0)
        self.stdout.write(f"Tempo Gasto  : {duracao}s")

        if mostrar_logs and progresso.logs:
            self.stdout.write("\n>>> Trilha de Eventos (LOGS):")
            for lg in progresso.logs:
                ts = getattr(lg, "criado_em", datetime.now()).strftime("%H:%M:%S")
                nv = getattr(lg, "nivel", "info").value
                msg = getattr(lg, "mensagem", "")
                etp = getattr(lg, "etapa", "")
                # Decoração de cor do level
                st_cor = self.style.SUCCESS if nv == 'sucesso' else (self.style.ERROR if nv == 'erro' else (self.style.WARNING if nv == 'aviso' else lambda x:x))
                self.stdout.write(st_cor(f"[{ts}] {nv.upper()} [{etp}] > {msg}"))

        if nivel_detalhe == "completo" and resultado:
            self.stdout.write("\n>>> Snapshot de Output (Dados da Infraestrutura):")
            dados_safe = _sanitizar_para_saida(resultado.dados)
            import pprint
            pprint.pp(dados_safe, stream=self.stdout, indent=2)


    def _exibir_json(self, progresso, resultado) -> None:
        """Gera STDOUT machine-readable puro para workers externos."""
        payload = {
            "tarefa": _sanitizar_para_saida(progresso),
            "resultado": _sanitizar_para_saida(resultado) if resultado else {},
            "resumo": _sanitizar_para_saida(resumir_tarefa(progresso, resultado))
        }
        self.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


    # ==========================================================================
    # MANUSEIO (ROTEADOR DE CÓDIGO)
    # ==========================================================================

    def handle(self, *args, **options):
        tipo_str = options.get("tipo")
        formato = options.get("formato")
        is_dry_run = bool(options.get("dry_run"))
        nao_confirmar = bool(options.get("nao_confirmar"))
        mostrar_logs = bool(options.get("mostrar_logs"))
        nivel_detalhe = options.get("nivel_detalhe")
        tarefa_id = str(options.get("tarefa_id") or "").strip()

        tarefa_banco = None

        try:
            tipo = converter_tipo_tarefa(tipo_str)

            # Quando existe tarefa-id, o banco é a fonte de verdade. Isso evita
            # perder parâmetros/configuração escolhidos pelo frontend.
            if tarefa_id and not is_dry_run:
                tarefa_banco = _adquirir_tarefa_banco(
                    tarefa_id,
                    tipo,
                )
                parametros = _mesclar_configuracao_parametros(
                    tarefa_banco.parametros,
                    tarefa_banco,
                )
                parametros = validar_parametros_tarefa(
                    tipo,
                    parametros,
                )
            else:
                parametros = self._montar_parametros(tipo, options)

            if is_dry_run:
                self._exibir_dry_run(tipo, parametros, formato)
                return

            interativo = self._stdin_interativo()
            privilegiado = tipo in TIPOS_PRIVILEGIADOS

            if privilegiado and not interativo and not nao_confirmar:
                raise CommandError(
                    "Ambiente não interativo bloqueou a tarefa. "
                    "Use --nao-confirmar em automações."
                )

            if self._precisa_confirmacao(
                tipo,
                is_dry_run,
                nao_confirmar,
            ):
                if not self._confirmar_execucao(tipo, parametros):
                    if tarefa_banco is not None:
                        TarefaSuricata.objects.filter(
                            pk=tarefa_id
                        ).update(
                            status=StatusTarefaSuricata.CANCELADO,
                            mensagem="Execução cancelada pelo operador.",
                            finalizado_em=django_timezone.now(),
                        )

                    if formato == "texto":
                        self.stdout.write(
                            self.style.WARNING(
                                "Abortado. Ação não confirmada."
                            )
                        )
                    else:
                        self.stdout.write(
                            json.dumps(
                                {
                                    "ok": False,
                                    "erro": "Cancelado interativamente.",
                                },
                                ensure_ascii=False,
                            )
                        )
                    return

            if tarefa_banco is not None:
                progresso = criar_progresso_tarefa(
                    tipo,
                    tarefa_id,
                )
                progresso.status = StatusEtapa.EXECUTANDO
                progresso.progresso = max(
                    1,
                    int(tarefa_banco.progresso or 0),
                )
                progresso.etapa_atual = (
                    tarefa_banco.etapa_atual or "iniciando"
                )
                progresso.mensagem = (
                    tarefa_banco.mensagem
                    or "Execução iniciada pelo worker."
                )
                progresso.iniciado_em = (
                    tarefa_banco.iniciado_em
                    or django_timezone.now()
                )

                callback_progresso = lambda tracker: (
                    _persistir_progresso_banco(
                        tarefa_id,
                        tracker,
                    )
                )
                callback_cancelamento = lambda: (
                    _cancelamento_solicitado_banco(tarefa_id)
                )
            else:
                progresso = None
                callback_progresso = None
                callback_cancelamento = None

            progresso, resultado = executar_tarefa(
                tipo=tipo,
                parametros=parametros,
                tarefa_id=tarefa_id or None,
                progresso=progresso,
                callback_progresso=callback_progresso,
                callback_cancelamento=callback_cancelamento,
                intervalo_callback=0.5,
            )

            if tarefa_banco is not None:
                _persistir_progresso_banco(
                    tarefa_id,
                    progresso,
                    resultado,
                )

            if formato == "json":
                self._exibir_json(progresso, resultado)
            else:
                self._exibir_texto(
                    progresso,
                    resultado,
                    mostrar_logs,
                    nivel_detalhe,
                )

            if resultado and not resultado.sucesso:
                raise CommandError(
                    "O processo não obteve sucesso integral. "
                    "Verifique a matriz de resultados."
                )

        except CommandError as exc:
            if tarefa_id:
                try:
                    tarefa = TarefaSuricata.objects.filter(
                        pk=tarefa_id
                    ).first()
                    if (
                        tarefa is not None
                        and tarefa.status
                        not in {
                            StatusTarefaSuricata.SUCESSO,
                            StatusTarefaSuricata.ERRO,
                            StatusTarefaSuricata.CANCELADO,
                            StatusTarefaSuricata.IGNORADO,
                        }
                    ):
                        _marcar_falha_executor(tarefa_id, str(exc))
                except Exception:
                    logger.exception(
                        "Falha ao registrar erro da tarefa %s.",
                        tarefa_id,
                    )

            if formato == "json":
                self.stdout.write(
                    json.dumps(
                        {"ok": False, "erro": str(exc)},
                        ensure_ascii=False,
                    )
                )
                raise SystemExit(1)

            raise

        except Exception as exc:
            logger.exception(
                "Erro inesperado na tarefa Suricata %s (%s).",
                tarefa_id or "sem-id",
                tipo_str,
            )

            if tarefa_id:
                try:
                    _marcar_falha_executor(
                        tarefa_id,
                        str(exc),
                    )
                except Exception:
                    logger.exception(
                        "Falha ao persistir crash da tarefa %s.",
                        tarefa_id,
                    )

            if formato == "json":
                self.stdout.write(
                    json.dumps(
                        {
                            "ok": False,
                            "erro": "Crash severo do executor.",
                            "detalhes": str(exc),
                        },
                        ensure_ascii=False,
                    )
                )
                raise SystemExit(1)

            raise CommandError(
                f"Crash inesperado do executor: {exc}"
            ) from exc

