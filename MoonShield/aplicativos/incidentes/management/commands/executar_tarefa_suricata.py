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

from incidentes.services.suricata.tipos import (
    TipoTarefaSuricata,
    ConfiguracaoSuricataDados,
    ModoCaptura,
    StatusEtapa,
)

from incidentes.services.suricata.tarefas import (
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
        # Desempacota configs básicas de CLI
        tipo_str = options.get("tipo")
        formato = options.get("formato")
        is_dry_run = options.get("dry_run")
        nao_confirmar = options.get("nao_confirmar")
        mostrar_logs = options.get("mostrar_logs")
        nivel_detalhe = options.get("nivel_detalhe")

        try:
            # 1. Parsing semântico e construção de pacote
            tipo = converter_tipo_tarefa(tipo_str)
            parametros = self._montar_parametros(tipo, options)
            
            # 2. Handler Seco
            if is_dry_run:
                self._exibir_dry_run(tipo, parametros, formato)
                return

            # 3. Interceptação de TTYs desguarnecidos (Que previnem stall de deploy C.I/Pipelines)
            interativo = self._stdin_interativo()
            is_privilegiado = (tipo in TIPOS_PRIVILEGIADOS)
            
            if is_privilegiado and not interativo and not nao_confirmar:
                raise CommandError("Ambiente não-interativo bloqueou a tarefa. Para automatizações, utilize o argumento --nao-confirmar na CLI.")

            # 4. Consentimento
            if self._precisa_confirmacao(tipo, is_dry_run, nao_confirmar):
                if not self._confirmar_execucao(tipo, parametros):
                    if formato == "texto":
                        self.stdout.write(self.style.WARNING("Abortado. Ação não foi confirmada pelo Operador."))
                    else:
                        self.stdout.write(json.dumps({"ok": False, "erro": "Cancelado interativamente."}, ensure_ascii=False))
                    return

            # 5. Core Trigger
            progresso, resultado = executar_tarefa(
                tipo=tipo,
                parametros=parametros,
                tarefa_id=options.get("tarefa_id"),
            )

            # 6. Renderização Positiva
            if formato == "json":
                self._exibir_json(progresso, resultado)
            else:
                self._exibir_texto(progresso, resultado, mostrar_logs, nivel_detalhe)

            # 7. Dispara Non-Zero exitcode pro terminal em caso de crash (Ex: Ansible/Chef fail-fast)
            if resultado and not resultado.sucesso:
                raise CommandError("O processo não obteve sucesso integral. Verifique a matriz de resultados exibida.")

        except CommandError as ce:
            # Devolve pro Django lidar (Ele renderiza em vermelho automaticamente no term e levanta Exit(1))
            if formato == "json":
                self.stdout.write(json.dumps({"ok": False, "erro": str(ce)}, ensure_ascii=False))
                sys.exit(1)
            raise ce
            
        except Exception as e:
            logger.exception(f"Erro colossal/catastrófico vazou do escopo da Tarefa {tipo_str}.")
            if formato == "json":
                self.stdout.write(json.dumps({"ok": False, "erro": "Crash severo do interpretador.", "detalhes": str(e)}, ensure_ascii=False))
                sys.exit(1)
            raise CommandError(f"Crash inesperado do interpretador de código: {str(e)}")