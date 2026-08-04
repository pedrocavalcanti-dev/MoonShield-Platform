import os
import signal
import logging
from threading import Event
from pathlib import Path
from datetime import datetime

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings

from incidentes.services.monitor_suricata import MonitorSuricata

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Inicia o monitor contínuo (worker) para o log eve.json do Suricata.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--arquivo',
            type=str,
            default='/var/log/suricata/eve.json',
            help='Caminho do arquivo EVE JSON.'
        )
        parser.add_argument(
            '--lote',
            type=int,
            default=100,
            help='Quantidade de eventos válidos por lote (padrão: 100).'
        )
        parser.add_argument(
            '--intervalo',
            type=float,
            default=1.0,
            help='Tempo de espera (segundos) quando não há novas linhas (padrão: 1.0).'
        )
        parser.add_argument(
            '--flush-intervalo',
            type=float,
            default=5.0,
            help='Tempo máximo (segundos) para forçar envio de lote parcial (padrão: 5.0).'
        )
        parser.add_argument(
            '--cursor',
            type=str,
            default='',
            help='Caminho do cursor. Se não informado, gerado automaticamente no BASE_DIR.'
        )
        parser.add_argument(
            '--desde-inicio',
            action='store_true',
            help='Ignora a otimização de pular para o final se for a primeira execução.'
        )
        parser.add_argument(
            '--resetar-cursor',
            action='store_true',
            help='Deleta o cursor existente para forçar recomeço.'
        )
        parser.add_argument(
            '--uma-vez',
            action='store_true',
            help='Processa todos os eventos novos disponíveis e encerra.'
        )

    def handle(self, *args, **options):
        arquivo = options['arquivo']
        lote = options['lote']
        intervalo = options['intervalo']
        flush_intervalo = options['flush_intervalo']
        cursor_param = options['cursor']
        desde_inicio = options['desde_inicio']
        resetar_cursor = options['resetar_cursor']
        uma_vez = options['uma_vez']

        # 1. Validações Iniciais
        if lote <= 0:
            raise CommandError("--lote deve ser maior que zero.")
        if intervalo < 0.1:
            raise CommandError("--intervalo deve ser no mínimo 0.1.")
        if flush_intervalo < 0.5:
            raise CommandError("--flush-intervalo deve ser no mínimo 0.5.")

        if not os.path.isfile(arquivo):
            raise CommandError(f"Arquivo EVE não encontrado: {arquivo}")

        # 2. Configuração do caminho do cursor e garantia da estrutura de pastas
        if cursor_param:
            cursor_path = cursor_param
        else:
            base = Path(settings.BASE_DIR)
            cursor_dir = base / "var" / "cursors"
            cursor_path = str(cursor_dir / "suricata_eve.cursor")

        try:
            Path(cursor_path).parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CommandError(f"Falha ao criar o diretório para o cursor: {exc}") from exc

        # 3. Tratamento de reset do cursor
        if resetar_cursor:
            if os.path.exists(cursor_path):
                try:
                    os.remove(cursor_path)
                    self.stdout.write(self.style.WARNING(f"[!] Cursor deletado: {cursor_path}"))
                    logger.info(f"Cursor deletado manualmente: {cursor_path}")
                except OSError as exc:
                    raise CommandError(f"Não foi possível remover o cursor: {exc}") from exc

        # 4. Exibição da configuração e Setup de Parada
        self._exibir_configuracao(
            arquivo, cursor_path, lote, intervalo, flush_intervalo, desde_inicio, uma_vez
        )

        stop_event = Event()

        def handle_signal(sig, frame):
            self.stdout.write(self.style.WARNING("\nSinal de parada recebido. Encerrando monitor..."))
            logger.info(f"Sinal de parada ({sig}) recebido. Solicitando encerramento...")
            stop_event.set()

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        # 5. Instanciação e Execução Robusta
        monitor = MonitorSuricata(
            eve_path=arquivo,
            batch_size=lote,
            interval=intervalo,
            flush_interval=flush_intervalo,
            cursor_path=cursor_path,
            start_at_end=not desde_inicio
        )

        try:
            estatisticas = monitor.executar(
                stop_event=stop_event,
                callback_status=self._processar_evento_status,
                run_once=uma_vez
            )
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("\nInterrupção forçada (KeyboardInterrupt)."))
            logger.info("Execução abortada via KeyboardInterrupt.")
            estatisticas = None
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"\n[ERRO] Ocorreu um erro inesperado: {str(e)}"))
            logger.exception("Erro crítico não tratado durante a execução do MonitorSuricata.")
            estatisticas = None

        # 6. Exibição do Resumo Final
        self._exibir_resumo(estatisticas)


    # =========================================================================
    # MÉTODOS PRIVADOS DE ORGANIZAÇÃO
    # =========================================================================

    def _exibir_configuracao(self, arquivo, cursor, lote, intervalo, flush, desde_inicio, uma_vez):
        """Imprime no terminal as configurações lidas e os estados iniciais no formato solicitado."""
        estado_inicio = "início do arquivo" if desde_inicio else "final do arquivo (se novo) / cursor existente"
        modo = "uma-vez (batch exit)" if uma_vez else "contínuo"
        pid = os.getpid()

        configuracao_msg = (
            f"{self.style.SUCCESS('MOONSHIELD — Monitor Suricata Local')}\n\n"
            f"Arquivo EVE      : {arquivo}\n"
            f"Cursor           : {cursor}\n"
            f"Tamanho do lote  : {lote}\n"
            f"Intervalo        : {intervalo}s\n"
            f"Flush parcial    : {flush}s\n"
            f"Posição inicial  : {estado_inicio}\n"
            f"Modo             : {modo}\n"
            f"PID              : {pid}\n"
        )
        self.stdout.write(configuracao_msg)
        logger.info(f"Monitor iniciado (PID: {pid}, Modo: {modo}, Lote: {lote}, Arquivo: {arquivo})")

    def _processar_evento_status(self, evento: dict):
        """Callback invocado pelo worker contínuo para refletir status e saúde dos lotes."""
        if not isinstance(evento, dict):
            return

        tipo = evento.get("tipo")

        if tipo == "inicializacao":
            self.stdout.write(self.style.SUCCESS(f"[OK] {evento.get('mensagem', 'Monitor iniciado.')}"))

        elif tipo == "lote":
            r = evento.get("resultado", {})
            if not isinstance(r, dict):
                r = {}

            # Campos principais (exibidos sempre)
            validos = r.get("validos", 0)
            alertas = r.get("alertas_recebidos", 0)
            novos = r.get("incidentes_novos", 0)
            atualizados = r.get("incidentes_atualizados", 0)
            dns = r.get("dns_salvos", 0)
            http = r.get("http_salvos", 0)
            tls = r.get("tls_salvos", 0)
            ignorados = r.get("ignorados", 0)
            
            # Campos condicionais
            suprimidos = r.get("alertas_suprimidos", 0)
            brutos = r.get("eventos_brutos_salvos", 0)

            # Construção limpa da linha
            partes = [
                f"[LOTE] {validos} eventos",
                f"ALERTAS {alertas}",
                f"NOVOS {novos}",
                f"ATUALIZADOS {atualizados}",
            ]

            if suprimidos > 0:
                partes.append(f"SUPRIMIDOS {suprimidos}")
            if brutos > 0:
                partes.append(f"BRUTOS {brutos}")

            partes.extend([
                f"DNS {dns}",
                f"HTTP {http}",
                f"TLS {tls}",
                f"IGNORADOS {ignorados}"
            ])

            self.stdout.write(" | ".join(partes))

        elif tipo == "cursor":
            self.stdout.write(f"[CURSOR] offset confirmado: {evento.get('offset', 0)}")

        elif tipo == "rotacao":
            self.stdout.write(self.style.WARNING("[ROTAÇÃO] Arquivo EVE rotacionado ou truncado. Cursor ajustado."))
            logger.info("Rotação ou truncamento de arquivo detectado pelo worker.")

        elif tipo == "erro":
            mensagem = evento.get("mensagem", "Erro não especificado.")
            self.stdout.write(self.style.ERROR(f"[ERRO] Falha ao processar lote: {mensagem}"))

        elif tipo == "encerramento":
            self.stdout.write(self.style.SUCCESS("[FIM] Monitor encerrado de forma limpa."))

    def _exibir_resumo(self, estatisticas: dict):
        """Calcula a volumetria, taxas e constrói o sumário final antes do término total do processo."""
        if not isinstance(estatisticas, dict):
            logger.warning("Monitor terminou sem retornar as estatísticas formatadas.")
            self.stdout.write(self.style.WARNING("\nEstatísticas finais indisponíveis."))
            return

        iniciado = estatisticas.get("iniciado_em", "—")
        encerrado = estatisticas.get("encerrado_em", "—")
        eventos_enviados = estatisticas.get("eventos_enviados", 0)

        # Cálculos de performance e duração
        duracao_fmt, segundos = self._formatar_duracao(iniciado, encerrado)
        taxa_fmt = self._calcular_taxa(eventos_enviados, segundos)

        resumo = (
            "\nResumo da execução\n"
            "------------------\n"
            f"Linhas lidas           : {estatisticas.get('linhas_lidas', 0)}\n"
            f"Eventos enviados       : {eventos_enviados}\n"
            f"Lotes enviados         : {estatisticas.get('lotes_enviados', 0)}\n"
            f"JSON inválidos         : {estatisticas.get('json_invalidos', 0)}\n"
            f"Falhas de ingestão     : {estatisticas.get('falhas_ingestao', 0)}\n"
            f"Rotações detectadas    : {estatisticas.get('rotacoes_detectadas', 0)}\n"
            f"Tempo total            : {duracao_fmt}\n"
            f"Média eventos/segundo  : {taxa_fmt}\n"
            f"Iniciado em            : {iniciado}\n"
            f"Encerrado em           : {encerrado}\n"
        )
        self.stdout.write(self.style.SUCCESS(resumo))
        logger.info(f"Monitor encerrado. Eventos enviados: {eventos_enviados} | Duração: {duracao_fmt} | Taxa: {taxa_fmt} ev/s")

    def _formatar_duracao(self, inicio_iso: str, fim_iso: str):
        """Converte strings ISO para datetime, calcula o delta e retorna formatado HH:MM:SS junto aos segundos brutos."""
        if inicio_iso == "—" or fim_iso == "—" or not inicio_iso or not fim_iso:
            return "—", 0.0

        try:
            # Substituir Z para +00:00 garante parsing robusto em Python <= 3.10
            inicio = datetime.fromisoformat(inicio_iso.replace("Z", "+00:00"))
            fim = datetime.fromisoformat(fim_iso.replace("Z", "+00:00"))
            segundos = (fim - inicio).total_seconds()

            if segundos < 0:
                return "—", 0.0

            horas, resto = divmod(segundos, 3600)
            minutos, segs = divmod(resto, 60)
            duracao_formatada = f"{int(horas):02d}:{int(minutos):02d}:{int(segs):02d}"
            
            return duracao_formatada, segundos
        except Exception:
            return "—", 0.0

    def _calcular_taxa(self, total_eventos: int, segundos_totais: float) -> str:
        """Retorna a taxa de processamento por segundo."""
        if not segundos_totais or segundos_totais <= 0:
            return "—"
        taxa = total_eventos / segundos_totais
        return f"{taxa:.2f}"