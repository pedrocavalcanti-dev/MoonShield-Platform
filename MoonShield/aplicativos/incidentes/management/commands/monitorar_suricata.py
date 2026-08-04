import os
import signal
from threading import Event
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings

from incidentes.services.monitor_suricata import MonitorSuricata

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

        # Validações de Argumentos
        if lote <= 0:
            raise CommandError("--lote deve ser maior que zero.")
        if intervalo < 0.1:
            raise CommandError("--intervalo deve ser no mínimo 0.1.")
        if flush_intervalo < 0.5:
            raise CommandError("--flush-intervalo deve ser no mínimo 0.5.")

        # Configuração do caminho do cursor
        if cursor_param:
            cursor_path = cursor_param
        else:
            base = Path(settings.BASE_DIR)
            cursor_dir = base / "var" / "cursors"
            cursor_path = str(cursor_dir / "suricata_eve.cursor")

        if resetar_cursor:
            if os.path.exists(cursor_path):
                try:
                    os.remove(cursor_path)
                    self.stdout.write(self.style.WARNING(f"[!] Cursor deletado: {cursor_path}"))
                except OSError as exc:
                    raise CommandError(f"Não foi possível remover o cursor: {exc}") from exc

        self.stdout.write(self.style.SUCCESS("MOONSHIELD — Monitor Suricata Local\n"))
        self.stdout.write(f"Arquivo: {arquivo}")
        self.stdout.write(f"Cursor: {cursor_path}")
        self.stdout.write(f"Lote: {lote}")
        self.stdout.write(f"Intervalo: {intervalo}s")
        self.stdout.write(f"Flush parcial: {flush_intervalo}s")
        
        estado_inicio = "início do arquivo" if desde_inicio else "final do arquivo (se novo)"
        self.stdout.write(f"Início: {estado_inicio}")
        self.stdout.write(f"Modo: {'uma-vez (batch exit)' if uma_vez else 'contínuo'}\n")

        # Configuração de Sinais e Parada
        stop_event = Event()

        def handle_signal(sig, frame):
            self.stdout.write(self.style.WARNING("\nSinal de parada recebido (Ctrl+C). Encerrando monitor limpo..."))
            stop_event.set()

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        # Callback de status visual no terminal
        def callback_status(evento: dict):
            tipo = evento.get("tipo")
            if tipo == "inicializacao":
                self.stdout.write(self.style.SUCCESS(f"[OK] {evento.get('mensagem')}"))
            elif tipo == "lote":
                r = evento.get("resultado", {})
                dns = r.get("dns_salvos", 0)
                http = r.get("http_salvos", 0)
                tls = r.get("tls_salvos", 0)
                ignorados = r.get("ignorados", 0)
                validos = r.get("validos", 0)
                self.stdout.write(f"[LOTE] {validos} eventos | DNS {dns} | HTTP {http} | TLS {tls} | ignorados {ignorados}")
            elif tipo == "cursor":
                self.stdout.write(f"[CURSOR] offset confirmado: {evento.get('offset')}")
            elif tipo == "rotacao":
                self.stdout.write(self.style.WARNING(f"[ROTAÇÃO] {evento.get('mensagem')}"))
            elif tipo == "erro":
                self.stdout.write(self.style.ERROR(f"[ERRO] {evento.get('mensagem')}"))
            elif tipo == "encerramento":
                self.stdout.write(self.style.SUCCESS(f"[FIM] {evento.get('mensagem')}"))

        monitor = MonitorSuricata(
            eve_path=arquivo,
            batch_size=lote,
            interval=intervalo,
            flush_interval=flush_intervalo,
            cursor_path=cursor_path,
            start_at_end=not desde_inicio
        )

        # Bloqueia a thread atual rodando o loop
        estatisticas = monitor.executar(
            stop_event=stop_event,
            callback_status=callback_status,
            run_once=uma_vez
        )

        # Resumo final
        self.stdout.write(self.style.SUCCESS("\nResumo da Execução:"))
        self.stdout.write(f"Linhas lidas: {estatisticas.get('linhas_lidas')}")
        self.stdout.write(f"Eventos enviados: {estatisticas.get('eventos_enviados')}")
        self.stdout.write(f"Lotes enviados: {estatisticas.get('lotes_enviados')}")
        self.stdout.write(f"JSON inválidos: {estatisticas.get('json_invalidos')}")
        self.stdout.write(f"Falhas contornadas: {estatisticas.get('falhas_ingestao')}")
        self.stdout.write(f"Rotações/Truncamentos: {estatisticas.get('rotacoes_detectadas')}")
        self.stdout.write(f"Início: {estatisticas.get('iniciado_em')}")
        self.stdout.write(f"Fim: {estatisticas.get('encerrado_em')}")