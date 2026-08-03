import os
import json
import collections
from django.core.management.base import BaseCommand, CommandError
from incidentes.services.ingestao_local import ingerir_eventos_locais


class Command(BaseCommand):
    help = 'Importa eventos locais do arquivo eve.json do Suricata para o banco de dados.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--arquivo',
            type=str,
            required=True,
            help='Caminho do arquivo EVE JSON.'
        )
        parser.add_argument(
            '--limite',
            type=int,
            default=100,
            help='Quantidade máxima de eventos válidos a importar (padrão: 100).'
        )
        parser.add_argument(
            '--inicio',
            action='store_true',
            help='Começa a ler do início do arquivo (comportamento padrão).'
        )
        parser.add_argument(
            '--final',
            action='store_true',
            help='Importa as últimas linhas do arquivo.'
        )

    def handle(self, *args, **options):
        arquivo = options['arquivo']
        limite = options['limite']
        inicio = options['inicio']
        final = options['final']

        # Validações de argumento e arquivo
        if inicio and final:
            raise CommandError("Não é possível usar --inicio e --final simultaneamente.")

        if limite <= 0:
            raise CommandError("O limite deve ser um número inteiro positivo.")

        if not os.path.exists(arquivo) or not os.path.isfile(arquivo):
            raise CommandError(f"Arquivo não encontrado ou inválido: {arquivo}")

        if not os.access(arquivo, os.R_OK):
            raise CommandError(f"Sem permissão de leitura para o arquivo: {arquivo}")

        linhas_lidas = 0
        json_invalidos = 0
        linhas_ignoradas = 0
        eventos_validos = []

        self.stdout.write(f"Iniciando leitura de {arquivo}...")

        try:
            with open(arquivo, 'r', encoding='utf-8', errors='replace') as f:
                if final:
                    # Lê o arquivo alimentando um deque circular para capturar só os X últimos
                    buffer_validos = collections.deque(maxlen=limite)
                    for linha in f:
                        linhas_lidas += 1
                        linha = linha.strip()
                        if not linha:
                            linhas_ignoradas += 1
                            continue
                        try:
                            evento = json.loads(linha)
                            if isinstance(evento, dict):
                                buffer_validos.append(evento)
                            else:
                                json_invalidos += 1
                        except json.JSONDecodeError:
                            json_invalidos += 1
                    
                    eventos_validos = list(buffer_validos)
                else:
                    # Lê do início e para quando atingir o limite
                    for linha in f:
                        linhas_lidas += 1
                        linha = linha.strip()
                        if not linha:
                            linhas_ignoradas += 1
                            continue
                        try:
                            evento = json.loads(linha)
                            if isinstance(evento, dict):
                                eventos_validos.append(evento)
                                if len(eventos_validos) >= limite:
                                    break
                            else:
                                json_invalidos += 1
                        except json.JSONDecodeError:
                            json_invalidos += 1

        except Exception as e:
            raise CommandError(f"Erro ao ler o arquivo: {e}")

        if not eventos_validos:
            self.stdout.write(self.style.WARNING("Nenhum evento válido encontrado para importar."))
            return

        self.stdout.write("Executando ingestão no pipeline...")
        resultado = ingerir_eventos_locais(eventos_validos)

        if not resultado.get("ok"):
            raise CommandError(f"Erro no pipeline: {resultado.get('erro', 'Desconhecido')}")

        # Resumo no terminal
        self.stdout.write(self.style.SUCCESS("\nResumo da Leitura:"))
        self.stdout.write(f"Arquivo: {arquivo}")
        self.stdout.write(f"Linhas lidas: {linhas_lidas}")
        self.stdout.write(f"Eventos válidos: {len(eventos_validos)}")
        self.stdout.write(f"JSON inválidos/não-dicionário: {json_invalidos}")
        self.stdout.write(f"Linhas vazias/ignoradas: {linhas_ignoradas}")

        self.stdout.write(self.style.SUCCESS("\nResumo do Processamento:"))
        self.stdout.write(f"Sensor local: {resultado.get('sensor', 'Desconhecido')}")
        self.stdout.write(f"Alertas recebidos: {resultado.get('alertas_recebidos', 0)}")
        self.stdout.write(f"Alertas suprimidos: {resultado.get('alertas_suprimidos', 0)}")
        self.stdout.write(f"Incidentes novos: {resultado.get('incidentes_novos', 0)}")
        self.stdout.write(f"Incidentes atualizados: {resultado.get('incidentes_atualizados', 0)}")
        self.stdout.write(f"Eventos brutos processados: {resultado.get('eventos_brutos_salvos', 0)}")
        self.stdout.write(f"DNS processados: {resultado.get('dns_salvos', 0)}")
        self.stdout.write(f"HTTP processados: {resultado.get('http_salvos', 0)}")
        self.stdout.write(f"TLS processados: {resultado.get('tls_salvos', 0)}")
        self.stdout.write(f"Tipos ignorados: {resultado.get('ignorados', 0)}")

        self.stdout.write(self.style.SUCCESS("\nImportação concluída com sucesso."))