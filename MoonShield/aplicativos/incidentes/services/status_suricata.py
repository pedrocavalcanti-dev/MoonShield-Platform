import os
import json
import logging
import subprocess
from datetime import UTC, datetime
from django.utils import timezone
from django.conf import settings

from incidentes.models import Sensor, Incidente, EventoBruto, EventoDNS, EventoHTTP, EventoTLS

logger = logging.getLogger(__name__)

EVE_STALE_SECONDS = 120
CURSOR_STALE_SECONDS = 120
SENSOR_STALE_SECONDS = 300

def obter_status_systemd(nome_servico: str) -> dict:
    """Consulta o status de um serviço systemd via systemctl show de forma segura e somente-leitura."""
    status = {
        "ativo": False,
        "estado": "desconhecido",
        "subestado": "desconhecido",
        "main_pid": 0,
        "erro": "",
    }
    try:
        resultado = subprocess.run(
            [
                "systemctl",
                "show",
                nome_servico,
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
                "--no-pager"
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if resultado.returncode == 0:
            linhas = resultado.stdout.strip().split("\n")
            for linha in linhas:
                if "=" in linha:
                    chave, valor = linha.split("=", 1)
                    if chave == "ActiveState":
                        status["estado"] = valor
                        status["ativo"] = (valor == "active")
                    elif chave == "SubState":
                        status["subestado"] = valor
                    elif chave == "MainPID":
                        try:
                            status["main_pid"] = int(valor)
                        except ValueError:
                            status["main_pid"] = 0
        else:
            status["erro"] = "Falha ao executar systemctl show."
            logger.warning(f"systemctl show retornou código {resultado.returncode} para {nome_servico}")
    except subprocess.TimeoutExpired:
        status["erro"] = "Timeout de 3s ao consultar systemctl."
        logger.error(f"Timeout ao consultar {nome_servico} via systemctl.")
    except Exception as e:
        status["erro"] = f"Falha na consulta: {str(e)}"
        logger.exception(f"Exceção ao consultar status do systemd para {nome_servico}")

    return status

def obter_status_suricata_local() -> dict:
    """Coleta informações de estado do Suricata local, monitor contínuo, eve.json, cursor e banco."""
    agora = timezone.now()
    
    # 1. Status Systemd
    status_suricata = obter_status_systemd("suricata.service")
    status_monitor = obter_status_systemd("moonshield-suricata-monitor.service")

    # 2. Status do EVE JSON
    eve_path = "/var/log/suricata/eve.json"
    eve_status = {
        "existe": False,
        "legivel": False,
        "caminho": eve_path,
        "tamanho": 0,
        "modificado_em": None,
        "idade_segundos": None,
        "erro": "",
    }
    
    if os.path.exists(eve_path):
        eve_status["existe"] = True
        eve_status["legivel"] = os.access(eve_path, os.R_OK)
        if eve_status["legivel"]:
            try:
                st = os.stat(eve_path)
                eve_status["tamanho"] = st.st_size
                mtime = datetime.fromtimestamp(st.st_mtime, tz=UTC)
                eve_status["modificado_em"] = mtime.isoformat()
                eve_status["idade_segundos"] = (agora - mtime).total_seconds()
            except Exception as e:
                eve_status["erro"] = f"Erro ao acessar estatísticas do arquivo: {str(e)}"
                logger.exception(f"Erro ao obter os.stat de {eve_path}")
        else:
            eve_status["erro"] = "Sem permissão de leitura no arquivo eve.json."
    else:
        eve_status["erro"] = "Arquivo eve.json não foi encontrado."

    # 3. Status do Cursor
    cursor_path = os.path.join(settings.BASE_DIR, "var", "cursors", "suricata_eve.cursor")
    cursor_status = {
        "existe": False,
        "valido": False,
        "caminho": cursor_path,
        "path_gravado": "",
        "offset": 0,
        "inode": 0,
        "device": 0,
        "updated_at": None,
        "idade_segundos": None,
        "erro": "",
    }

    if os.path.exists(cursor_path):
        cursor_status["existe"] = True
        try:
            with open(cursor_path, "r", encoding="utf-8") as f:
                dados = json.load(f)

            if isinstance(dados, dict):
                path_gravado = dados.get("path")
                offset = dados.get("offset")
                inode = dados.get("inode")
                device = dados.get("device")
                updated_at_str = dados.get("updated_at")

                valido = True
                motivos_invalido = []

                if not isinstance(path_gravado, str) or not path_gravado:
                    valido = False
                    motivos_invalido.append("campo 'path' inválido")
                
                if not isinstance(offset, int) or offset < 0:
                    valido = False
                    motivos_invalido.append("campo 'offset' inválido")

                if not isinstance(inode, int) or inode < 0:
                    valido = False
                    motivos_invalido.append("campo 'inode' inválido")

                if not isinstance(device, int) or device < 0:
                    valido = False
                    motivos_invalido.append("campo 'device' inválido")

                dt_updated = None
                if isinstance(updated_at_str, str):
                    try:
                        dt_updated = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
                        if dt_updated.tzinfo is None:
                            valido = False
                            motivos_invalido.append("campo 'updated_at' sem timezone")
                    except ValueError:
                        valido = False
                        motivos_invalido.append("campo 'updated_at' formato ISO inválido")
                else:
                    valido = False
                    motivos_invalido.append("campo 'updated_at' ausente/inválido")

                if valido:
                    cursor_status["valido"] = True
                    cursor_status["path_gravado"] = path_gravado
                    cursor_status["offset"] = offset
                    cursor_status["inode"] = inode
                    cursor_status["device"] = device
                    cursor_status["updated_at"] = dt_updated.isoformat()
                    cursor_status["idade_segundos"] = (agora - dt_updated).total_seconds()
                else:
                    cursor_status["erro"] = f"Cursor corrompido ({', '.join(motivos_invalido)})."
            else:
                cursor_status["erro"] = "Conteúdo do arquivo de cursor não é um JSON objeto."
        except Exception as e:
            cursor_status["erro"] = f"Erro de leitura do cursor: {str(e)}"
            logger.exception("Erro ao ler/parsear arquivo de cursor.")
    else:
        cursor_status["erro"] = "Arquivo de cursor ainda não foi criado."

    # 4. Status do Sensor Local no Banco
    sensor_local = Sensor.objects.filter(nome__startswith="suricata-local-").order_by("-last_seen").first()
    sensor_status = {
        "encontrado": False,
        "nome": "",
        "ip": "",
        "ativo": False,
        "last_seen": None,
        "idade_segundos": None,
    }

    if sensor_local:
        sensor_status["encontrado"] = True
        sensor_status["nome"] = sensor_local.nome
        sensor_status["ip"] = sensor_local.ip
        sensor_status["ativo"] = sensor_local.ativo
        if sensor_local.last_seen:
            sensor_status["last_seen"] = sensor_local.last_seen.isoformat()
            sensor_status["idade_segundos"] = (agora - sensor_local.last_seen).total_seconds()

    # 5. Avaliação Consolidada da Saúde
    saude = {
        "nivel": "ok",
        "mensagem": "Suricata e worker operando normalmente.",
        "problemas": []
    }

    # Condições Críticas
    if not status_suricata["ativo"]:
        saude["problemas"].append("O serviço do Suricata (suricata.service) está inativo.")
    if not eve_status["existe"]:
        saude["problemas"].append("O log /var/log/suricata/eve.json não foi encontrado.")
    elif not eve_status["legivel"]:
        saude["problemas"].append("O arquivo eve.json existe, mas o Django não tem permissão de leitura.")

    if saude["problemas"]:
        saude["nivel"] = "critical"
        saude["mensagem"] = "Falha crítica na captura de rede ou acesso aos logs."
    else:
        # Condições de Alerta (Warning)
        if not status_monitor["ativo"]:
            saude["problemas"].append("O worker local (moonshield-suricata-monitor.service) está parado.")
        
        if not cursor_status["existe"]:
            saude["problemas"].append("Arquivo de cursor ainda não foi gerado pelo worker.")
        elif not cursor_status["valido"]:
            saude["problemas"].append(f"Cursor inválido: {cursor_status['erro']}")
        elif cursor_status["path_gravado"] != eve_path:
            saude["problemas"].append(f"Cursor aponta para outro log ({cursor_status['path_gravado']}).")
        elif cursor_status["idade_segundos"] is not None and cursor_status["idade_segundos"] > CURSOR_STALE_SECONDS:
            saude["problemas"].append("O cursor não é atualizado há mais de 2 minutos.")

        if not sensor_status["encontrado"]:
            saude["problemas"].append("O sensor local ainda não possui registro no banco de dados.")
        elif not sensor_status["ativo"]:
            saude["problemas"].append("O sensor local está marcado como inativo no banco de dados.")
        elif sensor_status["idade_segundos"] is not None and sensor_status["idade_segundos"] > SENSOR_STALE_SECONDS:
            saude["problemas"].append("O sensor local não atualiza seu registro de last_seen no banco há mais de 5 minutos.")

        if eve_status["idade_segundos"] is not None and eve_status["idade_segundos"] > EVE_STALE_SECONDS:
            saude["problemas"].append("O eve.json não recebe modificações recentes (pode indicar ausência de tráfego de rede).")

        if saude["problemas"]:
            saude["nivel"] = "warning"
            saude["mensagem"] = "Atenção em componentes do monitoramento."

    return {
        "ok": True,
        "modo": "local",
        "arquitetura": "suricata_eve_worker_local",
        "suricata": status_suricata,
        "monitor": status_monitor,
        "eve": eve_status,
        "cursor": cursor_status,
        "sensor": sensor_status,
        "eventos": {
            "incidentes": Incidente.objects.count(),
            "eventos_brutos": EventoBruto.objects.count(),
            "dns": EventoDNS.objects.count(),
            "http": EventoHTTP.objects.count(),
            "tls": EventoTLS.objects.count(),
        },
        "saude": saude,
        "consultado_em": agora.isoformat()
    }