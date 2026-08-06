import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Callable

from incidentes.services.ingestao_local import ingerir_eventos_locais


logger = logging.getLogger(__name__)


@dataclass
class EstatisticasMonitor:
    rodando: bool = False
    arquivo: str = ""
    cursor_path: str = ""
    offset_confirmado: int = 0
    offset_atual: int = 0
    linhas_lidas: int = 0
    linhas_vazias: int = 0
    json_invalidos: int = 0
    objetos_invalidos: int = 0
    eventos_enfileirados: int = 0
    lotes_enviados: int = 0
    eventos_enviados: int = 0
    falhas_ingestao: int = 0
    rotacoes_detectadas: int = 0
    truncamentos_detectados: int = 0
    cursores_invalidos: int = 0
    cursores_recriados: int = 0
    temporarios_removidos: int = 0
    ultimo_evento_em: str = ""
    ultimo_lote_em: str = ""
    ultimo_erro: str = ""
    iniciado_em: str = ""
    encerrado_em: str = ""

    def como_dict(self) -> dict:
        return asdict(self)


class MonitorSuricata:
    """
    Monitor contínuo do eve.json.

    Características:
    - leitura incremental;
    - cursor persistido atomicamente;
    - limpeza de temporários abandonados;
    - recuperação automática de cursor inválido;
    - detecção de rotação e truncamento;
    - semântica de entrega "pelo menos uma vez".
    """

    def __init__(
        self,
        eve_path: str,
        batch_size: int = 100,
        interval: float = 1.0,
        flush_interval: float = 5.0,
        cursor_path: str | None = None,
        start_at_end: bool = True,
    ):
        self.eve_path = str(Path(eve_path).expanduser())
        self.batch_size = max(1, int(batch_size))
        self.interval = max(0.1, float(interval))
        self.flush_interval = max(0.1, float(flush_interval))
        self.cursor_path = str(
            Path(cursor_path or f"{self.eve_path}.moonshield.cursor").expanduser()
        )
        self.start_at_end = bool(start_at_end)

        self.estatisticas = EstatisticasMonitor(
            arquivo=self.eve_path,
            cursor_path=self.cursor_path,
        )

    # ------------------------------------------------------------------
    # Cursor
    # ------------------------------------------------------------------

    def _diretorio_cursor(self) -> Path:
        return Path(self.cursor_path).resolve().parent

    def _preparar_cursor(self) -> None:
        """
        Cria o diretório e remove arquivos temporários abandonados.

        Arquivos `.tmp.*` nunca são promovidos manualmente. O próximo cursor
        válido será gravado novamente por `os.replace`.
        """
        diretorio = self._diretorio_cursor()
        diretorio.mkdir(parents=True, exist_ok=True)

        nome = Path(self.cursor_path).name
        for temporario in diretorio.glob(f"{nome}.tmp.*"):
            try:
                temporario.unlink()
                self.estatisticas.temporarios_removidos += 1
                logger.warning(
                    "Temporário de cursor abandonado removido: %s",
                    temporario,
                )
            except OSError as exc:
                logger.warning(
                    "Não foi possível remover temporário %s: %s",
                    temporario,
                    exc,
                )

    def _cursor_estruturalmente_valido(self, dados: object) -> bool:
        if not isinstance(dados, dict):
            return False

        obrigatorios = {"path", "offset", "inode", "device", "updated_at"}
        if not obrigatorios.issubset(dados):
            return False

        if not isinstance(dados.get("path"), str):
            return False
        if not isinstance(dados.get("offset"), int) or dados["offset"] < 0:
            return False
        if not isinstance(dados.get("inode"), int) or dados["inode"] < 0:
            return False
        if not isinstance(dados.get("device"), int) or dados["device"] < 0:
            return False
        if not isinstance(dados.get("updated_at"), str):
            return False

        try:
            datetime.fromisoformat(dados["updated_at"].replace("Z", "+00:00"))
        except ValueError:
            return False

        return True

    def _descartar_cursor_invalido(self, motivo: str) -> None:
        path = Path(self.cursor_path)
        self.estatisticas.cursores_invalidos += 1
        self.estatisticas.ultimo_erro = motivo

        try:
            path.unlink(missing_ok=True)
            logger.warning(
                "Cursor inválido removido para recriação automática: %s (%s)",
                path,
                motivo,
            )
        except OSError as exc:
            logger.error(
                "Falha ao remover cursor inválido %s: %s",
                path,
                exc,
            )

    def _carregar_cursor(self) -> dict | None:
        """Carrega o cursor ou o remove quando estiver inválido."""
        self._preparar_cursor()

        path = Path(self.cursor_path)
        if not path.exists():
            return None

        try:
            dados = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self._descartar_cursor_invalido(
                f"Falha de leitura/JSON: {exc}"
            )
            return None

        if not self._cursor_estruturalmente_valido(dados):
            self._descartar_cursor_invalido(
                "Estrutura obrigatória ausente ou tipos inválidos."
            )
            return None

        if os.path.abspath(dados["path"]) != os.path.abspath(self.eve_path):
            self._descartar_cursor_invalido(
                "Cursor aponta para outro arquivo EVE."
            )
            return None

        return dados

    def _salvar_cursor(self, offset: int, inode: int, device: int) -> bool:
        """Salva o cursor atomicamente e confirma o diretório no disco."""
        offset = max(0, int(offset))
        inode = max(0, int(inode))
        device = max(0, int(device))

        dados = {
            "path": self.eve_path,
            "offset": offset,
            "inode": inode,
            "device": device,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        destino = Path(self.cursor_path)
        destino.parent.mkdir(parents=True, exist_ok=True)
        temporario = destino.parent / (
            f"{destino.name}.tmp.{uuid.uuid4().hex[:12]}"
        )

        try:
            with temporario.open("w", encoding="utf-8", newline="\n") as arquivo:
                json.dump(dados, arquivo, ensure_ascii=False, indent=2)
                arquivo.write("\n")
                arquivo.flush()
                os.fsync(arquivo.fileno())

            os.replace(temporario, destino)

            try:
                fd = os.open(str(destino.parent), os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                logger.debug(
                    "Filesystem não ofereceu fsync do diretório do cursor."
                )

            self.estatisticas.offset_confirmado = offset
            self.estatisticas.cursores_recriados += 1
            return True
        except Exception as exc:
            self.estatisticas.ultimo_erro = str(exc)
            logger.exception("Falha ao salvar cursor %s.", destino)
            return False
        finally:
            try:
                temporario.unlink(missing_ok=True)
            except OSError:
                logger.warning(
                    "Não foi possível remover temporário do cursor: %s",
                    temporario,
                )

    # ------------------------------------------------------------------
    # Ingestão
    # ------------------------------------------------------------------

    def _enviar_buffer(
        self,
        buffer: list[dict],
        stop_event: Event,
        callback: Callable | None,
        max_tentativas: int | None = None,
    ) -> bool:
        """Envia eventos com retry e backoff progressivo."""
        if not buffer:
            return True

        tentativas = 0
        backoffs = [1, 2, 5, 10, 30]

        while not stop_event.is_set():
            try:
                resultado = ingerir_eventos_locais(buffer)

                if resultado.get("ok"):
                    self.estatisticas.lotes_enviados += 1
                    self.estatisticas.eventos_enviados += len(buffer)
                    self.estatisticas.ultimo_lote_em = (
                        datetime.now(timezone.utc).isoformat()
                    )

                    if callback:
                        callback({"tipo": "lote", "resultado": resultado})
                    return True

                raise RuntimeError(
                    resultado.get(
                        "erro",
                        "Erro desconhecido no pipeline de ingestão.",
                    )
                )

            except Exception as exc:
                self.estatisticas.falhas_ingestao += 1
                self.estatisticas.ultimo_erro = str(exc)
                logger.error("Falha ao processar lote: %s", exc)

                if callback:
                    callback({"tipo": "erro", "mensagem": str(exc)})

                tentativas += 1
                if (
                    max_tentativas is not None
                    and tentativas >= max_tentativas
                ):
                    logger.error(
                        "Limite de tentativas atingido ao processar lote."
                    )
                    return False

                delay = backoffs[min(tentativas - 1, len(backoffs) - 1)]
                stop_event.wait(delay)

        return False

    # ------------------------------------------------------------------
    # Loop principal
    # ------------------------------------------------------------------

    def executar(
        self,
        stop_event: Event | None = None,
        callback_status: Callable | None = None,
        run_once: bool = False,
    ) -> dict:
        """
        Executa o monitor.

        `run_once=True` lê até o EOF atual e encerra.
        """
        stop_event = stop_event or Event()

        self.estatisticas.iniciado_em = (
            datetime.now(timezone.utc).isoformat()
        )
        self.estatisticas.rodando = True

        if callback_status:
            callback_status(
                {"tipo": "inicializacao", "mensagem": "Monitor iniciado."}
            )

        cursor = self._carregar_cursor()
        current_offset = 0
        current_inode = 0
        current_device = 0
        arquivo_handle = None
        buffer_eventos: list[dict] = []
        ultimo_flush = time.time()

        def fechar_arquivo() -> None:
            nonlocal arquivo_handle
            if arquivo_handle is not None:
                try:
                    arquivo_handle.close()
                except Exception:
                    pass
                arquivo_handle = None

        def publicar_rotacao(tipo: str) -> None:
            if callback_status:
                callback_status(
                    {
                        "tipo": "rotacao",
                        "subtipo": tipo,
                        "mensagem": (
                            "Rotação detectada."
                            if tipo == "rotacao"
                            else "Truncamento detectado."
                        ),
                    }
                )

        try:
            while not stop_event.is_set():
                try:
                    stat_atual = os.stat(self.eve_path)

                    rotacionou = (
                        current_inode != 0
                        and (
                            stat_atual.st_ino != current_inode
                            or stat_atual.st_dev != current_device
                        )
                    )
                    truncou = (
                        current_inode != 0
                        and stat_atual.st_ino == current_inode
                        and stat_atual.st_dev == current_device
                        and current_offset > stat_atual.st_size
                    )

                    if rotacionou or truncou:
                        if rotacionou:
                            self.estatisticas.rotacoes_detectadas += 1
                            publicar_rotacao("rotacao")
                        else:
                            self.estatisticas.truncamentos_detectados += 1
                            publicar_rotacao("truncamento")

                        logger.warning(
                            "%s do EVE detectado. Offset antigo=%s, "
                            "novo tamanho=%s.",
                            "Rotação" if rotacionou else "Truncamento",
                            current_offset,
                            stat_atual.st_size,
                        )

                        if buffer_eventos:
                            sucesso = self._enviar_buffer(
                                buffer_eventos,
                                stop_event,
                                callback_status,
                            )
                            if not sucesso:
                                if stop_event.is_set():
                                    break
                                stop_event.wait(self.interval)
                                continue

                            if not self._salvar_cursor(
                                current_offset,
                                current_inode,
                                current_device,
                            ):
                                stop_event.wait(self.interval)
                                continue

                            buffer_eventos.clear()

                        fechar_arquivo()
                        current_inode = stat_atual.st_ino
                        current_device = stat_atual.st_dev
                        current_offset = 0
                        self.estatisticas.offset_atual = 0

                        # Confirma imediatamente o novo arquivo/truncamento.
                        self._salvar_cursor(
                            current_offset,
                            current_inode,
                            current_device,
                        )
                        cursor = None

                    if current_inode == 0 and current_device == 0:
                        current_inode = stat_atual.st_ino
                        current_device = stat_atual.st_dev

                        if cursor:
                            mesmo_arquivo = (
                                cursor["inode"] == current_inode
                                and cursor["device"] == current_device
                            )

                            if mesmo_arquivo:
                                offset_cursor = cursor["offset"]

                                if offset_cursor <= stat_atual.st_size:
                                    current_offset = offset_cursor
                                else:
                                    self.estatisticas.truncamentos_detectados += 1
                                    current_offset = 0
                                    logger.warning(
                                        "Cursor maior que o EVE atual; "
                                        "reiniciando no início."
                                    )
                            else:
                                self.estatisticas.rotacoes_detectadas += 1
                                current_offset = 0
                                logger.warning(
                                    "Cursor pertence a inode/device antigo; "
                                    "novo EVE será lido do início."
                                )

                        elif self.start_at_end:
                            current_offset = stat_atual.st_size
                        else:
                            current_offset = 0

                        self.estatisticas.offset_atual = current_offset

                        # Mesmo sem evento novo, sempre cria um cursor válido.
                        self._salvar_cursor(
                            current_offset,
                            current_inode,
                            current_device,
                        )
                        cursor = None

                except FileNotFoundError:
                    fechar_arquivo()
                    logger.warning(
                        "Arquivo EVE não encontrado: %s. Aguardando...",
                        self.eve_path,
                    )
                    if callback_status:
                        callback_status(
                            {
                                "tipo": "espera",
                                "mensagem": "Arquivo EVE ainda não existe.",
                            }
                        )
                    if run_once:
                        break
                    stop_event.wait(self.interval)
                    continue

                except PermissionError:
                    fechar_arquivo()
                    mensagem = (
                        f"Permissão negada para ler {self.eve_path}."
                    )
                    self.estatisticas.ultimo_erro = mensagem
                    logger.error(mensagem)
                    if callback_status:
                        callback_status(
                            {"tipo": "erro", "mensagem": mensagem}
                        )
                    if run_once:
                        break
                    stop_event.wait(self.interval)
                    continue

                if arquivo_handle is None:
                    try:
                        arquivo_handle = open(
                            self.eve_path,
                            "r",
                            encoding="utf-8",
                            errors="replace",
                        )
                        arquivo_handle.seek(current_offset)
                    except Exception as exc:
                        self.estatisticas.ultimo_erro = str(exc)
                        logger.error(
                            "Falha ao abrir %s: %s",
                            self.eve_path,
                            exc,
                        )
                        stop_event.wait(self.interval)
                        continue

                leu_algo = False

                while not stop_event.is_set():
                    pos_antes = arquivo_handle.tell()
                    linha = arquivo_handle.readline()

                    if not linha:
                        break

                    if not linha.endswith("\n"):
                        arquivo_handle.seek(pos_antes)
                        break

                    self.estatisticas.linhas_lidas += 1
                    leu_algo = True
                    current_offset = arquivo_handle.tell()
                    self.estatisticas.offset_atual = current_offset
                    linha = linha.strip()

                    if not linha:
                        self.estatisticas.linhas_vazias += 1
                        continue

                    try:
                        evento = json.loads(linha)
                        if isinstance(evento, dict):
                            buffer_eventos.append(evento)
                            self.estatisticas.eventos_enfileirados += 1
                            self.estatisticas.ultimo_evento_em = (
                                datetime.now(timezone.utc).isoformat()
                            )
                        else:
                            self.estatisticas.objetos_invalidos += 1
                    except json.JSONDecodeError:
                        self.estatisticas.json_invalidos += 1

                    if len(buffer_eventos) >= self.batch_size:
                        sucesso = self._enviar_buffer(
                            buffer_eventos,
                            stop_event,
                            callback_status,
                        )
                        if sucesso:
                            if self._salvar_cursor(
                                current_offset,
                                current_inode,
                                current_device,
                            ):
                                if callback_status:
                                    callback_status(
                                        {
                                            "tipo": "cursor",
                                            "offset": current_offset,
                                        }
                                    )
                                buffer_eventos.clear()
                                ultimo_flush = time.time()

                agora = time.time()
                if (
                    buffer_eventos
                    and (agora - ultimo_flush) >= self.flush_interval
                ):
                    sucesso = self._enviar_buffer(
                        buffer_eventos,
                        stop_event,
                        callback_status,
                    )
                    if sucesso and self._salvar_cursor(
                        current_offset,
                        current_inode,
                        current_device,
                    ):
                        if callback_status:
                            callback_status(
                                {
                                    "tipo": "cursor",
                                    "offset": current_offset,
                                }
                            )
                        buffer_eventos.clear()
                        ultimo_flush = agora

                if (
                    not buffer_eventos
                    and current_offset
                    > self.estatisticas.offset_confirmado
                ):
                    if self._salvar_cursor(
                        current_offset,
                        current_inode,
                        current_device,
                    ) and callback_status:
                        callback_status(
                            {
                                "tipo": "cursor",
                                "offset": current_offset,
                            }
                        )

                if run_once and not leu_algo:
                    break

                if not leu_algo and not stop_event.is_set():
                    stop_event.wait(self.interval)

        except Exception as exc:
            self.estatisticas.ultimo_erro = str(exc)
            logger.exception(
                "Erro crítico no loop do MonitorSuricata."
            )
            if callback_status:
                callback_status(
                    {
                        "tipo": "erro",
                        "mensagem": f"Erro crítico: {exc}",
                    }
                )

        finally:
            fechar_arquivo()

            if buffer_eventos:
                logger.info(
                    "Enviando lote parcial final no encerramento."
                )
                evento_final = Event()
                sucesso = self._enviar_buffer(
                    buffer_eventos,
                    evento_final,
                    callback_status,
                    max_tentativas=3,
                )

                if sucesso:
                    if self._salvar_cursor(
                        current_offset,
                        current_inode,
                        current_device,
                    ):
                        buffer_eventos.clear()
                else:
                    logger.warning(
                        "Falha ao enviar lote final. Cursor não avançará."
                    )

            self.estatisticas.rodando = False
            self.estatisticas.encerrado_em = (
                datetime.now(timezone.utc).isoformat()
            )

            if callback_status:
                callback_status(
                    {
                        "tipo": "encerramento",
                        "mensagem": "Monitor encerrado.",
                    }
                )

        return self.estatisticas.como_dict()