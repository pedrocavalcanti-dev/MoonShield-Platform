import os
import json
import time
import logging
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Callable
from threading import Event

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
    ultimo_evento_em: str = ""
    ultimo_lote_em: str = ""
    ultimo_erro: str = ""
    iniciado_em: str = ""
    encerrado_em: str = ""

    def como_dict(self) -> dict:
        return asdict(self)


class MonitorSuricata:
    """
    Monitor contínuo para leitura do eve.json do Suricata.
    Garante leitura incremental, detecção de rotação, resiliência a falhas
    e semântica 'pelo menos uma vez' via persistência de cursor atômico.
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
        self.eve_path = eve_path
        self.batch_size = batch_size
        self.interval = interval
        self.flush_interval = flush_interval
        self.cursor_path = cursor_path or f"{eve_path}.moonshield.cursor"
        self.start_at_end = start_at_end
        
        self.estatisticas = EstatisticasMonitor(
            arquivo=self.eve_path,
            cursor_path=self.cursor_path,
        )

    def _carregar_cursor(self) -> dict | None:
        """Lê o cursor salvo no disco, se existir e for válido."""
        if not os.path.exists(self.cursor_path):
            return None
        
        try:
            with open(self.cursor_path, "r", encoding="utf-8") as f:
                dados = json.load(f)
            
            if not isinstance(dados, dict) or "offset" not in dados:
                raise ValueError("Formato de cursor inválido (sem offset).")
            if not isinstance(dados["offset"], int) or dados["offset"] < 0:
                raise ValueError("Offset inválido ou negativo.")
                
            return dados
        except Exception as e:
            logger.warning(f"Falha ao carregar cursor {self.cursor_path}: {e}")
            return None

    def _salvar_cursor(self, offset: int, inode: int, device: int):
        """Salva o cursor no disco de forma atômica para não corromper em quedas de energia."""
        dados = {
            "path": self.eve_path,
            "offset": offset,
            "inode": inode,
            "device": device,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        temp_path = self.cursor_path + f".tmp.{uuid.uuid4().hex[:8]}"
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.cursor_path)), exist_ok=True)
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(dados, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            
            os.replace(temp_path, self.cursor_path)
            self.estatisticas.offset_confirmado = offset
        except Exception as e:
            logger.error(f"Falha ao salvar cursor: {e}")

    def _enviar_buffer(
        self, 
        buffer: list[dict], 
        stop_event: Event, 
        callback: Callable | None, 
        max_tentativas: int | None = None
    ) -> bool:
        """Envia os eventos com política de retry e backoff progressivo limitável."""
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
                    self.estatisticas.ultimo_lote_em = datetime.now(timezone.utc).isoformat()
                    
                    if callback:
                        callback({"tipo": "lote", "resultado": resultado})
                    return True
                else:
                    msg_erro = resultado.get("erro", "Erro desconhecido no pipeline.")
                    raise RuntimeError(msg_erro)
                    
            except Exception as e:
                self.estatisticas.falhas_ingestao += 1
                self.estatisticas.ultimo_erro = str(e)
                logger.error(f"Falha ao processar lote: {e}")
                if callback:
                    callback({"tipo": "erro", "mensagem": str(e)})
                
                tentativas += 1
                if max_tentativas is not None and tentativas >= max_tentativas:
                    logger.error("Limite de tentativas atingido ao processar o lote.")
                    return False
                    
                delay = backoffs[min(tentativas - 1, len(backoffs) - 1)]
                logger.info(f"Aguardando {delay}s para tentar novamente (Tentativa {tentativas})...")
                stop_event.wait(delay)
                
        return False

    def executar(self, stop_event: Event = None, callback_status: Callable = None, run_once: bool = False) -> dict:
        """
        Loop principal de monitoramento.
        run_once=True lerá até o final do arquivo e encerrará imediatamente.
        """
        if stop_event is None:
            stop_event = Event()

        self.estatisticas.iniciado_em = datetime.now(timezone.utc).isoformat()
        self.estatisticas.rodando = True

        if callback_status:
            callback_status({"tipo": "inicializacao", "mensagem": "Monitor iniciado."})

        # Inicialização e leitura do Cursor
        cursor = self._carregar_cursor()
        current_offset = 0
        current_inode = 0
        current_device = 0
        
        arquivo_handle = None
        buffer_eventos = []
        ultimo_flush = time.time()

        def _fechar_arquivo():
            nonlocal arquivo_handle
            if arquivo_handle:
                try:
                    arquivo_handle.close()
                except Exception:
                    pass
                arquivo_handle = None

        try:
            while not stop_event.is_set():
                # 1. Tenta acessar o arquivo e verificar stat (rotação/truncamento)
                try:
                    st = os.stat(self.eve_path)
                    
                    # Primeira execução (abertura) ou rotação
                    rotacao = False
                    if current_inode != 0 and (st.st_ino != current_inode or st.st_dev != current_device):
                        rotacao = True
                    elif current_offset > st.st_size:
                        rotacao = True # Truncamento
                        
                    if rotacao:
                        self.estatisticas.rotacoes_detectadas += 1
                        logger.info("Rotação/truncamento de arquivo detectado.")
                        if callback_status:
                            callback_status({"tipo": "rotacao", "mensagem": "Novo arquivo/truncamento detectado."})
                        
                        # Processa e limpa buffer antigo antes de resetar contexto do arquivo
                        if buffer_eventos:
                            logger.info("Enviando lote pendente antes de rotacionar o arquivo...")
                            sucesso = self._enviar_buffer(buffer_eventos, stop_event, callback_status)
                            
                            if not sucesso:
                                # Em caso de falha (provavelmente porque stop_event disparou), 
                                # deixamos para o encerramento tratar o buffer
                                continue
                            
                            # Salva confirmando a vida do arquivo antigo antes do reset
                            self._salvar_cursor(current_offset, current_inode, current_device)
                            buffer_eventos.clear()
                            
                        _fechar_arquivo()
                        
                        current_inode = st.st_ino
                        current_device = st.st_dev
                        current_offset = 0
                        self.estatisticas.offset_atual = 0
                    
                    # Configura estado inicial se estivermos abrindo o arquivo pela primeira vez
                    if current_inode == 0 and current_device == 0:
                        current_inode = st.st_ino
                        current_device = st.st_dev
                        
                        if cursor:
                            if cursor.get("inode") == current_inode and cursor.get("device") == current_device:
                                offset_cursor = cursor.get("offset", 0)
                                if offset_cursor > st.st_size:
                                    logger.warning("Cursor maior que o arquivo atual. Truncamento detectado; reiniciando do zero.")
                                    current_offset = 0
                                    self.estatisticas.rotacoes_detectadas += 1
                                else:
                                    current_offset = offset_cursor
                            else:
                                current_offset = 0 
                        elif self.start_at_end:
                            current_offset = st.st_size
                            self._salvar_cursor(current_offset, current_inode, current_device)

                except FileNotFoundError:
                    logger.warning(f"Arquivo {self.eve_path} não encontrado. Aguardando...")
                    _fechar_arquivo()
                    if run_once:
                        break
                    stop_event.wait(self.interval)
                    continue
                except PermissionError:
                    logger.error(f"Permissão negada para ler {self.eve_path}.")
                    if callback_status:
                        callback_status({"tipo": "erro", "mensagem": "Permissão negada no arquivo EVE."})
                    _fechar_arquivo()
                    if run_once:
                        break
                    stop_event.wait(self.interval)
                    continue

                # 2. Abrir ou manter aberto
                if not arquivo_handle:
                    try:
                        arquivo_handle = open(self.eve_path, "r", encoding="utf-8", errors="replace")
                        arquivo_handle.seek(current_offset)
                    except Exception as e:
                        logger.error(f"Falha ao abrir {self.eve_path}: {e}")
                        stop_event.wait(self.interval)
                        continue
                
                # 3. Leitura contínua
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
                            self.estatisticas.ultimo_evento_em = datetime.now(timezone.utc).isoformat()
                        else:
                            self.estatisticas.objetos_invalidos += 1
                    except json.JSONDecodeError:
                        self.estatisticas.json_invalidos += 1

                    if len(buffer_eventos) >= self.batch_size:
                        sucesso = self._enviar_buffer(buffer_eventos, stop_event, callback_status)
                        if sucesso:
                            self._salvar_cursor(current_offset, current_inode, current_device)
                            if callback_status:
                                callback_status({"tipo": "cursor", "offset": current_offset})
                            buffer_eventos.clear()
                            ultimo_flush = time.time()
                
                # Flush por tempo (se temos lotes parciais presos e o tempo passou)
                agora = time.time()
                if buffer_eventos and (agora - ultimo_flush) >= self.flush_interval:
                    sucesso = self._enviar_buffer(buffer_eventos, stop_event, callback_status)
                    if sucesso:
                        self._salvar_cursor(current_offset, current_inode, current_device)
                        if callback_status:
                            callback_status({"tipo": "cursor", "offset": current_offset})
                        buffer_eventos.clear()
                        ultimo_flush = agora

                # Confirmar cursor quando não há buffer (linhas vazias, JSON inválido)
                if not buffer_eventos and current_offset > self.estatisticas.offset_confirmado:
                    self._salvar_cursor(current_offset, current_inode, current_device)
                    if callback_status:
                        callback_status({"tipo": "cursor", "offset": current_offset})

                if run_once and not leu_algo:
                    break

                if not leu_algo and not stop_event.is_set():
                    stop_event.wait(self.interval)

        except Exception as e:
            logger.exception("Erro crítico no loop de execução do MonitorSuricata.")
            if callback_status:
                callback_status({"tipo": "erro", "mensagem": f"Erro crítico: {e}"})
        finally:
            _fechar_arquivo()
            
            # Envia o lote parcial final no encerramento (se houver) com tentativas limitadas
            if buffer_eventos:
                logger.info("Enviando lote parcial final no encerramento...")
                evento_final = Event() 
                sucesso = self._enviar_buffer(
                    buffer_eventos, 
                    evento_final, 
                    callback_status, 
                    max_tentativas=3
                )
                
                if sucesso:
                    self._salvar_cursor(current_offset, current_inode, current_device)
                    buffer_eventos.clear()
                else:
                    logger.warning("Falha ao enviar lote final durante encerramento. Cursor não será salvo.")
            
            self.estatisticas.rodando = False
            self.estatisticas.encerrado_em = datetime.now(timezone.utc).isoformat()
            
            if callback_status:
                callback_status({"tipo": "encerramento", "mensagem": "Monitor encerrado."})

        return self.estatisticas.como_dict()