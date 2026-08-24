"""
MoonShield Agent — Servidor IPC Unix Socket
===========================================

Servidor local privilegiado do MoonShield-Agent.

O Django NÃO executa nftables diretamente e NÃO acessa nenhuma porta HTTP.
Toda operação privilegiada passa por:

    /run/moonshield/agent.sock

Segurança:
- Unix Domain Socket somente local.
- Socket 0660.
- Owner root.
- Group configurável (padrão: moonshield).
- Allowlist de ações definida em protocolo.py.
- Tamanho máximo por mensagem.
- Um request por conexão.
- Sem shell, sem eval e sem execução arbitrária de comandos recebidos.

Este arquivo já define o contrato das funções que os próximos módulos
(aplicador/status/instalador/rollback) deverão oferecer.
"""

from __future__ import annotations

import grp
import importlib
import logging
import os
import socket
import socketserver
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable

from firewall.ipc.protocolo import (
    MAX_MENSAGEM_BYTES,
    SOCKET_PADRAO,
    AcaoNaoPermitida,
    ErroProtocolo,
    RequisicaoIPC,
    codificar_resposta,
    decodificar_requisicao,
    resposta_erro,
    resposta_ok,
)


logger = logging.getLogger(__name__)

VERSAO_SERVIDOR_IPC = "1.0"
DIRETORIO_PADRAO = "/run/moonshield"
GRUPO_PADRAO = "moonshield"
SOCKET_MODE = 0o660
DIRETORIO_MODE = 0o750
TIMEOUT_CLIENTE = 15.0
MAX_CONEXOES_SIMULTANEAS = 32

_estado_lock = threading.Lock()
_estado = {
    "rodando": False,
    "socket": SOCKET_PADRAO,
    "iniciado_em": None,
    "requisicoes": 0,
    "sucessos": 0,
    "erros": 0,
    "ultima_acao": None,
    "ultima_requisicao_em": None,
}

_servidor_ref: "_ServidorUnix | None" = None
_thread_ref: threading.Thread | None = None
_semaforo = threading.BoundedSemaphore(MAX_CONEXOES_SIMULTANEAS)


# =============================================================================
# INICIALIZAÇÃO DA REDE
# =============================================================================

def _inicializar_rede() -> None:
    """
    Inicializa o subsistema persistente de Safe Apply da Rede.

    Deve acontecer ANTES da abertura do socket IPC para que nenhuma nova
    alteração seja aceita enquanto estados pendentes não forem reconciliados.

    Em caso de reinicialização do Agent:
    - alterações ainda dentro do prazo recuperam o timer;
    - alterações expiradas executam rollback;
    - falhas ficam registradas em log.
    """

    try:
        from rede.nucleo.configuracao import garantir_diretorios
        from rede.nucleo.rollback import inicializar_rollback_pendente

        garantir_diretorios()

        resultado = inicializar_rollback_pendente()

        recuperadas = resultado.get("recuperadas", [])
        revertidas = resultado.get("revertidas", [])
        erros = resultado.get("erros", [])

        logger.info(
            "[rede] Safe Apply inicializado | recuperadas=%s revertidas=%s erros=%s",
            len(recuperadas),
            len(revertidas),
            len(erros),
        )

        for alteracao_id in recuperadas:
            logger.info(
                "[rede] Safe Apply recuperado | alteracao_id=%s",
                alteracao_id,
            )

        for alteracao_id in revertidas:
            logger.warning(
                "[rede] rollback automático recuperado no boot | alteracao_id=%s",
                alteracao_id,
            )

        for erro in erros:
            logger.error(
                "[rede] falha ao recuperar alteração | alteracao_id=%s erro=%s",
                erro.get("alteracao_id"),
                erro.get("erro"),
            )

    except Exception:
        logger.exception(
            "[rede] falha durante inicialização do Safe Apply"
        )


# =============================================================================
# API PÚBLICA
# =============================================================================

def obter_stats() -> dict[str, Any]:
    with _estado_lock:
        return dict(_estado)


def esta_rodando() -> bool:
    with _estado_lock:
        return bool(_estado["rodando"])


def iniciar_servidor(
    *,
    socket_path: str = SOCKET_PADRAO,
    grupo: str = GRUPO_PADRAO,
    bloquear: bool = False,
) -> threading.Thread | None:
    global _servidor_ref, _thread_ref

    if esta_rodando():
        logger.info(
            "[ipc] servidor já está ativo em %s",
            _estado["socket"],
        )
        return _thread_ref

    # Antes de aceitar qualquer operação privilegiada de Rede,
    # recuperamos o estado persistente do Safe Apply.
    _inicializar_rede()

    _preparar_socket_path(socket_path)

    servidor = _ServidorUnix(
        socket_path,
        _HandlerIPC,
    )

    servidor.daemon_threads = True
    servidor.allow_reuse_address = False

    try:
        _configurar_permissoes_socket(
            socket_path,
            grupo,
        )
    except Exception:
        servidor.server_close()
        _remover_socket_se_existir(socket_path)
        raise

    _servidor_ref = servidor

    with _estado_lock:
        _estado.update({
            "rodando": True,
            "socket": socket_path,
            "iniciado_em": time.time(),
            "requisicoes": 0,
            "sucessos": 0,
            "erros": 0,
            "ultima_acao": None,
            "ultima_requisicao_em": None,
        })

    logger.info(
        "[ipc] MoonShield IPC v%s ativo em %s (modo=%o, grupo=%s)",
        VERSAO_SERVIDOR_IPC,
        socket_path,
        SOCKET_MODE,
        grupo,
    )

    if bloquear:
        try:
            servidor.serve_forever(
                poll_interval=0.5
            )
        finally:
            _finalizar_servidor(
                socket_path
            )

        return None

    def _run():
        try:
            servidor.serve_forever(
                poll_interval=0.5
            )
        except Exception:
            logger.exception(
                "[ipc] falha fatal no loop do servidor"
            )
        finally:
            _finalizar_servidor(
                socket_path
            )

    thread = threading.Thread(
        target=_run,
        name="moonshield-ipc",
        daemon=True,
    )

    _thread_ref = thread
    thread.start()

    return thread


def parar_servidor() -> None:
    global _servidor_ref, _thread_ref

    servidor = _servidor_ref

    if servidor is None:
        return

    try:
        servidor.shutdown()
    except Exception:
        logger.exception(
            "[ipc] erro durante shutdown"
        )

    try:
        servidor.server_close()
    except Exception:
        logger.exception(
            "[ipc] erro ao fechar socket"
        )

    socket_path = str(
        servidor.server_address
    )

    _remover_socket_se_existir(
        socket_path
    )

    with _estado_lock:
        _estado["rodando"] = False

    _servidor_ref = None
    _thread_ref = None


# =============================================================================
# SOCKET SERVER
# =============================================================================

class _ServidorUnix(
    socketserver.ThreadingMixIn,
    socketserver.UnixStreamServer,
):
    daemon_threads = True
    block_on_close = False
    address_family = socket.AF_UNIX
    socket_type = socket.SOCK_STREAM


class _HandlerIPC(socketserver.BaseRequestHandler):
    """Uma conexão = uma requisição = uma resposta."""

    def handle(self) -> None:
        requisicao: RequisicaoIPC | None = None

        if not _semaforo.acquire(
            blocking=False
        ):
            self._enviar(
                resposta_erro(
                    None,
                    codigo="ocupado",
                    mensagem=(
                        "MoonShield-Agent está processando "
                        "muitas requisições."
                    ),
                )
            )
            return

        try:
            self.request.settimeout(
                TIMEOUT_CLIENTE
            )

            raw = self._receber_linha()

            try:
                requisicao = decodificar_requisicao(
                    raw
                )

            except AcaoNaoPermitida as exc:
                self._registrar_erro(
                    None
                )

                self._enviar(
                    resposta_erro(
                        None,
                        codigo="acao_nao_permitida",
                        mensagem=str(exc),
                    )
                )

                return

            except ErroProtocolo as exc:
                self._registrar_erro(
                    None
                )

                self._enviar(
                    resposta_erro(
                        None,
                        codigo="protocolo_invalido",
                        mensagem=str(exc),
                    )
                )

                return

            self._registrar_inicio(
                requisicao
            )

            try:
                dados = _despachar(
                    requisicao
                )

                self._registrar_sucesso()

                self._enviar(
                    resposta_ok(
                        requisicao,
                        dados,
                    )
                )

            except ErroOperacao as exc:
                self._registrar_erro(
                    requisicao
                )

                logger.warning(
                    "[ipc] operação recusada | acao=%s id=%s codigo=%s mensagem=%s",
                    requisicao.acao,
                    requisicao.id,
                    exc.codigo,
                    str(exc),
                )

                self._enviar(
                    resposta_erro(
                        requisicao,
                        codigo=exc.codigo,
                        mensagem=str(exc),
                        detalhes=exc.detalhes,
                    )
                )

            except Exception as exc:
                logger.exception(
                    "[ipc] erro não tratado | acao=%s id=%s",
                    requisicao.acao,
                    requisicao.id,
                )

                self._registrar_erro(
                    requisicao
                )

                self._enviar(
                    resposta_erro(
                        requisicao,
                        codigo="erro_interno",
                        mensagem=(
                            "Falha interna ao executar "
                            "a operação."
                        ),
                        detalhes={
                            "tipo": type(exc).__name__,
                        },
                    )
                )

        except socket.timeout:
            self._registrar_erro(
                requisicao
            )

            if requisicao is not None:
                try:
                    self._enviar(
                        resposta_erro(
                            requisicao,
                            codigo="timeout",
                            mensagem=(
                                "Tempo limite da conexão "
                                "excedido."
                            ),
                        )
                    )
                except Exception:
                    pass

        except ConnectionError:
            self._registrar_erro(
                requisicao
            )

        finally:
            _semaforo.release()

    def _receber_linha(self) -> bytes:
        buffer = bytearray()

        while True:
            bloco = self.request.recv(
                min(
                    65536,
                    MAX_MENSAGEM_BYTES + 1,
                )
            )

            if not bloco:
                break

            buffer.extend(
                bloco
            )

            if len(buffer) > MAX_MENSAGEM_BYTES:
                raise ErroProtocolo(
                    "Mensagem excede o limite permitido."
                )

            pos = buffer.find(
                b"\n"
            )

            if pos >= 0:
                restante = buffer[
                    pos + 1:
                ]

                if restante.strip():
                    raise ErroProtocolo(
                        "A conexão aceita apenas uma "
                        "requisição por vez."
                    )

                return bytes(
                    buffer[:pos]
                )

        if not buffer:
            raise ErroProtocolo(
                "Conexão encerrada sem mensagem."
            )

        return bytes(
            buffer
        )

    def _enviar(self, resposta) -> None:
        self.request.sendall(
            codificar_resposta(
                resposta
            )
        )

    @staticmethod
    def _registrar_inicio(
        req: RequisicaoIPC,
    ) -> None:
        with _estado_lock:
            _estado["requisicoes"] += 1
            _estado["ultima_acao"] = req.acao
            _estado["ultima_requisicao_em"] = time.time()

        logger.info(
            "[ipc] %s | id=%s",
            req.acao,
            req.id,
        )

    @staticmethod
    def _registrar_sucesso() -> None:
        with _estado_lock:
            _estado["sucessos"] += 1

    @staticmethod
    def _registrar_erro(
        req: RequisicaoIPC | None,
    ) -> None:
        with _estado_lock:
            _estado["erros"] += 1


# =============================================================================
# DESPACHANTE
# =============================================================================

class ErroOperacao(RuntimeError):
    def __init__(
        self,
        mensagem: str,
        *,
        codigo: str = "operacao_falhou",
        detalhes: dict[str, Any] | None = None,
    ):
        super().__init__(
            mensagem
        )

        self.codigo = codigo
        self.detalhes = detalhes or {}


def _despachar(
    req: RequisicaoIPC,
) -> dict[str, Any]:
    if req.acao.startswith(
        "network."
    ):
        return _despachar_rede(
            req
        )

    handler = _HANDLERS.get(
        req.acao
    )

    if handler is None:
        raise ErroOperacao(
            f"Ação sem handler: {req.acao}",
            codigo="acao_sem_handler",
        )

    resultado = handler(
        req.dados
    )

    if resultado is None:
        return {}

    if isinstance(
        resultado,
        dict,
    ):
        return resultado

    return {
        "resultado": resultado,
    }


def _despachar_rede(
    req: RequisicaoIPC,
) -> dict[str, Any]:
    """
    Encaminha ações network.* para o dispatcher oficial do módulo Rede.

    O servidor IPC continua sendo único:
        /run/moonshield/agent.sock

    O módulo Rede recebe somente:
        ação já validada;
        dados da requisição.
    """

    try:
        modulo = importlib.import_module(
            "rede.ipc.handlers"
        )

    except Exception as exc:
        raise ErroOperacao(
            (
                "Não foi possível carregar "
                f"o módulo de Rede: {exc}"
            ),
            codigo="rede_modulo_indisponivel",
            detalhes={
                "tipo": type(exc).__name__,
            },
        ) from exc

    executar = getattr(
        modulo,
        "executar_acao_rede",
        None,
    )

    if not callable(
        executar
    ):
        raise ErroOperacao(
            (
                "O dispatcher do módulo de "
                "Rede não está disponível."
            ),
            codigo="rede_dispatcher_indisponivel",
        )

    try:
        resultado = executar(
            req.acao,
            req.dados,
        )

    except Exception as exc:
        codigo = str(
            getattr(
                exc,
                "codigo",
                "",
            )
            or "rede_operacao_falhou"
        )

        detalhes = (
            getattr(
                exc,
                "detalhes",
                {},
            )
            or {}
        )

        if not isinstance(
            detalhes,
            dict,
        ):
            detalhes = {
                "detalhes": str(
                    detalhes
                )
            }

        logger.warning(
            "[rede] operação falhou | acao=%s id=%s codigo=%s mensagem=%s detalhes=%s",
            req.acao,
            req.id,
            codigo,
            str(exc),
            detalhes,
        )

        raise ErroOperacao(
            (
                str(exc)
                or "A operação de Rede falhou."
            ),
            codigo=codigo,
            detalhes=detalhes,
        ) from exc

    if resultado is None:
        return {}

    if isinstance(
        resultado,
        dict,
    ):
        return resultado

    raise ErroOperacao(
        "O módulo de Rede retornou um formato inválido.",
        codigo="rede_resposta_invalida",
        detalhes={
            "tipo": type(resultado).__name__,
        },
    )


# =============================================================================
# HANDLERS
# =============================================================================

def _h_ping(
    _: dict[str, Any],
) -> dict[str, Any]:
    return {
        "pong": True,
        "servico": "moonshield-agent",
        "ipc": VERSAO_SERVIDOR_IPC,
        "pid": os.getpid(),
        "uptime_segundos": _uptime_segundos(),
        "socket": _estado.get(
            "socket",
            SOCKET_PADRAO,
        ),
    }


def _h_info(
    _: dict[str, Any],
) -> dict[str, Any]:
    return {
        "servico": "moonshield-agent",
        "pid": os.getpid(),
        "uid": (
            os.getuid()
            if hasattr(
                os,
                "getuid",
            )
            else None
        ),
        "gid": (
            os.getgid()
            if hasattr(
                os,
                "getgid",
            )
            else None
        ),
        "ipc": VERSAO_SERVIDOR_IPC,
        "uptime_segundos": _uptime_segundos(),
        "stats": obter_stats(),
    }


def _h_firewall_status(
    _: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel([
        (
            "firewall.nucleo.status",
            "obter_status",
        ),
        (
            "firewall.nucleo.instalador",
            "obter_status",
        ),
    ])


def _h_firewall_interfaces(
    _: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel([
        (
            "firewall.nucleo.status",
            "obter_interfaces",
        ),
        (
            "firewall.nucleo.status",
            "listar_interfaces",
        ),
    ])


def _h_firewall_rules(
    _: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel([
        (
            "firewall.nucleo.status",
            "obter_regras",
        ),
        (
            "firewall.nucleo.status",
            "listar_regras",
        ),
        (
            "firewall.nucleo.instalador",
            "listar_regras",
        ),
    ])


def _h_firewall_emergency(
    _: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel([
        (
            "firewall.nucleo.status",
            "obter_emergency",
        ),
        (
            "firewall.nucleo.status",
            "listar_emergency",
        ),
    ])


def _h_firewall_diagnostico(
    dados: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.status",
                "diagnosticar",
            ),
            (
                "firewall.nucleo.status",
                "executar_diagnostico",
            ),
        ],
        dados,
    )


def _h_firewall_install(
    dados: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.instalador",
                "instalar",
            ),
            (
                "firewall.nucleo.instalador",
                "instalar_firewall",
            ),
            (
                "firewall.nucleo.instalador",
                "instalar_regras",
            ),
        ],
        dados,
    )


def _h_firewall_repair(
    dados: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.instalador",
                "reparar",
            ),
            (
                "firewall.nucleo.instalador",
                "reparar_firewall",
            ),
        ],
        dados,
    )


def _h_firewall_uninstall(
    dados: dict[str, Any],
) -> dict[str, Any]:
    if not _bool(
        dados.get("confirmar")
    ):
        raise ErroOperacao(
            (
                "A desinstalação exige "
                "dados.confirmar=true."
            ),
            codigo="confirmacao_necessaria",
        )

    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.instalador",
                "desinstalar",
            ),
            (
                "firewall.nucleo.instalador",
                "remover",
            ),
            (
                "firewall.nucleo.instalador",
                "remover_regras",
            ),
        ],
        dados,
    )


def _h_firewall_apply(
    dados: dict[str, Any],
) -> dict[str, Any]:
    regras = dados.get(
        "regras",
        dados.get(
            "rules",
            [],
        ),
    )

    if not isinstance(
        regras,
        list,
    ):
        raise ErroOperacao(
            "dados.regras deve ser uma lista.",
            codigo="payload_invalido",
        )

    iface_map = (
        dados.get("iface_map")
        or {}
    )

    if not isinstance(
        iface_map,
        dict,
    ):
        raise ErroOperacao(
            (
                "dados.iface_map deve ser "
                "um objeto."
            ),
            codigo="payload_invalido",
        )

    payload = dict(
        dados
    )

    payload["regras"] = regras
    payload["iface_map"] = iface_map

    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.aplicador",
                "aplicar",
            ),
            (
                "firewall.nucleo.aplicador",
                "aplicar_regras",
            ),
        ],
        payload,
    )


def _h_firewall_rollback(
    dados: dict[str, Any],
) -> dict[str, Any]:
    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.rollback",
                "restaurar_ultimo",
            ),
            (
                "firewall.nucleo.rollback",
                "rollback",
            ),
            (
                "firewall.nucleo.rollback",
                "restaurar",
            ),
        ],
        dados,
    )


def _h_firewall_block(
    dados: dict[str, Any],
) -> dict[str, Any]:
    ip = str(
        dados.get("ip")
        or ""
    ).strip()

    if not ip:
        raise ErroOperacao(
            "Campo dados.ip é obrigatório.",
            codigo="payload_invalido",
        )

    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.aplicador",
                "bloquear_ip",
            ),
            (
                "firewall.nucleo.aplicador",
                "bloquear",
            ),
        ],
        dados,
    )


def _h_firewall_unblock(
    dados: dict[str, Any],
) -> dict[str, Any]:
    ip = str(
        dados.get("ip")
        or ""
    ).strip()

    if not ip:
        raise ErroOperacao(
            "Campo dados.ip é obrigatório.",
            codigo="payload_invalido",
        )

    return _chamar_primeiro_disponivel(
        [
            (
                "firewall.nucleo.aplicador",
                "liberar_ip",
            ),
            (
                "firewall.nucleo.aplicador",
                "desbloquear_ip",
            ),
            (
                "firewall.nucleo.aplicador",
                "liberar",
            ),
        ],
        dados,
    )


_HANDLERS: dict[
    str,
    Callable[
        [dict[str, Any]],
        dict[str, Any],
    ],
] = {
    "system.ping": _h_ping,
    "system.info": _h_info,
    "firewall.status": _h_firewall_status,
    "firewall.interfaces": _h_firewall_interfaces,
    "firewall.rules": _h_firewall_rules,
    "firewall.emergency": _h_firewall_emergency,
    "firewall.diagnostico": _h_firewall_diagnostico,
    "firewall.install": _h_firewall_install,
    "firewall.repair": _h_firewall_repair,
    "firewall.uninstall": _h_firewall_uninstall,
    "firewall.apply": _h_firewall_apply,
    "firewall.rollback": _h_firewall_rollback,
    "firewall.block": _h_firewall_block,
    "firewall.unblock": _h_firewall_unblock,
}


# =============================================================================
# ADAPTADOR TEMPORÁRIO DOS MÓDULOS
# =============================================================================

def _chamar_primeiro_disponivel(
    candidatos: list[
        tuple[
            str,
            str,
        ]
    ],
    dados: dict[str, Any] | None = None,
) -> dict[str, Any]:
    erros_import: list[str] = []

    for modulo_nome, func_nome in candidatos:
        try:
            modulo = importlib.import_module(
                modulo_nome
            )

        except Exception as exc:
            erros_import.append(
                (
                    f"{modulo_nome}: "
                    f"{type(exc).__name__}: {exc}"
                )
            )
            continue

        func = getattr(
            modulo,
            func_nome,
            None,
        )

        if not callable(
            func
        ):
            continue

        try:
            if dados:
                try:
                    resultado = func(
                        dados
                    )
                except TypeError:
                    resultado = func()

            else:
                try:
                    resultado = func()
                except TypeError:
                    resultado = func({})

        except Exception as exc:
            raise ErroOperacao(
                (
                    f"{modulo_nome}.{func_nome} "
                    f"falhou: {exc}"
                ),
                codigo="falha_modulo_firewall",
                detalhes={
                    "modulo": modulo_nome,
                    "funcao": func_nome,
                    "tipo": type(exc).__name__,
                },
            ) from exc

        return _normalizar_resultado_modulo(
            resultado
        )

    raise ErroOperacao(
        (
            "Operação ainda não está disponível "
            "no núcleo do Firewall."
        ),
        codigo="modulo_indisponivel",
        detalhes={
            "tentativas": erros_import,
        },
    )


def _normalizar_resultado_modulo(
    resultado: Any,
) -> dict[str, Any]:
    if resultado is None:
        return {}

    if isinstance(
        resultado,
        dict,
    ):
        if resultado.get("ok") is False:
            msg = (
                resultado.get("erro")
                or resultado.get("error")
                or resultado.get("mensagem")
                or "Operação recusada pelo módulo."
            )

            raise ErroOperacao(
                str(msg),
                codigo=str(
                    resultado.get("codigo")
                    or "operacao_falhou"
                ),
                detalhes={
                    k: v
                    for k, v in resultado.items()
                    if k not in {
                        "ok",
                        "erro",
                        "error",
                        "mensagem",
                        "codigo",
                    }
                },
            )

        return resultado

    if (
        isinstance(
            resultado,
            tuple,
        )
        and len(resultado) >= 2
    ):
        ok = bool(
            resultado[0]
        )

        mensagem = str(
            resultado[1]
        )

        if not ok:
            raise ErroOperacao(
                mensagem
            )

        return {
            "ok": True,
            "mensagem": mensagem,
        }

    if isinstance(
        resultado,
        bool,
    ):
        if not resultado:
            raise ErroOperacao(
                "Operação retornou falha."
            )

        return {
            "ok": True,
        }

    if isinstance(
        resultado,
        str,
    ):
        return {
            "mensagem": resultado,
        }

    return {
        "resultado": resultado,
    }


# =============================================================================
# PREPARAÇÃO / PERMISSÕES
# =============================================================================

def _preparar_socket_path(
    socket_path: str,
) -> None:
    path = Path(
        socket_path
    )

    diretorio = path.parent

    diretorio.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        os.chmod(
            diretorio,
            DIRETORIO_MODE,
        )
    except PermissionError:
        pass

    if path.exists() or path.is_socket():
        modo = os.lstat(
            path
        ).st_mode

        if not stat.S_ISSOCK(
            modo
        ):
            raise RuntimeError(
                (
                    f"Recusando remover '{socket_path}': "
                    "o caminho existe mas não é "
                    "um Unix socket."
                )
            )

        path.unlink()


def _configurar_permissoes_socket(
    socket_path: str,
    grupo: str,
) -> None:
    path = Path(
        socket_path
    )

    os.chmod(
        path,
        SOCKET_MODE,
    )

    try:
        gid = grp.getgrnam(
            grupo
        ).gr_gid

    except KeyError as exc:
        raise RuntimeError(
            (
                f"Grupo Linux '{grupo}' não existe. "
                "Crie-o antes de iniciar "
                "o MoonShield-Agent."
            )
        ) from exc

    uid = (
        0
        if os.geteuid() == 0
        else os.geteuid()
    )

    os.chown(
        path,
        uid,
        gid,
    )


def _remover_socket_se_existir(
    socket_path: str,
) -> None:
    try:
        path = Path(
            socket_path
        )

        if (
            not path.exists()
            and not path.is_socket()
        ):
            return

        modo = os.lstat(
            path
        ).st_mode

        if stat.S_ISSOCK(
            modo
        ):
            path.unlink()

    except FileNotFoundError:
        pass

    except Exception:
        logger.exception(
            "[ipc] não foi possível remover socket %s",
            socket_path,
        )


def _finalizar_servidor(
    socket_path: str,
) -> None:
    global _servidor_ref, _thread_ref

    _remover_socket_se_existir(
        socket_path
    )

    with _estado_lock:
        _estado["rodando"] = False

    _servidor_ref = None
    _thread_ref = None

    logger.info(
        "[ipc] servidor encerrado"
    )


# =============================================================================
# UTILITÁRIOS
# =============================================================================

def _uptime_segundos() -> int:
    with _estado_lock:
        inicio = _estado.get(
            "iniciado_em"
        )

    if not inicio:
        return 0

    return max(
        0,
        int(
            time.time()
            - float(inicio)
        ),
    )


def _bool(
    valor: Any,
) -> bool:
    if isinstance(
        valor,
        bool,
    ):
        return valor

    if valor is None:
        return False

    return str(
        valor
    ).strip().lower() in {
        "1",
        "true",
        "sim",
        "yes",
        "on",
        "ativo",
    }


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | %(levelname)s | "
            "%(name)s | %(message)s"
        ),
    )

    iniciar_servidor(
        bloquear=True
    )