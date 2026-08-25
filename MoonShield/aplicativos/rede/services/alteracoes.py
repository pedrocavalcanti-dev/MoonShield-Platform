"""
MoonShield Network
==================

Orquestrador de alterações de Rede.

Este é o ponto central do Control Plane para operações que podem
alterar conectividade do appliance.

Fluxo seguro:

    PostgreSQL
        ↓
    cria AlteracaoRede
        ↓
    valida configuração desejada
        ↓
    solicita aplicação segura ao Agent
        ↓
    Agent cria snapshot
        ↓
    Agent ARMA rollback automático
        ↓
    Agent aplica alteração
        ↓
    Django registra:
        AGUARDANDO_CONFIRMACAO
        ↓
    usuário confirma
        ↓
    Agent cancela rollback
        ↓
    CONFIRMADA

Se não houver confirmação:

    Agent executa rollback automaticamente.

IMPORTANTE
----------

O Django mantém `expira_em` para interface/auditoria.

Porém o mecanismo real de proteção NÃO pode depender:

- do navegador;
- de JavaScript;
- do processo web Django;
- de uma requisição futura.

O MoonShield-Agent será responsável pelo timer real de rollback.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from rede.dominio.erros import (
    AgentOperacaoRecusadaErro,
    AlteracaoEstadoInvalidoErro,
    AlteracaoExpiradaErro,
    AlteracaoNaoEncontradaErro,
    AlteracaoRedeErro,
    AplicacaoRedeErro,
    ConfiguracaoRedeInvalidaErro,
    RollbackRedeErro,
    SnapshotRedeErro,
)
from rede.dominio.tipos import NivelEventoRede, TipoAlteracaoRede
from rede.models import (
    AlteracaoRede,
    ConfiguracaoRoteamento,
    EventoRede,
    InterfaceRede,
    SnapshotRede,
)
from rede.services.agent_client import requisitar_agent
from rede.services.interfaces import montar_payload_interface, montar_payload_interfaces, obter_interface_por_id
from rede.services.nat import montar_payload_nat
from rede.services.roteamento import montar_payload_roteamento


STATUS_EM_ANDAMENTO = set(AlteracaoRede.statuses_em_andamento())

STATUS_QUE_PERMITEM_APLICACAO = {
    AlteracaoRede.Status.CRIADA,
}

STATUS_QUE_PERMITEM_CONFIRMACAO = {
    AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
}

STATUS_QUE_PERMITEM_ROLLBACK = {
    AlteracaoRede.Status.APLICANDO,
    AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
}


# =============================================================================
# SERIALIZAÇÃO
# =============================================================================

def serializar_alteracao(alteracao: AlteracaoRede) -> dict:
    """Serialização completa para API/frontend."""
    return {
        "id": str(alteracao.id),
        "tipo": alteracao.tipo,
        "tipo_label": alteracao.get_tipo_display(),
        "status": alteracao.status,
        "status_label": alteracao.get_status_display(),
        "titulo": alteracao.titulo,
        "descricao": alteracao.descricao,
        "configuracao_solicitada": alteracao.configuracao_solicitada,
        "resultado_agent": alteracao.resultado_agent,
        "snapshot_anterior": str(alteracao.snapshot_anterior_id) if alteracao.snapshot_anterior_id else None,
        "snapshot_posterior": str(alteracao.snapshot_posterior_id) if alteracao.snapshot_posterior_id else None,
        "requer_confirmacao": alteracao.requer_confirmacao,
        "expira_em": _iso(alteracao.expira_em),
        "segundos_restantes": _segundos_restantes(alteracao),
        "iniciada_em": _iso(alteracao.iniciada_em),
        "aplicada_em": _iso(alteracao.aplicada_em),
        "confirmada_em": _iso(alteracao.confirmada_em),
        "rollback_em": _iso(alteracao.rollback_em),
        "finalizada_em": _iso(alteracao.finalizada_em),
        "erro": alteracao.erro,
        "log": alteracao.log,
        "expirou": alteracao.expirou,
        "finalizada": alteracao.finalizada,
        "em_andamento": alteracao.em_andamento,
        "pode_confirmar": alteracao.pode_confirmar,
        "pode_rollback": alteracao.pode_rollback,
        "solicitado_por": alteracao.solicitado_por.username if alteracao.solicitado_por else None,
        "confirmado_por": alteracao.confirmado_por.username if alteracao.confirmado_por else None,
        "criado_em": _iso(alteracao.criado_em),
        "atualizado_em": _iso(alteracao.atualizado_em),
    }


def serializar_snapshot(snapshot: SnapshotRede) -> dict:
    return {
        "id": str(snapshot.id),
        "origem": snapshot.origem,
        "backend": snapshot.backend,
        "automatico": snapshot.automatico,
        "valido": snapshot.valido,
        "observacao": snapshot.observacao,
        "dados": snapshot.dados,
        "criado_em": _iso(snapshot.criado_em),
    }


# =============================================================================
# CONSULTAS
# =============================================================================

def obter_alteracao(alteracao_id: str | UUID, *, bloquear: bool = False) -> AlteracaoRede:
    """Obtém alteração pelo UUID."""
    queryset = AlteracaoRede.objects.select_related(
        "snapshot_anterior",
        "snapshot_posterior",
        "solicitado_por",
        "confirmado_por",
    )

    if bloquear:
        queryset = queryset.select_for_update(of=("self",))

    try:
        return queryset.get(pk=alteracao_id)
    except (AlteracaoRede.DoesNotExist, ValueError) as exc:
        raise AlteracaoNaoEncontradaErro(
            f"Alteração de rede '{alteracao_id}' não encontrada."
        ) from exc


def obter_alteracao_ativa(
    *,
    excluir_id: str | UUID | None = None,
    bloquear: bool = False,
) -> AlteracaoRede | None:
    """
    Retorna a alteração que atualmente reserva o pipeline de Rede.

    O queryset pode ser bloqueado quando chamado dentro de transaction.atomic().
    """
    queryset = (
        AlteracaoRede.objects
        .select_related("solicitado_por")
        .filter(status__in=STATUS_EM_ANDAMENTO)
        .order_by("criado_em")
    )

    if excluir_id is not None:
        queryset = queryset.exclude(pk=excluir_id)

    if bloquear:
        queryset = queryset.select_for_update(of=("self",))

    return queryset.first()


def listar_alteracoes_ativas() -> list[AlteracaoRede]:
    """Lista operações que ainda reservam o pipeline de Rede."""
    return list(
        AlteracaoRede.objects
        .select_related("solicitado_por")
        .filter(status__in=STATUS_EM_ANDAMENTO)
        .order_by("criado_em")
    )


def _bloquear_orquestracao_global() -> ConfiguracaoRoteamento:
    """
    Serializa a criação de alterações usando o registro singleton de roteamento.

    Como todas as criações passam por esta linha bloqueada no PostgreSQL,
    dois requests simultâneos não conseguem criar duas operações ativas.
    """
    config = ConfiguracaoRoteamento.atual()

    return (
        ConfiguracaoRoteamento.objects
        .select_for_update()
        .get(pk=config.pk)
    )


def _erro_operacao_em_andamento(alteracao: AlteracaoRede) -> AlteracaoEstadoInvalidoErro:
    return AlteracaoEstadoInvalidoErro(
        "Existe uma alteração de Rede aguardando conclusão.",
        detalhes={
            "alteracao_id": str(alteracao.id),
            "status": alteracao.status,
            "status_label": alteracao.get_status_display(),
            "titulo": alteracao.titulo,
        },
    )


def listar_alteracoes(
    *,
    status: str | None = None,
    tipo: str | None = None,
    limite: int = 100,
) -> list[dict]:
    """Lista histórico recente."""
    try:
        limite = int(limite)
    except (TypeError, ValueError):
        limite = 100

    limite = max(1, min(limite, 500))

    queryset = AlteracaoRede.objects.select_related(
        "solicitado_por",
        "confirmado_por",
        "snapshot_anterior",
        "snapshot_posterior",
    ).all()

    if status:
        queryset = queryset.filter(status=status)

    if tipo:
        queryset = queryset.filter(tipo=tipo)

    return [serializar_alteracao(alteracao) for alteracao in queryset[:limite]]


# =============================================================================
# EVENTOS
# =============================================================================

def registrar_evento(
    *,
    nivel: str,
    codigo: str,
    titulo: str,
    mensagem: str = "",
    dados: dict | None = None,
    interface: InterfaceRede | None = None,
    alteracao: AlteracaoRede | None = None,
    usuario=None,
) -> EventoRede:
    """Registra evento operacional."""
    return EventoRede.objects.create(
        nivel=nivel,
        codigo=codigo,
        titulo=titulo,
        mensagem=mensagem,
        dados=dados or {},
        interface=interface,
        alteracao=alteracao,
        usuario=usuario,
    )


# =============================================================================
# CRIAÇÃO GENÉRICA
# =============================================================================

def criar_alteracao(
    *,
    tipo: str,
    configuracao_solicitada: dict,
    titulo: str = "",
    descricao: str = "",
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    """
    Cria alteração no PostgreSQL sem chamar o Agent.

    Antes da criação:
    - reconcilia operações expiradas;
    - adquire lock global no PostgreSQL;
    - garante que não exista outra operação ativa.

    O lock é mantido somente durante a criação do registro. O Agent continua
    sendo a autoridade do Safe Apply e do rollback real.
    """
    tipos_validos = {escolha[0] for escolha in AlteracaoRede.Tipo.choices}

    if tipo not in tipos_validos:
        raise ConfiguracaoRedeInvalidaErro(
            f"Tipo de alteração de rede inválido: '{tipo}'."
        )

    if not isinstance(configuracao_solicitada, dict):
        raise ConfiguracaoRedeInvalidaErro(
            "configuracao_solicitada deve ser um objeto."
        )

    # Limpa estados vencidos que o Agent já concluiu antes de reservar
    # uma nova operação. Falhas de consulta são preservadas como estado ativo.
    reconciliar_alteracoes_expiradas()

    with transaction.atomic():
        _bloquear_orquestracao_global()

        ativa = obter_alteracao_ativa(bloquear=True)

        if ativa is not None:
            raise _erro_operacao_em_andamento(ativa)

        alteracao = AlteracaoRede.objects.create(
            tipo=tipo,
            status=AlteracaoRede.Status.CRIADA,
            titulo=str(titulo or "").strip(),
            descricao=str(descricao or "").strip(),
            configuracao_solicitada=configuracao_solicitada,
            requer_confirmacao=bool(requer_confirmacao),
            solicitado_por=usuario,
        )

        alteracao.adicionar_log("Alteração criada.")
        alteracao.save(update_fields=["log", "atualizado_em"])

        registrar_evento(
            nivel=NivelEventoRede.INFO.value,
            codigo="network_change_created",
            titulo="Alteração de rede criada",
            mensagem=alteracao.titulo or alteracao.get_tipo_display(),
            dados={
                "alteracao_id": str(alteracao.id),
                "tipo": alteracao.tipo,
            },
            alteracao=alteracao,
            usuario=usuario,
        )

    return alteracao


# =============================================================================
# CRIAÇÃO — INTERFACE
# =============================================================================

def criar_alteracao_interface(
    interface_id: int,
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    """Cria alteração para uma interface já salva como estado desejado."""
    interface = obter_interface_por_id(interface_id)
    payload = montar_payload_interface(interface)

    return criar_alteracao(
        tipo=TipoAlteracaoRede.INTERFACE.value,
        titulo=f"Configurar interface {interface.nome}",
        descricao="Aplicação da configuração desejada da interface.",
        configuracao_solicitada={"interface": payload},
        usuario=usuario,
        requer_confirmacao=requer_confirmacao,
    )


# =============================================================================
# CRIAÇÃO — ROTEAMENTO
# =============================================================================

def criar_alteracao_roteamento(
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    payload = montar_payload_roteamento()

    return criar_alteracao(
        tipo=TipoAlteracaoRede.ROTEAMENTO.value,
        titulo="Aplicar roteamento",
        descricao="Aplicação de IPv4 Forward e rotas estáticas.",
        configuracao_solicitada=payload,
        usuario=usuario,
        requer_confirmacao=requer_confirmacao,
    )


# =============================================================================
# CRIAÇÃO — NAT
# =============================================================================

def criar_alteracao_nat(
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    payload = montar_payload_nat(somente_ativas=False)

    return criar_alteracao(
        tipo=TipoAlteracaoRede.NAT.value,
        titulo="Aplicar configuração NAT",
        descricao="Aplicação das regras NAT administradas pelo MoonShield.",
        configuracao_solicitada=payload,
        usuario=usuario,
        requer_confirmacao=requer_confirmacao,
    )


# =============================================================================
# CRIAÇÃO — CONFIGURAÇÃO COMPLETA
# =============================================================================

def criar_alteracao_geral(
    *,
    usuario=None,
    requer_confirmacao: bool = True,
) -> AlteracaoRede:
    """Cria alteração contendo todo o estado desejado da Rede."""
    payload = {
        "interfaces": montar_payload_interfaces().get("interfaces", []),
        "roteamento": montar_payload_roteamento(),
        "nat": montar_payload_nat(somente_ativas=False),
    }

    return criar_alteracao(
        tipo=TipoAlteracaoRede.GERAL.value,
        titulo="Aplicar configuração completa da rede",
        descricao="Aplicação completa do estado desejado de interfaces, roteamento e NAT.",
        configuracao_solicitada=payload,
        usuario=usuario,
        requer_confirmacao=requer_confirmacao,
    )


# =============================================================================
# SNAPSHOT
# =============================================================================

def _criar_snapshot_de_resposta(
    dados: Any,
    *,
    usuario=None,
    observacao: str = "",
) -> SnapshotRede | None:
    """Persiste snapshot devolvido pelo Agent."""
    if not dados:
        return None

    if not isinstance(dados, dict):
        raise SnapshotRedeErro(
            "Snapshot devolvido pelo Agent possui formato inválido."
        )

    backend = str(dados.get("backend", "") or "")
    conteudo = dados.get("dados")

    if conteudo is None:
        conteudo = dados

    if not isinstance(conteudo, dict):
        raise SnapshotRedeErro(
            "Dados internos do snapshot possuem formato inválido."
        )

    return SnapshotRede.objects.create(
        origem="moonshield-agent",
        backend=backend,
        dados=conteudo,
        automatico=True,
        valido=True,
        observacao=observacao,
        criado_por=usuario,
    )


# =============================================================================
# PAYLOAD AGENT
# =============================================================================

def _montar_payload_agent(alteracao: AlteracaoRede) -> dict:
    """Monta contrato oficial para aplicação segura."""
    config = ConfiguracaoRoteamento.atual()
    timeout = config.tempo_confirmacao

    if not alteracao.requer_confirmacao:
        timeout = 0

    return {
        "change_id": str(alteracao.id),
        "type": alteracao.tipo,
        "safe_apply": True,
        "confirmation_required": alteracao.requer_confirmacao,
        "confirmation_timeout": timeout,
        "desired": alteracao.configuracao_solicitada,
    }


# =============================================================================
# APLICAÇÃO
# =============================================================================

def aplicar_alteracao(alteracao_id: str | UUID) -> AlteracaoRede:
    """
    Solicita aplicação segura ao Agent.

    A reserva do pipeline é validada novamente antes do IPC. Não mantemos
    transação PostgreSQL aberta enquanto o Agent executa a alteração.
    """
    with transaction.atomic():
        _bloquear_orquestracao_global()

        alteracao = obter_alteracao(alteracao_id, bloquear=True)

        if alteracao.status not in STATUS_QUE_PERMITEM_APLICACAO:
            raise AlteracaoEstadoInvalidoErro(
                f"Alteração não pode ser aplicada no estado '{alteracao.status}'."
            )

        concorrente = obter_alteracao_ativa(
            excluir_id=alteracao.id,
            bloquear=True,
        )

        if concorrente is not None:
            raise _erro_operacao_em_andamento(concorrente)

        alteracao.marcar_validando()
        alteracao.adicionar_log("Iniciando validação e aplicação segura.")
        alteracao.save(
            update_fields=[
                "status",
                "iniciada_em",
                "finalizada_em",
                "erro",
                "log",
                "atualizado_em",
            ]
        )

    payload = _montar_payload_agent(alteracao)

    with transaction.atomic():
        alteracao = obter_alteracao(alteracao_id, bloquear=True)

        if alteracao.status != AlteracaoRede.Status.VALIDANDO:
            raise AlteracaoEstadoInvalidoErro(
                "Estado da alteração mudou antes do envio ao Agent."
            )

        alteracao.marcar_aplicando()
        alteracao.adicionar_log("Solicitação enviada para MoonShield-Agent.")
        alteracao.save(
            update_fields=[
                "status",
                "iniciada_em",
                "finalizada_em",
                "log",
                "atualizado_em",
            ]
        )

    try:
        resultado = requisitar_agent(
            "network.change.apply",
            payload,
        )
    except AgentOperacaoRecusadaErro as exc:
        # Uma recusa explícita do Agent é um resultado conhecido. Se for
        # conflito por operação ativa, não classificamos como falha técnica.
        if getattr(exc, "codigo", "") == "alteracao_rede_em_andamento":
            _registrar_cancelamento_por_conflito(alteracao_id, exc)
        else:
            _registrar_falha_aplicacao(alteracao_id, exc)
        raise
    except Exception as exc:
        _registrar_falha_aplicacao(alteracao_id, exc)

        if isinstance(exc, AlteracaoRedeErro):
            raise

        raise AplicacaoRedeErro(
            "Falha ao solicitar aplicação da configuração de rede.",
            detalhes={"erro": str(exc)},
        ) from exc

    if not isinstance(resultado, dict):
        erro = AplicacaoRedeErro(
            "MoonShield-Agent retornou resposta inválida para a aplicação.",
            detalhes={"tipo_resposta": type(resultado).__name__},
        )
        _registrar_falha_aplicacao(alteracao_id, erro)
        raise erro

    # Primeiro persistimos o resultado operacional e o estado do Safe Apply.
    # Assim, mesmo que a persistência dos snapshots de auditoria falhe depois,
    # o Django continua sabendo qual operação está ativa e como confirmá-la.
    with transaction.atomic():
        alteracao = obter_alteracao(alteracao_id, bloquear=True)
        alteracao.resultado_agent = resultado
        alteracao.marcar_aplicada(
            expira_em=_resolver_expiracao(resultado, alteracao)
        )
        alteracao.adicionar_log(
            "Configuração aplicada. Aguardando confirmação."
            if alteracao.requer_confirmacao
            else "Configuração aplicada sem confirmação pendente."
        )
        alteracao.save(
            update_fields=[
                "resultado_agent",
                "aplicada_em",
                "status",
                "expira_em",
                "confirmada_em",
                "finalizada_em",
                "erro",
                "log",
                "atualizado_em",
            ]
        )

    snapshot_anterior = None
    snapshot_posterior = None

    try:
        snapshot_anterior = _criar_snapshot_de_resposta(
            resultado.get("snapshot_before"),
            usuario=alteracao.solicitado_por,
            observacao=f"Estado anterior à alteração {alteracao.id}",
        )

        snapshot_posterior = _criar_snapshot_de_resposta(
            resultado.get("snapshot_after"),
            usuario=alteracao.solicitado_por,
            observacao=f"Estado após aplicação {alteracao.id}",
        )
    except Exception as exc:
        # O snapshot operacional do Agent continua sendo a base do rollback.
        # Falha na cópia de auditoria do Django não pode apagar um Safe Apply
        # que já está armado e ativo.
        _registrar_aviso_snapshot(alteracao_id, exc)
    else:
        with transaction.atomic():
            alteracao = obter_alteracao(alteracao_id, bloquear=True)
            alteracao.snapshot_anterior = snapshot_anterior
            alteracao.snapshot_posterior = snapshot_posterior
            alteracao.save(
                update_fields=[
                    "snapshot_anterior",
                    "snapshot_posterior",
                    "atualizado_em",
                ]
            )

    alteracao = obter_alteracao(alteracao_id)

    registrar_evento(
        nivel=NivelEventoRede.SUCCESS.value,
        codigo="network_change_applied",
        titulo="Configuração de rede aplicada",
        mensagem=(
            "Aguardando confirmação."
            if alteracao.requer_confirmacao
            else "Aplicação concluída."
        ),
        dados={
            "alteracao_id": str(alteracao.id),
            "expira_em": _iso(alteracao.expira_em),
        },
        alteracao=alteracao,
        usuario=alteracao.solicitado_por,
    )

    return alteracao


# =============================================================================
# CONFIRMAÇÃO
# =============================================================================

def confirmar_alteracao(
    alteracao_id: str | UUID,
    *,
    usuario=None,
) -> AlteracaoRede:
    """
    Confirma que o administrador manteve acesso.

    A operação é idempotente quando já está confirmada. Se o prazo local
    expirou, consultamos o Agent antes de devolver erro para não manter o
    PostgreSQL preso em um estado antigo.
    """
    alteracao = obter_alteracao(alteracao_id)

    if alteracao.status == AlteracaoRede.Status.CONFIRMADA:
        return alteracao

    if alteracao.status == AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO and alteracao.expirou:
        alteracao = reconciliar_alteracao(alteracao_id)

        if alteracao.status == AlteracaoRede.Status.CONFIRMADA:
            return alteracao

        if alteracao.status != AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO:
            raise AlteracaoExpiradaErro(
                "O prazo de confirmação expirou e o Agent já concluiu a operação.",
                detalhes={
                    "alteracao_id": str(alteracao.id),
                    "status": alteracao.status,
                    "status_label": alteracao.get_status_display(),
                },
            )

    with transaction.atomic():
        alteracao = obter_alteracao(alteracao_id, bloquear=True)

        if alteracao.status == AlteracaoRede.Status.CONFIRMADA:
            return alteracao

        if alteracao.status not in STATUS_QUE_PERMITEM_CONFIRMACAO:
            raise AlteracaoEstadoInvalidoErro(
                "Alteração não está aguardando confirmação.",
                detalhes={
                    "alteracao_id": str(alteracao.id),
                    "status": alteracao.status,
                },
            )

        if alteracao.expirou:
            raise AlteracaoExpiradaErro(
                "O prazo de confirmação da alteração expirou.",
                detalhes={"alteracao_id": str(alteracao.id)},
            )

        payload = _payload_operacao_agent(alteracao)

    try:
        resultado = requisitar_agent(
            "network.change.confirm",
            payload,
        )
    except Exception as exc:
        # A resposta de confirmação pode ter se perdido depois de o Agent já
        # ter confirmado. Consultamos o estado real antes de declarar falha.
        try:
            reconciliada = reconciliar_alteracao(alteracao_id)
        except Exception:
            reconciliada = None

        if reconciliada and reconciliada.status == AlteracaoRede.Status.CONFIRMADA:
            return reconciliada

        raise AlteracaoRedeErro(
            "Não foi possível confirmar a alteração no Agent.",
            detalhes={"erro": str(exc)},
        ) from exc

    with transaction.atomic():
        alteracao = obter_alteracao(alteracao_id, bloquear=True)

        if alteracao.status == AlteracaoRede.Status.CONFIRMADA:
            return alteracao

        if alteracao.status != AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO:
            raise AlteracaoEstadoInvalidoErro(
                "Estado da alteração mudou durante a confirmação.",
                detalhes={
                    "alteracao_id": str(alteracao.id),
                    "status": alteracao.status,
                },
            )

        alteracao.marcar_confirmada(usuario=usuario)
        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "confirmation": resultado,
        }
        alteracao.adicionar_log(
            "Alteração confirmada. Rollback automático cancelado."
        )
        alteracao.save(
            update_fields=[
                "status",
                "confirmada_em",
                "finalizada_em",
                "confirmado_por",
                "expira_em",
                "erro",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=NivelEventoRede.SUCCESS.value,
        codigo="network_change_confirmed",
        titulo="Alteração de rede confirmada",
        mensagem=alteracao.titulo or "Alteração confirmada",
        alteracao=alteracao,
        usuario=usuario,
    )

    return alteracao


# =============================================================================
# ROLLBACK
# =============================================================================

def executar_rollback(
    alteracao_id: str | UUID,
    *,
    usuario=None,
    motivo: str = "Rollback solicitado.",
) -> AlteracaoRede:
    """
    Solicita restauração do snapshot anterior.

    Se a alteração já foi revertida, devolve o estado atual sem repetir a
    operação. Se estiver marcada como rollback, consulta o Agent primeiro.
    """
    alteracao = obter_alteracao(alteracao_id)

    if alteracao.status == AlteracaoRede.Status.REVERTIDA:
        return alteracao

    if alteracao.status == AlteracaoRede.Status.ROLLBACK:
        reconciliada = reconciliar_alteracao(alteracao_id)

        if reconciliada.status == AlteracaoRede.Status.REVERTIDA:
            return reconciliada

    with transaction.atomic():
        alteracao = obter_alteracao(alteracao_id, bloquear=True)

        if alteracao.status == AlteracaoRede.Status.REVERTIDA:
            return alteracao

        if alteracao.status not in STATUS_QUE_PERMITEM_ROLLBACK:
            raise AlteracaoEstadoInvalidoErro(
                f"Rollback não permitido no estado '{alteracao.status}'.",
                detalhes={
                    "alteracao_id": str(alteracao.id),
                    "status": alteracao.status,
                },
            )

        alteracao.marcar_rollback()
        alteracao.adicionar_log(motivo)
        alteracao.save(
            update_fields=[
                "status",
                "rollback_em",
                "finalizada_em",
                "log",
                "atualizado_em",
            ]
        )

        payload = _payload_operacao_agent(alteracao)
        payload["reason"] = motivo

    try:
        resultado = requisitar_agent(
            "network.change.rollback",
            payload,
        )
    except Exception as exc:
        # Antes de marcar falha, confirmamos se o Agent não concluiu o rollback
        # e apenas a resposta se perdeu.
        try:
            reconciliada = reconciliar_alteracao(alteracao_id)
        except Exception:
            reconciliada = None

        if reconciliada and reconciliada.status == AlteracaoRede.Status.REVERTIDA:
            return reconciliada

        with transaction.atomic():
            alteracao = obter_alteracao(alteracao_id, bloquear=True)
            alteracao.marcar_falha(f"Rollback falhou: {exc}")
            alteracao.save(
                update_fields=[
                    "status",
                    "erro",
                    "finalizada_em",
                    "expira_em",
                    "log",
                    "atualizado_em",
                ]
            )

        registrar_evento(
            nivel=NivelEventoRede.ERROR.value,
            codigo="network_rollback_failed",
            titulo="Rollback de rede falhou",
            mensagem=str(exc),
            alteracao=alteracao,
            usuario=usuario,
        )

        raise RollbackRedeErro(
            "MoonShield-Agent não conseguiu confirmar o rollback.",
            detalhes={"erro": str(exc)},
        ) from exc

    snapshot_posterior = None

    if isinstance(resultado, dict) and resultado.get("snapshot_after"):
        try:
            snapshot_posterior = _criar_snapshot_de_resposta(
                resultado.get("snapshot_after"),
                usuario=usuario,
                observacao=f"Estado após rollback {alteracao.id}",
            )
        except Exception as exc:
            _registrar_aviso_snapshot(alteracao_id, exc)

    with transaction.atomic():
        alteracao = obter_alteracao(alteracao_id, bloquear=True)
        alteracao.marcar_revertida()

        if snapshot_posterior:
            alteracao.snapshot_posterior = snapshot_posterior

        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "rollback": resultado if isinstance(resultado, dict) else {},
        }
        alteracao.adicionar_log("Rollback concluído.")
        alteracao.save(
            update_fields=[
                "status",
                "rollback_em",
                "finalizada_em",
                "expira_em",
                "erro",
                "snapshot_posterior",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=NivelEventoRede.WARNING.value,
        codigo="network_change_reverted",
        titulo="Alteração de rede revertida",
        mensagem=motivo,
        alteracao=alteracao,
        usuario=usuario,
    )

    return alteracao


# =============================================================================
# ALTERAÇÕES EXPIRADAS
# =============================================================================

def listar_alteracoes_expiradas():
    """Alterações vencidas segundo o PostgreSQL."""
    agora = timezone.now()

    return (
        AlteracaoRede.objects
        .filter(
            status=AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO,
            expira_em__isnull=False,
            expira_em__lte=agora,
        )
        .order_by("expira_em")
    )


def reconciliar_alteracao(alteracao_id: str | UUID) -> AlteracaoRede:
    """
    Consulta o Agent e sincroniza um estado operacional conhecido.

    Nenhum rollback é disparado aqui. O Agent continua sendo a autoridade
    sobre timeout e recuperação de conectividade.
    """
    alteracao = obter_alteracao(alteracao_id)

    if alteracao.finalizada:
        return alteracao

    # Alteração apenas criada ainda não foi enviada ao Agent.
    if alteracao.status == AlteracaoRede.Status.CRIADA:
        return alteracao

    resultado = requisitar_agent(
        "network.change.status",
        _payload_operacao_agent(alteracao),
    )

    if not isinstance(resultado, dict):
        return alteracao

    estado_agent = _normalizar_estado_agent(resultado)

    if estado_agent in {"reverted", "rolled_back"}:
        _marcar_revertida_por_agent(alteracao.id, resultado)

    elif estado_agent in {"confirmed", "committed"}:
        _marcar_confirmada_por_agent(alteracao.id, resultado)

    elif estado_agent in {"failed", "error"}:
        _marcar_falha_por_agent(alteracao.id, resultado)

    elif estado_agent in {"rollback", "rolling_back"}:
        _marcar_rollback_por_agent(alteracao.id, resultado)

    elif estado_agent in {"waiting_confirmation", "waiting", "armed"}:
        _atualizar_estado_aguardando_por_agent(alteracao.id, resultado)

    return obter_alteracao(alteracao.id)


def reconciliar_alteracoes_expiradas() -> int:
    """
    Reconcilia alterações cujo prazo local terminou.

    Não dispara rollback cegamente. Pergunta ao Agent qual foi o resultado
    real da operação e só então atualiza o PostgreSQL.
    """
    alteracoes = list(listar_alteracoes_expiradas())
    processadas = 0

    for alteracao in alteracoes:
        status_anterior = alteracao.status

        try:
            atualizada = reconciliar_alteracao(alteracao.id)
        except Exception:
            # Se não conseguimos falar com a autoridade real, mantemos o lock.
            continue

        if atualizada.status != status_anterior:
            processadas += 1

    return processadas


def reconciliar_alteracoes_ativas() -> int:
    """
    Reconcilia operações já enviadas ao Agent.

    Útil para atualização do painel, recuperação após reinício do Django e
    saneamento de estados antigos. Alterações em CRIADA não são consultadas.
    """
    alteracoes = listar_alteracoes_ativas()
    processadas = 0

    for alteracao in alteracoes:
        if alteracao.status == AlteracaoRede.Status.CRIADA:
            continue

        status_anterior = alteracao.status

        try:
            atualizada = reconciliar_alteracao(alteracao.id)
        except Exception:
            continue

        if atualizada.status != status_anterior:
            processadas += 1

    return processadas


# =============================================================================
# CANCELAMENTO
# =============================================================================

@transaction.atomic
def cancelar_alteracao(
    alteracao_id: str | UUID,
    *,
    usuario=None,
) -> AlteracaoRede:
    """Cancela somente uma alteração ainda não enviada ao Agent."""
    alteracao = obter_alteracao(
        alteracao_id,
        bloquear=True,
    )

    if alteracao.status == AlteracaoRede.Status.CANCELADA:
        return alteracao

    if alteracao.status != AlteracaoRede.Status.CRIADA:
        raise AlteracaoEstadoInvalidoErro(
            "Somente alterações ainda não aplicadas podem ser canceladas.",
            detalhes={
                "alteracao_id": str(alteracao.id),
                "status": alteracao.status,
            },
        )

    alteracao.status = AlteracaoRede.Status.CANCELADA
    alteracao.finalizada_em = timezone.now()
    alteracao.expira_em = None
    alteracao.adicionar_log("Alteração cancelada.")
    alteracao.save(
        update_fields=[
            "status",
            "finalizada_em",
            "expira_em",
            "log",
            "atualizado_em",
        ]
    )

    registrar_evento(
        nivel=NivelEventoRede.WARNING.value,
        codigo="network_change_cancelled",
        titulo="Alteração de rede cancelada",
        alteracao=alteracao,
        usuario=usuario,
    )

    return alteracao


# =============================================================================
# STATUS AGENT
# =============================================================================

def consultar_status_agent(
    alteracao_id: str | UUID,
) -> dict:
    """Consulta operação correspondente no Agent."""
    alteracao = obter_alteracao(alteracao_id)

    return requisitar_agent(
        "network.change.status",
        _payload_operacao_agent(alteracao),
    )


# =============================================================================
# HELPERS — OPERAÇÃO AGENT
# =============================================================================

def _payload_operacao_agent(
    alteracao: AlteracaoRede,
) -> dict:
    """Extrai identificadores retornados pelo Agent."""
    resultado = alteracao.resultado_agent or {}

    return {
        "change_id": str(alteracao.id),
        "operation_id": resultado.get("operation_id"),
        "confirmation_token": resultado.get("confirmation_token"),
    }


# =============================================================================
# EXPIRAÇÃO
# =============================================================================

def _resolver_expiracao(
    resultado: dict,
    alteracao: AlteracaoRede,
) -> datetime | None:
    """Prefere a expiração informada pelo Agent."""
    if not alteracao.requer_confirmacao:
        return None

    agent_expira = resultado.get("expires_at")

    if agent_expira:
        parsed = _datetime(agent_expira)

        if parsed:
            return parsed

    config = ConfiguracaoRoteamento.atual()

    return timezone.now() + timedelta(
        seconds=config.tempo_confirmacao
    )


# =============================================================================
# FALHA NA APLICAÇÃO
# =============================================================================

def _registrar_falha_aplicacao(
    alteracao_id,
    exc: Exception,
) -> None:
    """Persiste erro real ocorrido antes da conclusão da aplicação."""
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )
        alteracao.marcar_falha(str(exc))
        alteracao.save(
            update_fields=[
                "status",
                "erro",
                "finalizada_em",
                "expira_em",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=NivelEventoRede.ERROR.value,
        codigo="network_change_failed",
        titulo="Falha na alteração de rede",
        mensagem=str(exc),
        alteracao=alteracao,
        usuario=alteracao.solicitado_por,
    )


def _registrar_cancelamento_por_conflito(
    alteracao_id,
    exc: Exception,
) -> None:
    """
    Marca como cancelada uma operação que o Agent recusou porque outra já
    estava ativa. Não classifica clique concorrente como falha técnica.
    """
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )
        alteracao.status = AlteracaoRede.Status.CANCELADA
        alteracao.finalizada_em = timezone.now()
        alteracao.expira_em = None
        alteracao.erro = ""
        alteracao.adicionar_log(
            f"Aplicação cancelada por conflito operacional: {exc}"
        )
        alteracao.save(
            update_fields=[
                "status",
                "finalizada_em",
                "expira_em",
                "erro",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=NivelEventoRede.WARNING.value,
        codigo="network_change_conflict",
        titulo="Alteração de rede bloqueada",
        mensagem=str(exc),
        alteracao=alteracao,
        usuario=alteracao.solicitado_por,
    )


def _registrar_aviso_snapshot(
    alteracao_id,
    exc: Exception,
) -> None:
    """
    Registra falha da cópia de auditoria do snapshot sem encerrar o Safe Apply.

    O snapshot e o timer reais continuam sob responsabilidade do Agent.
    """
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )
        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "snapshot_persistence_warning": str(exc),
        }
        alteracao.adicionar_log(
            f"Aviso: não foi possível persistir snapshot de auditoria: {exc}"
        )
        alteracao.save(
            update_fields=[
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=NivelEventoRede.WARNING.value,
        codigo="network_snapshot_persistence_warning",
        titulo="Snapshot de auditoria não persistido",
        mensagem=str(exc),
        alteracao=alteracao,
        usuario=alteracao.solicitado_por,
    )


# =============================================================================
# RECONCILIAÇÃO — AGENT REVERTEU
# =============================================================================

def _marcar_revertida_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if alteracao.status == AlteracaoRede.Status.REVERTIDA:
            return

        alteracao.marcar_revertida()
        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "reconciliation": resultado,
        }
        alteracao.adicionar_log(
            "Agent informou que o rollback automático foi executado."
        )
        alteracao.save(
            update_fields=[
                "status",
                "rollback_em",
                "finalizada_em",
                "expira_em",
                "erro",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )

    registrar_evento(
        nivel=NivelEventoRede.WARNING.value,
        codigo="network_auto_rollback",
        titulo="Rollback automático executado",
        mensagem="A alteração não foi confirmada dentro do prazo.",
        alteracao=alteracao,
    )


def _marcar_confirmada_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if alteracao.status == AlteracaoRede.Status.CONFIRMADA:
            return

        alteracao.marcar_confirmada()
        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "reconciliation": resultado,
        }
        alteracao.adicionar_log(
            "Estado confirmado durante reconciliação com o Agent."
        )
        alteracao.save(
            update_fields=[
                "status",
                "confirmada_em",
                "finalizada_em",
                "expira_em",
                "erro",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )


def _marcar_falha_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        mensagem = str(
            resultado.get("error")
            or resultado.get("message")
            or "Agent informou falha na operação."
        )

        alteracao.marcar_falha(mensagem)
        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "reconciliation": resultado,
        }
        alteracao.adicionar_log(
            f"Falha detectada durante reconciliação: {mensagem}"
        )
        alteracao.save(
            update_fields=[
                "status",
                "erro",
                "finalizada_em",
                "expira_em",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )


def _marcar_rollback_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if alteracao.finalizada:
            return

        alteracao.marcar_rollback()
        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "reconciliation": resultado,
        }
        alteracao.adicionar_log(
            "Agent informou rollback em andamento."
        )
        alteracao.save(
            update_fields=[
                "status",
                "rollback_em",
                "finalizada_em",
                "resultado_agent",
                "log",
                "atualizado_em",
            ]
        )


def _atualizar_estado_aguardando_por_agent(
    alteracao_id,
    resultado: dict,
) -> None:
    with transaction.atomic():
        alteracao = obter_alteracao(
            alteracao_id,
            bloquear=True,
        )

        if alteracao.finalizada:
            return

        expira_em = _datetime(
            resultado.get("expires_at")
            or resultado.get("expira_em")
        )

        alteracao.status = AlteracaoRede.Status.AGUARDANDO_CONFIRMACAO

        if expira_em is not None:
            alteracao.expira_em = expira_em

        alteracao.resultado_agent = {
            **(alteracao.resultado_agent or {}),
            "reconciliation": resultado,
        }
        alteracao.save(
            update_fields=[
                "status",
                "expira_em",
                "resultado_agent",
                "atualizado_em",
            ]
        )


def _normalizar_estado_agent(resultado: dict) -> str:
    return str(
        resultado.get("state")
        or resultado.get("status")
        or ""
    ).strip().lower()


# =============================================================================
# HELPERS GERAIS
# =============================================================================

def _segundos_restantes(alteracao: AlteracaoRede) -> int | None:
    if not alteracao.expira_em:
        return None

    segundos = int(
        (alteracao.expira_em - timezone.now()).total_seconds()
    )

    return max(0, segundos)


def _iso(
    valor: datetime | None,
) -> str | None:
    if valor is None:
        return None

    return valor.isoformat()


def _datetime(
    valor: Any,
) -> datetime | None:
    """Aceita datetime ou ISO 8601."""
    if isinstance(valor, datetime):
        resultado = valor

    elif isinstance(valor, str):
        resultado = parse_datetime(valor)

        if resultado is None:
            return None

    else:
        return None

    if timezone.is_naive(resultado):
        resultado = timezone.make_aware(resultado)

    return resultado