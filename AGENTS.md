# MoonShield — AGENTS.md

## 1. Papel do Codex

Este arquivo contém regras obrigatórias para agentes de código trabalhando no MoonShield.

Fluxo:

Pedro
→ ChatGPT define/revisa arquitetura, prioridade e critérios
→ Codex analisa o workspace
→ Codex implementa
→ Codex testa
→ Codex revisa o diff
→ Pedro valida em Linux quando necessário
→ ChatGPT revisa
→ próximo lote

O Codex deve atuar como executor técnico.

Antes de editar:
- leia este arquivo;
- leia os arquivos relacionados;
- procure consumidores/produtores;
- entenda contratos existentes;
- verifique impacto.

Não reescreva o MoonShield do zero.
Prefira alterações incrementais, pequenas e testáveis.

Se uma instrução explícita recente do usuário conflitar com este arquivo, a instrução recente prevalece.

---

# 2. Produto

Foco atual:

MOONSHIELD APPLIANCE ISO

A antiga instalação Linux genérica foi salva separadamente.

Daqui em diante podemos alterar Django, Agent, banco, frontend e fluxos pensando somente na appliance.

Destino:

- Debian 13 amd64;
- instalação por ISO;
- systemd;
- PostgreSQL;
- NetworkManager;
- nftables;
- Suricata;
- AdGuard Home;
- MoonShield Agent;
- Django;
- Gunicorn;
- Nginx;
- console local.

A ISO final deve instalar os componentes principais sem depender da internet.

Internet será usada posteriormente para:
- updates;
- feeds;
- regras;
- integrações externas.

---

# 3. Arquitetura

Fluxo principal:

Browser
→ Nginx
→ Django
→ MoonShield Agent
→ Linux

Componentes Linux:

- NetworkManager;
- nftables;
- Suricata;
- AdGuard;
- systemd.

Responsabilidades:

Django:
- control plane;
- interface web;
- APIs;
- autenticação;
- regras de negócio;
- desired state;
- topologia;
- reconciliação;
- histórico;
- auditoria;
- PostgreSQL.

Agent:
- executor privilegiado;
- leitura do estado Linux;
- NetworkManager;
- nftables;
- rotas;
- NAT;
- snapshots;
- rollback;
- systemd;
- integrações privilegiadas.

PostgreSQL:
- desired state;
- histórico;
- auditoria;
- configurações persistentes.

Linux:
- observed state.

Regra:

PostgreSQL = desejado
Linux = observado
Django = decisão/orquestração
Agent = execução privilegiada

---

# 4. Limites Django ↔ Agent

Django NÃO deve executar diretamente:

- nmcli;
- ip;
- nft;
- iptables;
- ip6tables;
- sysctl;
- systemctl;
- alterações privilegiadas;
- escrita direta em configurações críticas do Linux.

Isso pertence ao Agent.

O Agent NÃO decide:

- qual interface é WAN;
- qual é LAN;
- qual é MGMT;
- HOME_NET;
- topologia;
- política de produto.

Essas decisões pertencem ao Django.

Não alterar Django e Agent no mesmo lote sem necessidade explícita.

---

# 5. Network Control

O módulo `rede` é a fonte oficial de topologia.

Ele controla:

- WAN;
- LAN;
- MGMT;
- DMZ;
- CUSTOM;
- UNASSIGNED;
- interfaces;
- IPv4;
- gateway;
- rota padrão;
- métricas;
- MTU;
- roteamento;
- NAT;
- redes internas;
- HOME_NET;
- desired state;
- observed state;
- reconciliação;
- drift.

Firewall, DNS, Suricata, Dispositivos, DHCP e futuros módulos devem consumir a topologia da Rede.

Não criar fontes paralelas de WAN/LAN/HOME_NET.

---

# 6. Topologia

Nunca hardcodar:

- quantidade fixa de NICs;
- enp0s3;
- enp0s8;
- ens18;
- eno1;
- eth0;
- qualquer nome físico específico.

2 NICs:

- WAN obrigatória;
- LAN obrigatória;
- MGMT dedicada opcional;
- gerenciamento pode ocorrer pela LAN.

3+ NICs:

- WAN;
- LAN;
- MGMT opcional;
- DMZ/CUSTOM/etc.

Nunca assumir:

terceira interface = MGMT

Papéis válidos:

- unassigned;
- wan;
- lan;
- mgmt;
- dmz;
- custom.

WAN != LAN.

MGMT dedicada != WAN/LAN.

UNASSIGNED = detectada mas não gerenciada.

---

# 7. Desired / Observed

Preservar sempre:

desired
observed

Nunca:

- substituir desired silenciosamente pelo Linux;
- assumir que banco = estado real;
- assumir que Linux está correto sem comparar.

Observed deve suportar múltiplos IPv4.

Revisões:

revisao_desejada
revisao_aplicada

Se:

desejada > aplicada
→ pending_apply

Se:

desejada == aplicada
e desired != observed
→ drifted

Estados oficiais:

- unmanaged;
- synced;
- pending_apply;
- applying;
- waiting_confirmation;
- drifted;
- missing;
- error.

---

# 8. Reconciliação

Ao consultar Rede:

1. consultar estado;
2. consultar Agent quando necessário;
3. obter observed;
4. persistir observed;
5. comparar desired x observed;
6. calcular status;
7. responder ao frontend.

Ações:

Atualizar = nova leitura.

Detectar interfaces = novo inventário.

Reconciliar = nova comparação.

Reconciliação NÃO aplica automaticamente mudanças destrutivas.

---

# 9. Safe Apply

Obrigatório para mudanças que possam interromper conectividade.

Fluxo:

desired
→ validação
→ snapshot
→ Agent aplica
→ rollback armado
→ waiting_confirmation
→ confirmação
→ rollback desarmado
→ confirmed

Sem confirmação:

timeout
→ rollback
→ reverted

O timer real de rollback NÃO pode depender de:

- browser;
- JavaScript;
- Django;
- futura requisição HTTP.

O rollback pertence ao lado privilegiado/Agent.

Nunca derrubar silenciosamente uma interface que mantém acesso administrativo.

---

# 10. Roteamento

Roteamento pertence ao módulo Rede.

Deve respeitar:

- topologia oficial;
- WAN/LAN;
- gateway;
- default route;
- métricas;
- desired/observed;
- Safe Apply;
- Agent.

Não alterar rota administrativa de forma destrutiva sem rollback.

Não implementar NAT dentro do lote de Roteamento.

---

# 11. NAT

NAT pertence à Rede.

Responsabilidades:

- MASQUERADE;
- saída LAN → WAN;
- integração com roteamento.

Firewall trata:

- ALLOW;
- DENY;
- DROP;
- REJECT.

Não misturar responsabilidades.

---

# 12. Firewall

Backend:

nftables

Regras obrigatórias:

- nunca usar `nft flush ruleset` como comportamento normal;
- não apagar regras externas ao namespace MoonShield;
- trabalhar apenas nas tabelas/chains MoonShield;
- preservar conexões estabelecidas;
- preservar acesso administrativo;
- validar regras globais perigosas.

Fluxo:

Django
→ Agent
→ nftables

Não reescrever esse contrato sem necessidade.

---

# 13. HOME_NET

HOME_NET deve vir da Rede.

Exemplo:

LAN:
10.10.0.1/24

Rede interna calculada:
10.10.0.0/24

O usuário não deve precisar preencher HOME_NET manualmente no fluxo normal.

Suricata consome esse resultado.

---

# 14. NetworkManager

NetworkManager é o backend oficial de rede da appliance.

Usar:

- perfis persistentes;
- detecção dinâmica de interfaces;
- configuração via Agent;
- persistência após reboot.

Não migrar/desativar interface administrativa de forma destrutiva durante bootstrap.

---

# 15. PostgreSQL

PostgreSQL é o banco de produção.

Persistir nele:

- interfaces;
- desired;
- observed;
- papéis;
- roteamento;
- NAT;
- histórico;
- alterações;
- snapshots;
- auditoria;
- configurações.

SQLite só pode ser usado explicitamente em DEV.

Nunca criar fallback automático PostgreSQL → SQLite.

Não modificar `.env` sem pedido.

Não hardcodar segredos.

---

# 16. Django

Comando correto:

python gerenciar.py

NÃO usar:

python manage.py

Servidor atual:

Gunicorn

Não trocar para Uvicorn sem motivo arquitetural real.

---

# 17. Frontend

Preservar quando não houver mudança visual explícita:

- IDs;
- data-*;
- sidebar;
- drawer;
- toasts;
- Safe Apply;
- Histórico;
- Aplicar Tudo;
- Rollback;
- responsividade.

Não fazer redesign junto com alteração lógica sem necessidade.

---

# 18. Estilo de código

Preferir código:

- compacto;
- legível;
- explícito;
- modular;
- consistente.

Evitar verticalização excessiva.

Bom:

interface.ipv4_atual = item.get("ipv4") or None

Evitar quebrar expressões simples em muitas linhas.

Não minificar de forma ilegível.

---

# 19. Segurança durante desenvolvimento

Nunca:

- expor tokens;
- versionar secrets;
- remover CSRF;
- remover autenticação;
- criar endpoint administrativo sem autenticação;
- dar privilégios desnecessários;
- executar comandos privilegiados diretamente no Django.

Hardening completo será feito em etapa própria.

Não transformar toda tarefa atual em auditoria genérica de segurança.

---

# 20. Windows x Linux

Windows pode validar:

- sintaxe;
- imports;
- Django;
- migrations;
- services;
- APIs;
- JS;
- testes unitários.

Linux/VM deve validar:

- NetworkManager;
- nmcli;
- nftables;
- systemd;
- socket Unix;
- Agent real;
- interfaces reais;
- rotas;
- Suricata;
- AdGuard;
- reboot.

Não fingir que uma validação Windows prova comportamento Linux.

---

# 21. VM de laboratório

Ambiente atual pode usar nomes como:

WAN = enp0s3
LAN = enp0s8

Isso é APENAS laboratório.

Nunca hardcodar esses nomes no produto.

Evitar alterações destrutivas na interface usada para administração.

---

# 22. Git

Antes de editar:

git status

Depois:

git diff

Nunca executar sem autorização explícita:

git reset --hard
git clean -fd

Nunca descartar alterações locais silenciosamente.

---

# 23. Regra de lotes

Padrão:

máximo 3 arquivos por lote

Se precisar de quarto arquivo:

1. pare;
2. informe o arquivo;
3. explique por quê;
4. aguarde autorização.

Não ampliar escopo silenciosamente.

---

# 24. Workflow obrigatório

Antes:

1. ler AGENTS.md;
2. identificar arquivos do lote;
3. procurar consumidores/produtores;
4. entender contratos;
5. verificar impacto;
6. fazer `git status`.

Durante:

1. alterar somente o necessário;
2. não refatorar fora do escopo;
3. não mudar arquitetura sem necessidade;
4. respeitar limite do lote;
5. não alterar configuração real da VM sem pedido.

Depois:

1. validar sintaxe;
2. executar testes relevantes;
3. executar `gerenciar.py check`;
4. revisar `git diff`;
5. listar arquivos alterados;
6. informar migrations;
7. informar impacto no Agent;
8. informar erros e pendências.

Nunca esconder falhas.

---

# 25. Migrations

Ao alterar models:

- gerar nova migration quando necessária;
- nunca apagar migrations antigas;
- nunca editar migration já aplicada;
- informar o nome da migration criada.

Se models não mudaram:

Migration: não necessária.

---

# 26. Quando parar

Parar e pedir autorização antes de:

- alterar mais de 3 arquivos;
- mudar arquitetura central;
- quebrar contrato Django ↔ Agent;
- alterar Django e Agent no mesmo lote;
- apagar model/campo/tabela;
- apagar migration;
- mudar Safe Apply estruturalmente;
- modificar `.env`;
- alterar WAN ativa;
- executar comando destrutivo;
- aplicar mudança perigosa na VM.

---

# 27. Checkpoint atual

Produto:

100% MoonShield Appliance ISO.

VM já possui e validou após reboot:

- Debian 13;
- NetworkManager;
- PostgreSQL 17;
- Django;
- Gunicorn;
- Nginx;
- moonshield-web.service;
- nftables;
- Suricata 7.0.10;
- Emerging Threats Open;
- AdGuard Home v0.107.79;
- DNS via AdGuard.

Não reinstalar componentes já existentes sem necessidade.

---

# 28. Network Control — progresso

Concluído:

Lote 1
- desired/observed;
- revisões;
- múltiplos IPv4.

Lote 2
- inventário;
- validação;
- reconciliação.

Lote 3
- interfaces/status API;
- Agent health separado.

Lote 4
- topologia oficial.

Lote 5
- frontend Interfaces.

Lote 6
- Overview usando topologia oficial.

Próximo:

Lote 7 — Roteamento

Depois:

Lote 8 — NAT
Lote 9 — Safe Apply
Lote 10 — Diagnóstico

Não pular essa sequência.

---

# 29. Arquivos dos próximos lotes

## Lote 7 — Roteamento

- `MoonShield/aplicativos/rede/services/roteamento.py`
- `MoonShield/aplicativos/rede/api/roteamento.py`
- `MoonShield/static/js/rede/secoes/roteamento_nat.js`

## Lote 8 — NAT

- `MoonShield/aplicativos/rede/services/nat.py`
- `MoonShield/aplicativos/rede/api/nat.py`
- `MoonShield/templates/rede/parciais/_roteamento_nat.html`

## Lote 9 — Safe Apply

- `MoonShield/aplicativos/rede/services/alteracoes.py`
- `MoonShield/aplicativos/rede/api/alteracoes.py`
- `MoonShield/static/js/rede/componentes/safe_apply.js`

## Lote 10 — Diagnóstico

- `MoonShield/aplicativos/rede/services/diagnostico.py`
- `MoonShield/aplicativos/rede/api/diagnostico.py`
- `MoonShield/static/js/rede/secoes/diagnostico.js`

---

# 30. MoonShield Agent

Código atual:

`MoonShield-Agent/`

Já existem módulos relacionados a:

- NetworkManager;
- inventário;
- aplicação;
- validação;
- diagnóstico;
- roteamento;
- NAT;
- snapshot;
- rollback;
- IPC;
- firewall;
- Suricata.

Ainda NÃO assumir como definidos:

- entrypoint final;
- daemon final;
- socket final;
- service systemd final;
- contrato final Django ↔ Agent.

Não criar `moonshield-agent.service` por suposição.

Depois dos Lotes 7–10:

1. analisar Agent completo;
2. fechar contrato Django ↔ Agent;
3. definir execução/IPC;
4. testar em Linux real.

---

# 31. Sequência após Rede

Depois dos Lotes 7–10:

1. fechar MoonShield Agent;
2. testar Django ↔ Agent ↔ NetworkManager;
3. integrar Agent ↔ nftables;
4. integrar Suricata;
5. integrar AdGuard;
6. adaptar painel para Appliance;
7. criar onboarding;
8. criar console local;
9. hardening final;
10. automatizar instalação;
11. gerar ISO;
12. testar instalação limpa;
13. validar reprodutibilidade.

Não antecipar essas etapas sem necessidade.

---

# 32. Appliance UI

Como os componentes farão parte da ISO, evitar conceitos antigos como:

"Instalar Suricata"
"Instalar AdGuard"
"Instalar nftables"

Preferir:

Suricata
- status;
- configuração;
- regras;
- diagnóstico.

AdGuard
- status;
- configuração;
- integração.

Firewall
- política;
- regras;
- status.

Isso será feito após Network/Agent.

---

# 33. Reboot / persistência

Antes de considerar Rede finalizada, validar em Linux:

reboot
→ NetworkManager
→ WAN
→ LAN
→ rota
→ NAT
→ Firewall
→ Agent
→ Django/reconciliação
→ painel coerente

Não considerar funcionalidade de rede concluída apenas por testes unitários.

---

# 34. ISO

A VM atual é a appliance de desenvolvimento.

Primeiro fazemos o software funcionar nela.

Depois transformamos passos manuais em instalação reproduzível.

Critério final:

VM vazia
→ instala ISO
→ primeiro boot
→ serviços ativos
→ onboarding
→ configuração da rede
→ appliance funcional

Se destruir a VM e reinstalar, o resultado deve ser reproduzível.

---

# 35. Formato de resposta

Após implementação:

Resumo
- ...

Arquivos alterados
- ...

Implementação
- ...

Compatibilidade
- ...

Migration
- necessária / não necessária

Testes executados
- comando → resultado

Impacto no Agent
- precisa / não precisa mudar

Pendências
- ...

Não responder apenas "feito".

---

# 36. Regra final

Antes:
entenda o código.

Durante:
altere somente o necessário.

Depois:
teste e revise o diff.

Objetivo:
finalizar o MoonShield Appliance de forma incremental, segura e testável.


---

# 37. Execução de comandos pelo agente — REGRA DE PRIORIDADE MÁXIMA

Esta regra sobrescreve, para execução pelo agente, quaisquer instruções anteriores deste arquivo que mandem executar:

- git status;
- git diff;
- git grep;
- git log;
- git show;
- git ls-files;
- git rev-parse;
- rg;
- grep;
- Select-String;
- Get-Content;
- Test-Path;
- comandos Python;
- py_compile;
- unittest;
- pytest;
- gerenciar.py check;
- qualquer outro comando de terminal.

## Regra principal

O AGENTE NÃO DEVE EXECUTAR COMANDOS DE TERMINAL.

Isso vale tanto antes, durante quanto depois da implementação.

O agente deve usar o editor e as ferramentas nativas de leitura/edição de arquivos do workspace.

Não utilizar o terminal apenas para localizar código que pode ser localizado pelas ferramentas de navegação/leitura do editor.

## Antes de editar

O agente deve:

1. ler AGENTS.md;
2. ler GEMINI.md quando existir;
3. analisar somente os arquivos necessários;
4. navegar pelo código usando leitura/exploração nativa do editor;
5. entender o contrato relacionado à tarefa;
6. identificar os arquivos mínimos necessários.

NÃO executar:

```text
git status
git grep
rg
grep
Get-Content
Select-String
findstr
cat
type
head
tail
python
py
pytest
unittest