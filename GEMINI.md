# GEMINI.md — MoonShield Platform

> Contexto operacional para o Gemini Code Assist / modo agente no VS Code.
>
> **Este arquivo NÃO substitui `AGENTS.md`.**
> Sempre leia e siga `AGENTS.md` primeiro. Este `GEMINI.md` complementa o `AGENTS.md` com arquitetura, decisões, estado real validado, lotes concluídos, bugs conhecidos, ordem de implementação, regras de segurança e checkpoint exato.

---

# 1. Regra principal

O MoonShield já possui arquitetura definida e vários lotes concluídos e validados.

Ao trabalhar neste repositório:

1. não crie arquitetura paralela;
2. não substitua serviços existentes por novos caminhos sem necessidade;
3. não duplique responsabilidades;
4. não crie novas APIs/actions se já existir contrato oficial equivalente;
5. não altere models/migrations sem autorização explícita;
6. não execute mudanças reais de rede no Linux sem autorização explícita;
7. não faça commit/push automaticamente;
8. não avance de lote sem validação;
9. não simplifique Safe Apply removendo snapshot/rollback/confirmação;
10. não use comandos destrutivos de nftables/rede.

Antes de editar:
- leia `AGENTS.md`;
- leia este `GEMINI.md`;
- leia os arquivos reais relevantes;
- trace o fluxo existente;
- explique causa/arquitetura antes de mudanças grandes.

---

# 2. Arquitetura do produto

```text
Browser
  ↓
Nginx
  ↓
Django / Gunicorn
  ↓
MoonShield Agent
  ↓
Linux
  ├── NetworkManager
  ├── nftables
  ├── Suricata
  ├── AdGuard Home
  └── systemd
```

Responsabilidades:

```text
Django
= control plane / cérebro
= desired state
= validação lógica
= topologia
= auditoria
= histórico
= políticas

PostgreSQL
= desired state
= histórico
= auditoria
= entidades persistentes

Agent
= executor privilegiado
= leitor do estado real
= snapshot / rollback
= IPC seguro

Linux
= observed state / realidade operacional
```

## Regra fundamental

Django NÃO deve executar diretamente comandos privilegiados como:

```text
nmcli
nft
sysctl
ip
systemctl
```

Toda escrita privilegiada passa pelo Agent.

O Agent NÃO decide sozinho:

```text
WAN
LAN
MGMT
DMZ
HOME_NET
rede interna
interface principal
```

Essas decisões pertencem ao Django/topologia oficial do módulo `rede`.

---

# 3. Ambiente do appliance

Sistema:

```text
Debian 13
hostname: moonshield
sem desktop
```

Paths:

```text
/opt/moonshield/source
/opt/moonshield/source/MoonShield
/opt/moonshield/source/MoonShield-Agent
/opt/moonshield/app -> /opt/moonshield/source/MoonShield
/opt/moonshield/venv
```

Runtime/config:

```text
/etc/moonshield
/var/lib/moonshield
/var/log/moonshield
/var/backups/moonshield
/run/moonshield
```

Serviços instalados:

```text
NetworkManager
PostgreSQL 17
moonshield-web
Nginx
nftables
Suricata 7.0.10
AdGuard Home v0.107.79
```

Portas/base:

```text
Nginx: 80
Gunicorn: 127.0.0.1:8000
PostgreSQL: localhost:5432
DNS: 53
AdGuard UI DEV: 3000
```

O navegador acessa Nginx, não Gunicorn diretamente.

---

# 4. `rede` é a fonte oficial da topologia

O módulo `rede` é proprietário oficial de:

```text
WAN
LAN
MGMT
DMZ
CUSTOM
unassigned
interfaces
endereços IPv4
gateway
rota default
métricas
MTU
roteamento
NAT
redes internas
acesso de gerenciamento
desired state
observed state
drift
reconciliation
HOME_NET derivado
```

Papéis:

```text
unassigned
wan
lan
mgmt
dmz
custom
```

Nenhum módulo consumidor deve manter uma segunda verdade de topologia.

Consumidores futuros:

```text
Firewall
Suricata
AdGuard
Devices
Dashboard
Diagnóstico
Incidentes
Configurações
```

Todos devem consumir `rede`.

---

# 5. Safe Apply

Fluxo oficial:

```text
desired
  ↓
validation
  ↓
snapshot
  ↓
Agent apply
  ↓
rollback armed
  ↓
waiting_confirmation
  ↓
confirm
  ↓
rollback disarmed
  ↓
confirmed
```

Se não houver confirmação no timeout:

```text
Agent executa rollback
```

Rollback deve ser independente de browser/Django.

---

# 6. IPC Django ↔ Agent

Socket:

```text
/run/moonshield/agent.sock
```

Permissões:

```text
root:moonshield
0660
```

Actions auditadas:

```text
system.ping
network.status
network.inventory
network.diagnostics
network.routing.status
network.nat.status
network.change.apply
network.change.confirm
network.change.rollback
network.change.status
network.change.cancel
```

Não inventar actions paralelas sem necessidade.

---

# 7. A1 — concluído

Runtime / entrypoint / IPC / systemd.

Agent:

```text
python -m firewall.ipc.servidor
```

systemd:

```text
root:moonshield
WorkingDirectory MoonShield-Agent
RuntimeDirectory moonshield
Restart=on-failure
SIGTERM graceful
```

Safe Apply recovery ocorre antes de aceitar requests.

---

# 8. A2 — concluído

Commit:

```text
35707ee fix: align network agent contracts batch A2
```

Correções:
- `expira_em` vem do Agent;
- offline → 503;
- timeout → 504;
- resposta inválida → 502.

Linux anterior:

```text
37/37 PASS
```

---

# 9. A3 — concluído

Commit:

```text
6fbcf11 fix: preserve network observed state batch A3
```

Inventory inválido NÃO vira `interfaces=[]`.

Agent offline preserva observed.

Linux:

```text
40/40 PASS
```

Inventory real:

```text
enp0s3
enp0s8
```

com MAC/link/carrier/IPv4/gateway/metric/MTU/profile.

---

# 10. A4 — concluído

NetworkManager/interface apply real.

Safe Apply obrigatório.

Backend usa argv seguro, sem `shell=True`.

Profiles:

```text
moonshield-<interface>
```

Preserva profiles não alvo.

`revisao_aplicada` só promove após confirmação.

`AlteracaoRede.configuracao_solicitada.revisoes_interfaces` congela revisão aplicada.

Estado final anterior:

```text
enp0s3 = WAN
enp0s8 = LAN

enp0s3 revisão 1/1 synced
enp0s8 revisão 4/4 synced
0 pending
```

Linux validado:

```text
enp0s3 = 192.168.0.106/24 DHCP
enp0s8 = 192.168.52.1/24 static
```

---

# 11. A5 — concluído

Routing real concluído.

Ownership:

```text
RotaEstatica = rota gerenciada pelo MoonShield
rota só no Linux/NetworkManager = externa/manual = preservar
```

Remoção delta:

```text
FINAL =
(current - removed_moonshield)
∪ desired_moonshield
```

Tombstone de remoção:

```text
ativa=False
pendente=True
sincronizada=True
```

`sincronizada=True` é evidência de aplicação anterior.

Teste real:

```text
10.250.0.0/24 via 192.168.52.254 dev enp0s8 metric 100
```

ADD PASS.
Persistência NM PASS.
Remoção da última rota PASS.
WAN/bootstrap preservada.
Default route preservada.

A5 = CONCLUÍDO.

---

# 12. A6 — EM ANDAMENTO

## NAT + IPv4 Forward real

Commit inicial:

```text
6127f0a feat: add real nat and ipv4 forwarding batch A6
```

Correção posterior:

```text
a288ef1 fix: isolate nat apply from networkmanager routing
```

O que já funciona:

```text
NAT MASQUERADE                     PASS
table ip moonshield_nat            PASS
ip_forward 0→1                     PASS
network.nat.status                 PASS
remoção NAT                        PASS
ip_forward 1→0                     PASS
moonshield_nat removida            PASS
inet filter preservado             PASS
```

Persistência de ip_forward:

```text
/etc/sysctl.d/90-moonshield-network.conf
```

Regra LAB validada:

```text
iifname "enp0s8"
oifname "enp0s3"
ip saddr 192.168.52.0/24
masquerade
comment "moonshield-nat:1"
```

---

# 13. BUG CRÍTICO ATUAL DO A6

Apesar de NAT/nftables/ip_forward funcionarem, aplicar NAT causa regressão na WAN.

Baseline correto:

```text
default via 192.168.0.1 dev enp0s3 proto dhcp metric 100

moonshield-bootstrap:
ipv4.method = auto
ipv4.gateway = --
ipv4.routes = --
ipv4.never-default = no

ip_forward = 0
sem moonshield_nat
```

Após ADD NAT:

```text
ip -4 route show default
→ vazio

moonshield-bootstrap:
ipv4.never-default = yes
```

Após REMOVE NAT:

```text
NAT removida
ip_forward volta 0
mas ipv4.never-default continua yes
default continua ausente
```

Recuperação manual comprovada:

```bash
nmcli connection modify moonshield-bootstrap ipv4.never-default no
nmcli connection up moonshield-bootstrap
```

Isso restaura imediatamente a default route.

---

# 14. O que já foi corrigido/tentado no A6

A correção `a288ef1` isolou NAT de:

```text
_aplicar_interfaces()
_aplicar_roteamento()
configurar_rotas()
ativar_interface()
snapshot de profiles NetworkManager
```

Payload NAT deve conter somente:

```text
roteamento.ipv4_forward
nat
```

Não deve conter:

```text
interfaces
gateway
rota_padrao
rotas estáticas
MTU
configuração IPv4
```

Mesmo assim o bug continuou.

---

# 15. Segunda análise A6

Busca estática identificou pontos mutáveis:

```text
MoonShield-Agent/rede/backends/networkmanager.py
```

Funções:

```text
NetworkManagerBackend.configurar_interface()
NetworkManagerBackend.configurar_rotas()
NetworkManagerBackend.ativar_interface()
NetworkManagerBackend.restaurar_snapshot_interface()
```

A escrita conhecida de:

```text
ipv4.never-default
```

ocorre em:

```text
NetworkManagerBackend.configurar_interface()
```

Mas o trace estático não encontrou cadeia NAT → `configurar_interface()` após `a288ef1`.

Portanto:

```text
NÃO corrigir novamente por hipótese.
```

Precisamos instrumentar o executor real de `nmcli`.

---

# 16. PRÓXIMA TAREFA EXATA — INSTRUMENTAÇÃO NETWORKMANAGER

Este é o checkpoint exato.

Arquivo autorizado:

```text
MoonShield-Agent/rede/backends/networkmanager.py
```

Objetivo:

instrumentar a função central que executa `nmcli`, provavelmente:

```text
NetworkManagerBackend._nmcli()
```

ou equivalente real.

Registrar via logger somente comandos MUTÁVEIS:

```text
nmcli connection modify
nmcli connection up
nmcli connection down
nmcli device reapply
```

Read-only pode ser ignorado:

```text
nmcli connection show
nmcli device show
nmcli device status
```

Não usar `print`.

Não registrar senha/token/secret.

Formato conceitual:

```text
[networkmanager] comando mutável
operacao=connection.modify
args=[...]
```

---

# 17. TESTE NEGATIVO OBRIGATÓRIO A6

Plano:

```text
tipo = nat
```

NÃO pode chamar:

```text
configurar_interface
configurar_rotas
ativar_interface
restaurar_snapshot_interface
```

ou qualquer função mutável de NetworkManager encontrada.

Deve chamar:

```text
definir_ipv4_forward
aplicar_regras_nat
```

Use mocks e `assert_not_called()`.

---

# 18. Escopo da próxima rodada A6

Pode alterar:

```text
MoonShield-Agent/rede/backends/networkmanager.py
```

E, se necessário, UM arquivo de teste apropriado.

Se precisar de terceiro arquivo:

```text
PARE
explique
peça autorização
```

Não alterar models/migrations.

Não corrigir sem causa comprovada.

---

# 19. Procedimento depois da instrumentação

Fluxo:

```text
instrumentar
→ git diff --check
→ revisão
→ usuário autoriza commit
→ commit/push
→ Linux pull
→ restart Agent/Web
→ ADD NAT UMA VEZ
→ checar default antes de confirmar
→ se default sumir: NÃO confirmar
→ capturar journal
```

Comando:

```bash
journalctl -u moonshield-agent --since "-5 min" --no-pager
```

Objetivo:
identificar comando `nmcli` mutável real.

Só depois corrigir causa.

---

# 20. Baseline de rede antes de novo LAB

Valores do laboratório anterior:

```text
WAN
interface: enp0s3
profile: moonshield-bootstrap
DHCP
IPv4 observado: 192.168.0.106/24
gateway: 192.168.0.1
default route: via 192.168.0.1
ipv4.never-default = no

LAN
interface: enp0s8
profile: moonshield-enp0s8
IPv4: 192.168.52.1/24
sem gateway/default

NAT
OFF

ip_forward
0

nftables
somente table inet filter baseline
```

IMPORTANTE:
esses valores são de laboratório e NÃO podem ser hardcoded.

Após importar a VM em outro PC/rede, execute read-only:

```bash
ip -4 addr
ip -4 route show table main
ip -4 route show default
nmcli -t -f DEVICE,STATE,CONNECTION device status
nmcli connection show
sysctl net.ipv4.ip_forward
nft list ruleset
```

---

# 21. VM importada em outro ambiente

Antes de qualquer apply real:

1. verificar interfaces;
2. verificar MACs;
3. verificar profiles;
4. verificar default route;
5. verificar IP WAN;
6. verificar LAN;
7. verificar Agent;
8. verificar Web;
9. verificar Nginx;
10. verificar conectividade.

Não assumir que o Senac possui a mesma rede do laboratório anterior.

---

# 22. A7 — NÃO INICIADO

Safe Apply real completo.

Só iniciar após A6 100% concluído.

Objetivos:

```text
timeout real
rollback automático
browser independente
Django independente
restart/recovery do Agent
expiração
restauração por snapshot
```

---

# 23. A8 — NÃO INICIADO

Drift / Reconciliation real.

Só após A7.

Objetivos:

```text
desired vs observed
drift real
mudança manual no Linux
detecção
status correto
reconciliation segura
não promover revision artificialmente
preservar ownership
```

---

# 24. Roadmap após A8

```text
A9  Firewall / nftables integration
A10 Suricata IDS integration
A11 AdGuard DNS integration
A12 Diagnósticos extras
A13 Consumer integration
A14 Appliance services / boot
```

Depois:

```text
Config real
Dashboard real
Devices
Incidentes/Eventos
Threat Map
Reports
AI
Retention/logs
Onboarding
Hardening
HTTPS
Installer reproduzível
ISO RC1
Blank VM / reproducibility
```

---

# 25. A9 — Firewall consome `rede`

Firewall deve usar `rede` para:

```text
WAN
LAN
MGMT
DMZ
redes internas
interfaces
```

Nunca decidir topologia sozinho.

A6 usa somente:

```text
table ip moonshield_nat
```

A9 será responsável pelo filter/firewall.

Nunca:

```bash
nft flush ruleset
```

---

# 26. A10 — Suricata consome `rede`

Suricata 7.0.10 já instalado.

Derivar de `rede`:

```text
HOME_NET
interfaces monitoradas
redes internas
WAN
```

Não hardcodar HOME_NET.

Começar como IDS.
IPS depois.

---

# 27. A11 — AdGuard consome `rede`

AdGuard Home v0.107.79 já instalado.

Usar `rede` para:

```text
interfaces internas
redes permitidas
LAN
MGMT
clientes
bind/listen
integração futura Devices
```

WAN não deve virar rede interna.

---

# 28. A13 — consumidores

```text
rede
├── Firewall
├── Suricata
├── AdGuard
├── Devices
├── Dashboard
├── Diagnóstico
├── Incidentes
└── Configurações
```

`rede` continua fonte única.

---

# 29. Diagnóstico

Diagnóstico atual é sob demanda:

```text
Executar
→ Agent lê estado naquele momento
→ resultado aparece
```

Resultado pode sumir ao sair/recarregar.
Isso é intencional e não é bug.

Mais tarde, após A9/A10/A11, pode ganhar checks de:

```text
Firewall
Suricata
ET Open
AdGuard
DNS :53
Agent
NetworkManager
PostgreSQL
Nginx
```

---

# 30. Arquivo de log runtime sujo

```text
MoonShield/logs/moonshield.log
```

pode aparecer modificado no Git.

Não adicionar/restaurar/commitar automaticamente.

---

# 31. Testes Django em Linux

Quando necessário:

```bash
sudo -u postgres psql -c "ALTER ROLE moonshield CREATEDB;"
```

Executar testes.

Depois SEMPRE:

```bash
sudo -u postgres psql -c "ALTER ROLE moonshield NOCREATEDB;"
sudo -u postgres psql -c "\du moonshield"
```

Não deixar CREATEDB ativo.

---

# 32. Testes Windows

`.venv` Windows já apresentou referência a Python 3.12 inexistente.

Se falhar por isso:
reporte.

Não alterar projeto só para consertar venv local sem autorização.

Linux `/opt/moonshield/venv` é ambiente oficial.

---

# 33. nftables

Nunca:

```bash
nft flush ruleset
```

A6:

```text
table ip moonshield_nat
```

Baseline filter anterior:

```nft
table inet filter {
    chain input {
        type filter hook input priority filter;
        policy accept;
    }
    chain forward {
        type filter hook forward priority filter;
        policy accept;
    }
    chain output {
        type filter hook output priority filter;
        policy accept;
    }
}
```

A6 não pode alterar essa tabela.

---

# 34. Segurança de comandos

Nunca usar `shell=True` para payload de usuário/configuração de rede.

Preferir argv seguro.

Validar:
- interface;
- IPv4;
- CIDR;
- gateway;
- metric;
- MTU;
- nomes.

---

# 35. NetworkManager

Responsabilidades já existentes:

```text
configurar_interface
configurar_rotas
ativar_interface
snapshot
restore
inventory
```

No A6 NAT:

```text
NetworkManager DEVE SER READ-ONLY
```

NAT usa apenas nomes de interfaces, CIDR e papéis para construir nftables.

NAT NÃO modifica profiles.

---

# 36. ip_forward

Regra:

```text
se houver NAT ativo:
    effective_forward = True
senão:
    effective_forward = ConfiguracaoRoteamento.ipv4_forward
```

Persistência:

```text
/etc/sysctl.d/90-moonshield-network.conf
```

---

# 37. NAT ownership

Namespace exclusivo:

```text
family = ip
table = moonshield_nat
chain = postrouting
```

Remoção da última regra já funcionou no LAB.

Tabelas externas devem ser preservadas.

---

# 38. Default route

`RotaEstatica` NÃO deve gerenciar:

```text
0.0.0.0/0
```

Default route pertence à configuração WAN/interface.

A5/A6 não devem criar segunda fonte de verdade.

---

# 39. HOME_NET

Agent não decide HOME_NET.

Futuro A10:

```text
Django / rede
→ calcula redes internas
→ Suricata recebe configuração
```

Agent apenas executa.

---

# 40. Pendência futura de admin/onboarding

Garantir futuramente que migrations/bootstrap não redefinam senha admin de produção.

Não misturar com A6/A7/A8.

---

# 41. Estilo de trabalho esperado do Gemini

Para tarefas de risco:

1. analisar;
2. rastrear;
3. explicar causa;
4. informar arquivos;
5. pedir autorização se escopo exceder;
6. editar;
7. rodar validações locais seguras;
8. mostrar resumo;
9. PARAR;
10. aguardar validação/commit.

---

# 42. Formato de resposta em lotes

```text
LOTE / CORREÇÃO — NOME

Resumo
- ...

Causa raiz
- ...

Fluxo
- ...

Arquivos alterados
- ...

Model alterado
- SIM/NÃO

Migration
- SIM/NÃO

Rede real alterada
- SIM/NÃO

Testes
- ...

git diff --check
- ...

Pronto para commit/validação Linux
- SIM/NÃO

Se NÃO:
- bloqueio exato

PARE.
```

---

# 43. Não commitar automaticamente

Fluxo:

```text
Gemini edita
→ Gemini para
→ revisão
→ autorização
→ commit manual
→ push
→ Linux pull
→ validação real
```

Não executar `git commit`/`git push` sem autorização.

---

# 44. Checkpoint resumido

```text
A1 Runtime / systemd               ✅
A2 Django ↔ Agent                  ✅
A3 Inventory / observed            ✅
A4 NetworkManager real             ✅
A5 Routing real                    ✅
A6 NAT + IPv4 Forward              🟠
A7 Safe Apply real                 ⏸
A8 Drift / Reconciliation          ⏸
A9 Firewall integration            ⏸
A10 Suricata integration           ⏸
A11 AdGuard integration            ⏸
A12 Diagnostics extras             ⏸
A13 Consumers integration          ⏸
A14 Appliance / boot               ⏸
```

A6 está funcional em NAT, mas bloqueado por:

```text
ADD NAT
→ ipv4.never-default muda no → yes
→ default route desaparece
```

Próxima ação:

```text
instrumentar NetworkManagerBackend._nmcli()
```

---

# 45. Prompt recomendado para nova sessão Gemini

```text
Leia primeiro o AGENTS.md e o GEMINI.md na raiz do repositório.

Não redesenhe a arquitetura e não avance de lote.

Estamos no A6, exatamente no checkpoint descrito no GEMINI.md:
NAT/nftables/ip_forward funcionam, mas ADD NAT ainda altera ipv4.never-default da WAN e remove a default route.

Sua primeira tarefa é SOMENTE a instrumentação autorizada de NetworkManager descrita no GEMINI.md.

Antes de editar:
1. confirme os arquivos relevantes;
2. trace a função _nmcli() real;
3. confirme o logger existente;
4. diga quais arquivos pretende alterar.

Depois faça apenas a instrumentação e o teste negativo previstos.
Não commit.
Não execute rede real.
Pare ao final e forneça o relatório.
```

---

# 46. Prioridades

```text
1. não perder conectividade
2. não destruir configuração externa
3. ownership correto
4. rollback confiável
5. observed real
6. idempotência
7. persistência
8. UI
9. conveniência
```

---

# 47. Princípio final

MoonShield deve se comportar como appliance de produção.

Toda mudança deve ser:

```text
determinística
auditável
reversível
idempotente
ownership-safe
observável
```

E módulos de segurança devem consumir uma única topologia oficial:

```text
rede
```

Nunca criar estados paralelos divergentes.
