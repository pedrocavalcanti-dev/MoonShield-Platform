<div align="center">

```
███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║███████╗███████║██║█████╗  ██║     ██║  ██║
██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║███████║██║  ██║██║███████╗███████╗██████╔╝
╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
```

<img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Django-5.x-092E20?style=for-the-badge&logo=django&logoColor=white"/>
<img src="https://img.shields.io/badge/JavaScript-Vanilla-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black"/>
<img src="https://img.shields.io/badge/Chart.js-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white"/>
<img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
<img src="https://img.shields.io/badge/Suricata-EF3B2D?style=for-the-badge&logoColor=white"/>
<img src="https://img.shields.io/badge/AdGuard_Home-68BC71?style=for-the-badge&logoColor=white"/>

### 🛡️ Dashboard Unificado de SOC/NOC — Plataforma Educacional

*Visibilidade total. Resposta rápida. Controle absoluto.*

> **v1.0 · Projeto Senac 2026 · Redes & Segurança**

</div>

---

## 📖 Sobre o Projeto

O **MoonShield** é uma plataforma educacional centralizada para operações de segurança **(SOC)** e monitoramento de rede **(NOC)**. Desenvolvido em Django, consolida logs, métricas e alertas de diversas fontes — Suricata IDS, Firewall (iptables/nftables), DNS (AdGuard Home) — em uma única interface interativa e de alta performance.

Projetado para **cursos técnicos, laboratórios de segurança e projetos integradores** que precisam simular a rotina de um SOC/NOC com visibilidade total sobre a infraestrutura e agilidade na resposta a incidentes.

> Projeto desenvolvido por **Pedro Cavalcanti** no Técnico em Redes e Segurança do Senac (2026).

---

## 🚀 Módulos e Funcionalidades

| # | Módulo | Descrição | Status |
|---|--------|-----------|--------|
| 01 | 🏠 **Dashboard Principal** | Visão geral de métricas, KPIs e conexões ativas em tempo real | ✅ Ativo |
| 02 | 🚨 **IDS / Incidentes (SOC)** | Integração com Suricata: alertas ao vivo, triagem, investigação por IP, risk score, correlação DNS/HTTP/TLS | ✅ Ativo |
| 03 | 🌐 **DNS & Rede** | Painel AdGuard Home: consultas ao vivo, bloqueio de domínios, regras e feed DNS em tempo real | ✅ Ativo |
| 04 | 🔥 **Firewall** | Monitoramento de tráfego, gestão de regras iptables e bloqueio em 1 clique | 🔧 Em desenvolvimento |
| 05 | 🌍 **Mapa de Ameaças** | Visualização geográfica (Leaflet.js) de origens de ataques via GeoIP em tempo real | 🔧 Planejado |
| 06 | 💻 **Diagnóstico de Rede** | Ping, traceroute, status dos sensores e terminal de diagnóstico integrado | 🔧 Planejado |
| 07 | 🤖 **Moon AI** | Análise automática de incidentes via Claude API: correlação, mitigações e resumos | 🔧 Planejado |
| 08 | 📄 **Relatórios** | Geração automática em PDF e CSV consolidando todos os módulos | 🔧 Planejado |
| 09 | 👤 **Gestão de Acesso** | Perfis com avatares, temas Dark/Light e preferências individuais | ✅ Ativo |

---

## ⚙️ Modos de Operação

### 🔬 Modo Demo — Ambiente Simulado

- Gera dados realistas (alertas, IPs, eventos DNS) automaticamente
- **Zero configuração** — funciona sem infraestrutura real
- Ideal para demonstrações, apresentações e aulas práticas
- Disponível imediatamente após a instalação

### 🛡️ Modo Produção — Ambiente Real

- Integra com **Suricata IDS**, **AdGuard Home** e **iptables/nftables** reais
- Requer o **sensor MoonShield** rodando no servidor Linux de coleta
- Monitoramento contínuo com histórico persistente

---

## 🛠️ Stack Tecnológica

| Camada | Tecnologia |
|--------|-----------|
| **Backend** | Python 3.12 + Django 5.x |
| **Banco de Dados** | SQLite *(dev)* · PostgreSQL *(produção)* |
| **Frontend** | HTML5, CSS3, JavaScript Vanilla |
| **Visualização** | Chart.js · Leaflet.js |
| **Segurança** | Suricata IDS · AdGuard Home · iptables/nftables |
| **IA** | Claude API (Anthropic) |

---

## 📂 Arquitetura do Projeto

```
MoonShield/
│
├── 📁 aplicativos/          # ⚙️  O Motor — todos os apps Django
│   ├── autenticacao/        #    Controle de acesso e sessões
│   ├── firewall/            #    Regras, tráfego e bloqueios
│   ├── incidentes/          #    Integração Suricata, pipeline SOC e incidentes
│   ├── dns/                 #    Monitoramento DNS (AdGuard Home)
│   ├── mapa_ameacas/        #    Geolocalização e visualização de ataques
│   ├── dispositivos/        #    Inventário, scan e diagnóstico
│   ├── relatorios/          #    Geração de PDF/CSV
│   ├── MoonShieldai/        #    Módulo de IA (Claude API)
│   ├── painel/              #    Dashboard geral
│   └── configuracoes/       #    Configurações do sistema
│
├── 📁 config/               # 🧠  O Cérebro — settings.py e roteador mestre
├── 📁 media/                # 📎  Arquivos dinâmicos (avatars, uploads)
├── 📁 static/               # 🎨  Frontend estático (CSS, JS, imagens)
├── 📁 templates/            # 🖥️  Camada HTML (espelha estrutura dos apps)
│   └── reutilizaveis/       #    Componentes globais: topbar, sidebar...
│
├── gerenciar.py             # 🎛️  Orquestrador principal (manage.py customizado)
├── requirements.txt         # 📦  Dependências do projeto
└── .env                     # 🔐  Variáveis de ambiente (não versionar!)
```

---

## 💻 Instalação

### Pré-requisitos

| Requisito | Versão |
|-----------|--------|
| **Python** | 3.10 ou superior |
| **SO** | Windows 10/11 ou Linux (Ubuntu/Debian) |
| **RAM** | 4 GB mínimo |

---

### Passo a passo

#### 1️⃣ Clonar o repositório

```bash
git clone https://github.com/pedrocavalcanti-dev/moonshield.git
cd MoonShield/MoonShield
```

#### 2️⃣ Criar e ativar o ambiente virtual

**Windows (PowerShell):**
```powershell
python -m venv .venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\activate
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### 3️⃣ Instalar as dependências

```bash
pip install -r requirements.txt
```

#### 4️⃣ Aplicar as migrações

```bash
python gerenciar.py migrate
```

> ✅ O sistema cria automaticamente o usuário **moonshield** e exibe as credenciais no terminal. Use-as para fazer login.

#### 5️⃣ Iniciar o servidor

```bash
python gerenciar.py runserver
```

Acesse **[http://127.0.0.1:8000](http://127.0.0.1:8000)**, use as credenciais exibidas no terminal e está dentro. ✅

---

## 🔐 Variáveis de Ambiente (opcional)

Crie um arquivo `.env` na raiz para personalizar:

```env
SECRET_KEY=sua-chave-secreta-aqui
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
```

> ⚠️ **Nunca** versione o `.env` — já está no `.gitignore`.

---

## 🌐 Sensor MoonShield (Modo Produção)

Para receber dados reais do Suricata, execute o sensor no servidor Linux de coleta:

```bash
# No servidor Linux com Suricata instalado
python3 sensor.py --auto
```

O sensor lê o `eve.json` do Suricata em tempo real, envia os eventos para o backend via HTTP e exibe o status em uma animação ASCII com o escudo MoonShield. Token de autenticação gerado e renovado automaticamente.

---

## 🔭 Visão Futura

- **Firewall Visual** completo com bloqueio em 1 clique integrado ao IDS
- **IPS** — Suricata em modo inline com bloqueio automático via iptables
- **Mapa de Ameaças** ao vivo com linhas de ataque animadas (GeoIP + Leaflet.js)
- **Moon AI** — análise automática de incidentes via Claude API
- **Relatórios PDF** gerados automaticamente por período
- **MoonShield Attack** — simulação controlada para cenários Blue Team vs Red Team *(exclusivamente educacional, ambiente isolado)*
- **Versão SaaS** — MoonGroup: plataforma multi-tenant para MSPs e instituições de ensino

---

## 📄 Licença

Distribuído sob a licença **MIT**. Consulte o arquivo `LICENSE` para mais detalhes.

---

<div align="center">

Desenvolvido com 🛡️ por **Pedro Cavalcanti**

*Técnico em Redes de Computadores · Senac São Paulo · 2026*

*Para operações táticas de Blue Team e ensino prático de segurança de redes.*

</div>
