<div align="center">

# 🛡️ CyberGuard AI

**Plataforma inteligente de monitoramento e análise de segurança**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![Plotly](https://img.shields.io/badge/Plotly-3F4F75?style=for-the-badge&logo=plotly&logoColor=white)](https://plotly.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-89%20passed-22C55E?style=for-the-badge&logo=pytest&logoColor=white)](tests/)

*Transforme arquivos de log brutos em inteligência de segurança acionável — em menos de 60 segundos.*

[🚀 Demo](#-demo) · [⚙️ Instalação](#-instalação) · [📖 Funcionalidades](#-funcionalidades) · [🏗️ Arquitetura](#-arquitetura)

</div>

---

## 🎯 O que é?

O **CyberGuard AI** é uma plataforma open-source de análise de logs de segurança que combina:

- 🔍 **Detecção automática** de 6 tipos de ameaças (brute force, comprometimento de contas, IPs suspeitos e mais)
- 📊 **Dashboard interativo** com gráficos Plotly, linha do tempo e mapa de calor
- 🤖 **IA explicativa** que traduz incidentes técnicos em linguagem simples (offline ou via Claude API)
- 📄 **Relatório PDF profissional** pronto para apresentar à gestão
- 🗄️ **Histórico persistente** em banco de dados SQLite

> Ideal para analistas de segurança júnior, sysadmins de PMEs e estudantes de cybersecurity que precisam de uma solução SIEM leve e acessível.

---

## 📸 Screenshots

| Dashboard | Análise de Ameaças |
|-----------|-------------------|
| KPIs + gráficos interativos | Cards de incidentes com score de risco |

| Explicação por IA | Relatório PDF |
|-------------------|---------------|
| Linguagem simples em 3 blocos | Profissional, pronto para gestão |

---

## ✨ Funcionalidades

### 🔍 Detecção de Ameaças (6 detectores)
| Detector | Regra | Score Base |
|----------|-------|-----------|
| Brute Force | 5+ falhas do mesmo IP em 10 min | 70 |
| Login Após Falhas | Sucesso após 3+ falhas em 30 min | 85 |
| Acesso Off-Hours | Fora das 7h–22h ou fins de semana | 40 |
| IP Suspeito | 1 IP → 3+ usuários distintos | 60 |
| Enumeração de Usuários | 10+ usernames distintos com falha | 75 |
| Acesso Privilegiado | admin/root fora do horário ou com falhas | 50 |

### 📊 Dashboard
- 7 KPIs em tempo real
- Distribuição por severidade (pizza)
- Incidentes por tipo de ameaça (barras)
- Linha do tempo de eventos por hora
- Top 10 IPs e usuários mais atacados
- Evolução do score de risco
- Mapa de calor hora × dia da semana

### 🤖 IA Explicativa
- **Modo offline**: templates inteligentes com contexto real do incidente (IP, usuário, timestamps)
- **Modo online**: explicações geradas pela Claude API (requer `ANTHROPIC_API_KEY`)
- Estrutura em 3 blocos: *O que aconteceu / Por que é perigoso / O que fazer agora*

### 📄 Relatório PDF
- Capa com metadados da análise
- Sumário executivo com tabela de KPIs
- Detalhamento dos incidentes críticos e altos
- Tabela de recomendações priorizadas (Imediato / Curto / Longo Prazo)
- Aviso de confidencialidade

---

## 🚀 Instalação

### Pré-requisitos
- Python 3.11+
- pip

### Passos

```bash
# 1. Clone o repositório
git clone https://github.com/orlandini01/cyberguard-ai.git
cd cyberguard-ai

# 2. Crie e ative o ambiente virtual
python -m venv venv

# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Configure as variáveis de ambiente
cp .env.example .env
# Edite o .env se quiser usar a Claude API (opcional)

# 5. Gere os dados de exemplo
python data/generate_samples.py

# 6. Inicie a aplicação
python run.py
```

Acesse em: **http://localhost:8501**

### Configuração opcional da IA
```env
# .env
ANTHROPIC_API_KEY=sk-ant-...  # opcional — sem isso, usa modo offline
```

---

## 📖 Como usar

1. **Importar Logs** → Faça upload de CSV/JSON/TXT ou use os dados de exemplo
2. **Executar Análise** → O motor detecta ameaças e calcula scores automaticamente
3. **Dashboard** → Visualize KPIs, gráficos e a linha do tempo
4. **Análise** → Filtre e revise os incidentes detectados
5. **Incidentes** → Detalhe cada incidente e obtenha explicação da IA
6. **Relatórios** → Gere e baixe o PDF profissional
7. **Histórico** → Consulte análises anteriores

### Formatos de log suportados

**CSV** (colunas obrigatórias):
```csv
timestamp,source_ip,username,action,status,details
2024-06-15 14:30:00,10.0.0.1,joao.silva,LOGIN,success,Autenticação normal
2024-06-15 02:15:00,185.220.101.47,admin,SSH_LOGIN,failure,Senha incorreta
```

**JSON**:
```json
[
  {"timestamp": "2024-06-15T14:30:00", "source_ip": "10.0.0.1",
   "username": "joao.silva", "action": "LOGIN", "status": "success"}
]
```

**TXT** (formato syslog):
```
Jun 15 14:30:00 srv LOGIN[1234]: success user=joao.silva src=10.0.0.1 msg="Normal"
```

---

## 🏗️ Arquitetura

```
cyberguard-ai/
├── app/                    # Interface Streamlit
│   ├── main.py             # Dashboard principal
│   └── pages/              # Páginas da aplicação
│       ├── 01_upload.py    # Importação de logs
│       ├── 02_analysis.py  # Análise de ameaças
│       ├── 03_incidents.py # Detalhamento + IA
│       ├── 04_reports.py   # Geração de PDF
│       └── 05_history.py   # Histórico SQLite
│
├── src/                    # Lógica de negócio
│   ├── log_parser.py       # Parser CSV/JSON/TXT
│   ├── threat_detector.py  # 6 detectores de ameaça
│   ├── risk_engine.py      # Cálculo de score 0–100
│   ├── ai_assistant.py     # IA offline + Claude API
│   ├── report_generator.py # Geração de PDF (ReportLab)
│   ├── database.py         # SQLite (SQLAlchemy)
│   └── utils.py            # Utilitários compartilhados
│
├── data/                   # Logs de exemplo (533 eventos)
├── tests/                  # 89+ testes automatizados
├── reports/                # PDFs gerados
└── docs/                   # Documentação técnica
```

### Fórmula de risco
```
score = base_score × fator_frequência × fator_horário × fator_privilégio
score = min(score, 100.0)

fator_frequência = min(eventos / threshold, 3.0)
fator_horário    = 1.3  (se fora do horário comercial)
fator_privilégio = 1.5  (se conta admin/root)
```

---

## 🧰 Stack Tecnológica

| Categoria | Tecnologia | Função |
|-----------|------------|--------|
| Interface | Streamlit 1.32+ | Dashboard web interativo |
| Dados | Pandas 2.2+ | Manipulação de logs |
| Visualização | Plotly 5.20+ | Gráficos interativos |
| Banco de dados | SQLite + SQLAlchemy 2.0 | Histórico persistente |
| PDF | ReportLab 4.1+ | Relatórios profissionais |
| IA | Anthropic SDK 0.25+ | Explicações (opcional) |
| Testes | Pytest 8.0+ | 89+ testes automatizados |

---

## 🧪 Testes

```bash
# Rodar todos os testes
python -m pytest tests/ -v

# Com cobertura de código
python -m pytest tests/ --cov=src --cov-report=html

# Módulo específico
python -m pytest tests/test_threat_detector.py -v
```

**Cobertura atual:** 89 testes · `utils`, `log_parser`, `threat_detector`, `risk_engine`, `ai_assistant`

---

## 🗺️ Roadmap

- [x] MVP v1.0 — Parser, detecção, dashboard, PDF, IA, histórico
- [ ] v1.1 — Monitoramento em tempo real (file watcher)
- [ ] v1.2 — Alertas por e-mail e Slack
- [ ] v1.3 — API REST com FastAPI
- [ ] v2.0 — Machine Learning (Isolation Forest para anomalias)
- [ ] v3.0 — SaaS multi-tenant com autenticação e billing

---

## 👨‍💻 Autor

**Pier Orlandini**
Estudante de Sistemas de Informação · Estagiário em Dados · Entusiasta de Cybersecurity

[![LinkedIn](https://img.shields.io/badge/LinkedIn-pier--orlandini--1112p-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/pier-orlandini-1112p)
[![GitHub](https://img.shields.io/badge/GitHub-orlandini01-181717?style=flat&logo=github)](https://github.com/orlandini01)

---

## 📄 Licença

MIT © 2024 Pier Orlandini — Veja [LICENSE](LICENSE) para detalhes.

---

<div align="center">
<sub>Feito com 🛡️ e Python · CyberGuard AI v1.0</sub>
</div>
