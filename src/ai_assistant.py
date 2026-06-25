"""
ai_assistant.py — Explicações de incidentes via IA.

Modo OFFLINE: templates inteligentes (sem API, sempre disponível)
Modo ONLINE:  Claude API (requer ANTHROPIC_API_KEY no .env)
"""

import os
from src.utils import has_api_key

INCIDENT_LABELS = {
    "BRUTE_FORCE":           "Ataque de Força Bruta",
    "SUCCESS_AFTER_FAILURE": "Login Bem-sucedido Após Múltiplas Falhas",
    "OFF_HOURS_ACCESS":      "Acesso em Horário Incomum",
    "SUSPICIOUS_IP":         "Comportamento Suspeito de IP",
    "USER_ENUMERATION":      "Enumeração de Usuários",
    "PRIVILEGED_ACCESS":     "Acesso Privilegiado Suspeito",
}

# ─── Ponto de entrada ─────────────────────────────────────────

def explain_incident(incident: dict) -> str:
    """
    Gera explicação de um incidente em linguagem simples.

    Seleciona automaticamente modo online (Claude API) ou offline (templates).
    """
    if has_api_key():
        try:
            return _explain_via_api(incident)
        except Exception as e:
            return _explain_offline(incident) + f"\n\n_(Modo offline — erro na API: {e})_"
    return _explain_offline(incident)


def get_recommendations(incident_type: str) -> list[dict]:
    """Retorna lista de recomendações de mitigação por tipo de incidente."""
    return RECOMMENDATIONS.get(incident_type, RECOMMENDATIONS["DEFAULT"])


# ─── Modo ONLINE — Claude API ────────────────────────────────

def _explain_via_api(incident: dict) -> str:
    """Gera explicação usando a Claude API."""
    import anthropic

    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    inc_type = incident.get("incident_type", "")
    label    = INCIDENT_LABELS.get(inc_type, inc_type)
    sev      = incident.get("severity", "").upper()
    score    = incident.get("risk_score", 0)
    ip       = incident.get("source_ip", "")
    user     = incident.get("target_user", "")
    count    = incident.get("event_count", 0)
    desc     = incident.get("description", "")
    first    = str(incident.get("first_seen", ""))
    last     = str(incident.get("last_seen", ""))

    prompt = f"""Você é um analista sênior de cibersegurança. Explique o seguinte incidente de segurança 
em linguagem clara e objetiva para um gestor de TI (não técnico).

INCIDENTE DETECTADO:
- Tipo: {label}
- Severidade: {sev} (Score: {score}/100)
- IP de origem: {ip}
- Usuário alvo: {user}
- Total de eventos: {count}
- Período: {first} → {last}
- Descrição técnica: {desc}

Estruture sua resposta em 3 parágrafos curtos:
1. O QUE ACONTECEU (explique o incidente em linguagem simples, sem jargão)
2. POR QUE É PERIGOSO (impacto potencial para o negócio)
3. O QUE FAZER AGORA (ação imediata recomendada)

Seja direto, use no máximo 150 palavras no total. Escreva em português brasileiro."""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text


# ─── Modo OFFLINE — Templates inteligentes ───────────────────

def _explain_offline(incident: dict) -> str:
    """Gera explicação via templates baseados no tipo e contexto do incidente."""
    inc_type = incident.get("incident_type", "")
    sev      = incident.get("severity", "low")
    score    = incident.get("risk_score", 0)
    ip       = incident.get("source_ip", "IP desconhecido")
    user     = incident.get("target_user", "usuário desconhecido")
    count    = incident.get("event_count", 0)
    first    = incident.get("first_seen")
    last     = incident.get("last_seen")

    ts_first = first.strftime("%d/%m/%Y às %H:%M") if hasattr(first, "strftime") else str(first)
    ts_last  = last.strftime("%d/%m/%Y às %H:%M")  if hasattr(last,  "strftime") else str(last)

    sev_context = {
        "critical": "extremamente grave e requer ação imediata",
        "high":     "grave e deve ser tratado com urgência",
        "medium":   "moderado e deve ser investigado em breve",
        "low":      "de baixo risco, mas deve ser monitorado",
    }.get(sev, "significativo")

    templates = {
        "BRUTE_FORCE": f"""**O QUE ACONTECEU**
O sistema detectou um ataque de força bruta: o endereço IP `{ip}` realizou **{count} tentativas consecutivas** de acesso à conta `{user}` entre {ts_first} e {ts_last}. Esse tipo de ataque tenta adivinhar a senha testando muitas combinações em sequência.

**POR QUE É PERIGOSO**
Se o atacante descobrir a senha, terá acesso completo à conta `{user}` e a todos os dados e sistemas aos quais ela tem permissão. Este incidente é classificado como **{sev_context}** (score {score}/100).

**O QUE FAZER AGORA**
1. Bloquear imediatamente o IP `{ip}` no firewall
2. Verificar se a conta `{user}` foi comprometida
3. Ativar bloqueio automático após 5 tentativas falhas (fail2ban)
4. Considerar autenticação multifator (MFA) para todas as contas""",

        "SUCCESS_AFTER_FAILURE": f"""**O QUE ACONTECEU**
O sistema detectou um padrão altamente suspeito: após **{count - 1} tentativas de login malsucedidas**, houve um login **bem-sucedido** na conta `{user}` a partir do IP `{ip}` em {ts_last}. Isso pode indicar que a senha foi descoberta ou vazada.

**POR QUE É PERIGOSO**
Este é o cenário mais grave — indica provável **comprometimento real da conta**. O atacante pode ter acesso ativo agora mesmo a dados sensíveis, sistemas internos e outras contas. Score: **{score}/100 ({sev_context})**.

**O QUE FAZER AGORA**
1. 🚨 Revogar imediatamente todas as sessões ativas do usuário `{user}`
2. Redefinir a senha por canal seguro (não por e-mail)
3. Auditar todas as ações realizadas após o login suspeito
4. Verificar se outros sistemas foram acessados com essas credenciais""",

        "OFF_HOURS_ACCESS": f"""**O QUE ACONTECEU**
O sistema registrou **{count} acessos** originados do IP `{ip}` fora do horário comercial, entre {ts_first} e {ts_last}. Acessos noturnos ou de fim de semana são um indicador comum de atividade maliciosa ou uso indevido de credenciais.

**POR QUE É PERIGOSO**
Acessos fora do horário normal dificultam a detecção e resposta em tempo real. Podem indicar um funcionário agindo de má-fé, credenciais roubadas sendo usadas de outro fuso horário, ou um sistema comprometido operando automaticamente. Classificado como **{sev_context}** (score {score}/100).

**O QUE FAZER AGORA**
1. Confirmar com o usuário `{user}` se o acesso era legítimo
2. Verificar a localização geográfica do IP `{ip}`
3. Implementar restrição de acesso por horário para usuários comuns
4. Configurar alertas automáticos para acessos fora do horário""",

        "SUSPICIOUS_IP": f"""**O QUE ACONTECEU**
O endereço IP `{ip}` realizou **{count} tentativas de acesso** a múltiplas contas diferentes de usuários do sistema entre {ts_first} e {ts_last}. Esse comportamento é característico de ataques de **credential stuffing** (teste de senhas vazadas) ou varredura de contas.

**POR QUE É PERIGOSO**
Atacantes frequentemente obtêm listas de usuários e senhas vazadas de outros serviços e as testam automaticamente. Mesmo que a maioria das tentativas falhe, uma única conta vulnerável é suficiente para uma invasão. Severidade: **{sev_context}** (score {score}/100).

**O QUE FAZER AGORA**
1. Bloquear o IP `{ip}` imediatamente no firewall
2. Verificar todos os usuários que esse IP tentou acessar
3. Forçar troca de senha nas contas alvo como precaução
4. Integrar listas de IPs maliciosos conhecidos ao firewall""",

        "USER_ENUMERATION": f"""**O QUE ACONTECEU**
O IP `{ip}` testou sistematicamente **{count} combinações de nomes de usuário** no sistema entre {ts_first} e {ts_last}, todas resultando em falha. Essa técnica é usada para descobrir quais contas existem antes de lançar um ataque direcionado.

**POR QUE É PERIGOSO**
Conhecer os nomes de usuário válidos é o primeiro passo de um ataque sofisticado. Com essa informação, o atacante pode lançar ataques de força bruta direcionados, phishing personalizado ou usar senhas de vazamentos anteriores. Criticidade: **{sev_context}** (score {score}/100).

**O QUE FAZER AGORA**
1. Bloquear o IP `{ip}` imediatamente
2. Alterar todas as mensagens de erro de login para "credenciais inválidas" (sem diferenciar usuário de senha)
3. Implementar rate limiting e CAPTCHA após 3 tentativas
4. Revisar se algum usuário enumerado foi posteriormente atacado""",

        "PRIVILEGED_ACCESS": f"""**O QUE ACONTECEU**
O sistema detectou atividade suspeita na conta privilegiada `{user}` a partir do IP `{ip}`: **{count} eventos** foram registrados entre {ts_first} e {ts_last}, incluindo falhas de autenticação ou acessos fora do horário esperado.

**POR QUE É PERIGOSO**
Contas como `{user}` possuem acesso elevado a sistemas críticos, dados sensíveis e configurações de segurança. Um comprometimento dessa conta pode resultar em acesso total à infraestrutura, instalação de malware ou exfiltração de dados. Nível: **{sev_context}** (score {score}/100).

**O QUE FAZER AGORA**
1. Verificar imediatamente com o responsável se o acesso era legítimo
2. Revogar sessões ativas da conta `{user}` por precaução
3. Implementar autenticação multifator obrigatória para contas privilegiadas
4. Revisar e auditar todas as ações recentes dessa conta""",
    }

    template = templates.get(inc_type)
    if template:
        return template

    # Fallback genérico
    label = INCIDENT_LABELS.get(inc_type, inc_type)
    return f"""**O QUE ACONTECEU**
O sistema detectou um incidente do tipo **{label}** envolvendo o IP `{ip}` e o usuário `{user}`. Foram registrados {count} eventos entre {ts_first} e {ts_last}.

**POR QUE É PERIGOSO**
Este incidente foi classificado como **{sev_context}** com score de risco {score}/100, indicando que requer atenção da equipe de segurança.

**O QUE FAZER AGORA**
1. Investigar os logs detalhados deste incidente
2. Verificar se o IP `{ip}` é reconhecido e legítimo
3. Confirmar com o usuário `{user}` se as atividades eram esperadas
4. Escalar para a equipe de segurança se necessário"""


# ─── Recomendações por tipo ───────────────────────────────────

RECOMMENDATIONS = {
    "BRUTE_FORCE": [
        {"priority": "immediate",  "title": "Bloquear IP no firewall",
         "description": "Adicione o IP atacante à lista de bloqueio permanente."},
        {"priority": "immediate",  "title": "Verificar se conta foi comprometida",
         "description": "Revise os logs para garantir que nenhum login foi bem-sucedido."},
        {"priority": "short_term", "title": "Ativar bloqueio automático",
         "description": "Configure fail2ban: bloqueio após 5 tentativas falhas em 10 minutos."},
        {"priority": "long_term",  "title": "Implementar MFA",
         "description": "Autenticação multifator elimina ataques de força bruta mesmo com senha comprometida."},
    ],
    "SUCCESS_AFTER_FAILURE": [
        {"priority": "immediate",  "title": "Revogar sessão imediatamente",
         "description": "Force logout e invalide todos os tokens ativos do usuário."},
        {"priority": "immediate",  "title": "Resetar senha por canal seguro",
         "description": "Redefina a senha e notifique o usuário por canal alternativo seguro."},
        {"priority": "short_term", "title": "Auditar ações pós-login",
         "description": "Revise tudo que foi feito após o login suspeito para avaliar o dano."},
        {"priority": "short_term", "title": "Alertas de padrão falha→sucesso",
         "description": "Configure notificação em tempo real para este padrão crítico."},
    ],
    "OFF_HOURS_ACCESS": [
        {"priority": "immediate",  "title": "Confirmar legitimidade com o usuário",
         "description": "Entre em contato com o usuário para verificar se o acesso era esperado."},
        {"priority": "short_term", "title": "Restringir acesso por horário",
         "description": "Implemente política de acesso apenas em horário comercial para usuários comuns."},
        {"priority": "short_term", "title": "Configurar alertas de horário",
         "description": "Notificação automática para qualquer acesso fora do horário padrão."},
    ],
    "SUSPICIOUS_IP": [
        {"priority": "immediate",  "title": "Bloquear IP suspeito",
         "description": "IP com comportamento de scanning deve ser bloqueado imediatamente."},
        {"priority": "short_term", "title": "Forçar troca de senha nas contas alvo",
         "description": "Usuários afetados devem redefinir senhas por precaução."},
        {"priority": "long_term",  "title": "Integrar threat intelligence",
         "description": "Use feeds de IPs maliciosos (AbuseIPDB) para bloqueio proativo."},
    ],
    "USER_ENUMERATION": [
        {"priority": "immediate",  "title": "Bloquear IP enumerador",
         "description": "Bloqueio imediato do IP que testou sistematicamente usernames."},
        {"priority": "short_term", "title": "Padronizar mensagens de erro",
         "description": "Retorne sempre 'credenciais inválidas', nunca diferencie user/senha."},
        {"priority": "short_term", "title": "Implementar rate limiting",
         "description": "Limite tentativas por IP e adicione CAPTCHA progressivo."},
    ],
    "PRIVILEGED_ACCESS": [
        {"priority": "immediate",  "title": "Verificar legitimidade",
         "description": "Confirme com o responsável se o acesso privilegiado era esperado."},
        {"priority": "short_term", "title": "MFA obrigatório para contas privilegiadas",
         "description": "Toda conta admin/root deve ter autenticação multifator ativo."},
        {"priority": "long_term",  "title": "Implementar PAM",
         "description": "Privileged Access Management: acesso temporário, auditado e aprovado."},
    ],
    "DEFAULT": [
        {"priority": "immediate",  "title": "Investigar o incidente",
         "description": "Revise os logs detalhados e determine o impacto potencial."},
        {"priority": "short_term", "title": "Documentar e escalar",
         "description": "Registre o incidente e notifique a equipe de segurança responsável."},
    ],
}