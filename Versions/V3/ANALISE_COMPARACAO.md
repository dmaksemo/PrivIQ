# Diferenças: Análise Padrão vs Análise Avançada de Governança

## 📊 Visão Geral

Seu sistema possui **duas engines distintas** de análise de governança Azure, cada uma com capacidades e objetivos diferentes:

---

## 🔍 **ANÁLISE PADRÃO** (`AzureLogAnalyzer`)

### 📁 **Arquivo:** `azure_log_analyzer.py`
### 🎯 **Objetivo:** Análise básica de segurança com foco em detecção de padrões

### ⚙️ **Características:**

#### **Modelo de Dados:**
- Usa `AIAnalysisResult` (modelo básico)
- Findings simples com `Finding` (4 campos básicos)
- Estrutura de risco simplificada

#### **Capacidades de Análise:**
- ✅ Detecção de padrões de segurança básicos
- ✅ Análise de logs com IA (GPT-4)
- ✅ Identificação de riscos gerais
- ✅ Relatórios padronizados

#### **Tipos de Detecção:**
- Padrões anômalos gerais
- Atividades suspeitas básicas
- Violações de segurança comuns
- Análise de comportamento superficial

#### **Saídas:**
- Dashboard básico
- Relatórios simples
- Métricas fundamentais
- Exportação JSON padrão

---

## 🚀 **ANÁLISE AVANÇADA** (`AdvancedGovernanceAnalyzer`)

### 📁 **Arquivo:** `governance_analyzer.py`
### 🎯 **Objetivo:** Análise especializada de governança com compliance

### ⚙️ **Características:**

#### **Modelo de Dados:**
- Usa `EnhancedAIAnalysisResult` (modelo expandido)
- Findings detalhados com `DetailedFinding` (12+ campos)
- Métricas de governança especializadas (`GovernanceMetric`)
- Assessment de compliance (`ComplianceAssessment`)
- Análise de tendências (`TrendAnalysis`)

#### **Capacidades Avançadas:**
- ✅ **Análise Dupla:** Regras + IA
- ✅ **6 Engines Especializadas:** SOD, Privilégios, Compliance, etc.
- ✅ **Frameworks de Compliance:** SOX, NIST, ISO27001, GDPR, HIPAA, PCI-DSS
- ✅ **Análise Preditiva:** Tendências e projeções
- ✅ **Dashboards Persona-Based:** Executivo, Analista, Compliance

#### **Engines de Análise Especializadas:**

1. **SOD Violations Engine**
   - Segregação de funções
   - Detecção de conflitos de roles
   - Matriz de incompatibilidades

2. **Direct Assignments Engine**
   - Atribuições diretas de roles
   - Bypass de grupos
   - Violações de processo

3. **Excessive Privileges Engine**
   - Análise de privilégios excessivos
   - Usuários super-privilegiados
   - Princípio do menor privilégio

4. **Duplicate Groups Engine**
   - Grupos com permissões duplicadas
   - Redundâncias de acesso
   - Otimização de estrutura

5. **Suspicious Patterns Engine**
   - Atividades suspeitas avançadas
   - Padrões de mass assignment
   - Escalação de privilégios

6. **Compliance Violations Engine**
   - Violações específicas por framework
   - Gaps de conformidade
   - Evidências regulatórias

#### **Frameworks de Compliance Suportados:**
```python
SOX: {
    "critical_roles": ["Global Administrator", "Privileged Role Administrator"],
    "max_admin_roles": 2,
    "segregation_rules": [("Global Admin", "Security Admin")]
}

NIST: {
    "access_review_days": 90,
    "privileged_session_timeout": 4,
    "mfa_required_roles": ["Global Administrator"]
}

ISO27001: {
    "max_failed_attempts": 5,
    "account_lockout_duration": 30,
    "password_policy_compliance": True
}
```

#### **Saídas Avançadas:**
- 📊 **6 Dashboards Especializados:** Executivo, Analista, Compliance, Tendências, Ações, Forense
- 📈 **Análise Preditiva:** Projeções de 30 dias com IA
- 🎯 **Centro de Ações:** Gerenciamento de remediação
- 📋 **Relatórios Regulatórios:** Para auditoria e compliance
- 📊 **Métricas de Governança:** 7+ KPIs especializados

---

## 🔄 **Comparação Técnica**

| Aspecto | Análise Padrão | Análise Avançada |
|---------|----------------|------------------|
| **Complexidade** | Básica | Avançada |
| **Frameworks** | Genérico | 6 Frameworks específicos |
| **Engines** | 1 (IA) | 6 (Regras) + 1 (IA) |
| **Modelos** | `AIAnalysisResult` | `EnhancedAIAnalysisResult` |
| **Findings** | 4 campos | 12+ campos |
| **Compliance** | Não específico | SOX, NIST, ISO27001, GDPR |
| **Predições** | Não | Sim (30 dias) |
| **Personas** | Não | 3 (Exec, Analyst, Auditor) |
| **Ações** | Básicas | Centro de Ações completo |
| **Métricas** | Básicas | 7+ KPIs especializados |

---

## 🎯 **Quando Usar Cada Uma**

### **Use Análise Padrão quando:**
- ✅ Precisa de análise rápida e básica
- ✅ Foco em detecção geral de anomalias
- ✅ Recursos limitados de processamento
- ✅ Não há requisitos específicos de compliance

### **Use Análise Avançada quando:**
- ✅ Tem requisitos específicos de compliance (SOX, NIST, etc.)
- ✅ Precisa de análise detalhada de governança
- ✅ Quer dashboards personalizados por persona
- ✅ Necessita análise preditiva e tendências
- ✅ Requer centro de ações para remediação
- ✅ Foco em auditoria e evidências regulatórias

---

## 💡 **Resumo Executivo**

A **Análise Padrão** é como um **"detector de fumaça"** - identifica problemas gerais de segurança.

A **Análise Avançada** é como um **"sistema de proteção contra incêndio completo"** - não só detecta, mas classifica, prediz, recomenda ações específicas e fornece dashboards personalizados para diferentes perfis organizacionais.

🏆 **Recomendação:** Use a **Análise Avançada** para ambientes corporativos com requisitos de compliance e governança rigorosos.