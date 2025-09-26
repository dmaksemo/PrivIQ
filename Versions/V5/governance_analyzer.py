# governance_analyzer.py

import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import pandas as pd
import re

import httpx
from pydantic import ValidationError

try:
    from openai import AzureOpenAI
except ImportError:
    AzureOpenAI = None

from config import config
from models import EnhancedAIAnalysisResult, DetailedFinding, GovernanceViolationType, ComplianceFramework, RiskLevel
from data_processor import AzureLogProcessor

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class AdvancedGovernanceAnalyzer:
    """Analisador avançado de governança Azure com IA e análises especializadas."""
    
    def __init__(self):
        """Inicializa o analisador com cliente OpenAI e processador de dados."""
        self.client = None
        self.processor = AzureLogProcessor()
        
        # Configurações de compliance
        self.compliance_frameworks = {
            ComplianceFramework.SOX: {
                "critical_roles": ["Global Administrator", "Privileged Role Administrator"],
                "max_admin_roles": 2,
                "segregation_rules": [
                    ("Global Administrator", "Security Administrator"),
                    ("User Administrator", "Privileged Role Administrator")
                ]
            },
            ComplianceFramework.NIST: {
                "access_review_days": 90,
                "privileged_session_timeout": 4,
                "mfa_required_roles": ["Global Administrator", "Security Administrator"]
            },
            ComplianceFramework.ISO27001: {
                "max_failed_attempts": 5,
                "account_lockout_duration": 30,
                "password_policy_compliance": True
            }
        }
        
        # Padrões suspeitos avançados
        self.suspicious_patterns = {
            "mass_role_assignment": {"threshold": 10, "timeframe_minutes": 30},
            "privilege_escalation": {"roles": ["Global Administrator", "Privileged Role Administrator"]},
            "unusual_locations": {"threshold": 3, "timeframe_hours": 24},
            "dormant_account_activation": {"inactive_days": 90}
        }
        
        if AzureOpenAI and config.is_openai_configured():
            try:
                http_client = httpx.Client(verify=True, timeout=180.0)
                self.client = AzureOpenAI(
                    api_key=config.openai_api_key,
                    api_version=config.openai_api_version,
                    azure_endpoint=config.openai_endpoint,
                    http_client=http_client
                )
                logger.info("Cliente AzureOpenAI inicializado com sucesso.")
            except Exception as e:
                logger.error(f"Falha ao inicializar AzureOpenAI: {e}")

    def perform_comprehensive_analysis(self, logs: List[Dict[str, Any]]) -> EnhancedAIAnalysisResult:
        """Executa análise abrangente de governança com IA e regras customizadas."""
        
        if not logs:
            return self._create_error_result("Nenhum log foi fornecido para análise.")
        
        logger.info(f"Iniciando análise abrangente de governança para {len(logs)} logs.")
        
        # Processa logs e executa análises especializadas
        logs_json = json.dumps(logs, default=str)
        self.processor.logs_df = self.processor.load_logs_from_file(logs_json)
        
        # Análises especializadas
        rule_based_findings = self._perform_rule_based_analysis()
        
        if self.client:
            # Análise com IA
            ai_findings = self._perform_ai_analysis(logs)
            all_findings = rule_based_findings + ai_findings.findings
        else:
            all_findings = rule_based_findings
            logger.warning("Análise limitada - OpenAI não disponível")
        
        # Consolida resultados
        return self._consolidate_analysis_results(all_findings, logs)
    
    def _perform_rule_based_analysis(self) -> List[DetailedFinding]:
        """Executa análises baseadas em regras de governança."""
        findings = []
        
        # 1. Análise de Violações SOD
        findings.extend(self._analyze_sod_violations())
        
        # 2. Análise de Atribuições Diretas
        findings.extend(self._analyze_direct_assignments())
        
        # 3. Análise de Privilégios Excessivos
        findings.extend(self._analyze_excessive_privileges())
        
        # 4. Análise de Grupos Duplicados
        findings.extend(self._analyze_duplicate_groups())
        
        # 5. Análise de Padrões Suspeitos
        findings.extend(self._analyze_suspicious_patterns())
        
        # 6. Análise de Compliance
        findings.extend(self._analyze_compliance_violations())
        
        return findings
    
    def _analyze_sod_violations(self) -> List[DetailedFinding]:
        """Detecta violações de segregação de funções."""
        findings = []
        
        if self.processor.role_assignments_df is None or self.processor.role_assignments_df.empty:
            return findings
        
        user_roles = defaultdict(set)
        
        # Agrupa roles por usuário
        for _, row in self.processor.role_assignments_df.iterrows():
            user = row.get('user_principal_name')
            role = row.get('role_name', row.get('role_definition_name', ''))
            if user and role:
                user_roles[user].add(role)
        
        # Verifica violações SOD para cada framework
        for framework, config_rules in self.compliance_frameworks.items():
            if "segregation_rules" in config_rules:
                for role1, role2 in config_rules["segregation_rules"]:
                    for user, roles in user_roles.items():
                        if role1 in roles and role2 in roles:
                            finding = DetailedFinding(
                                risk_level=RiskLevel.CRITICAL,
                                violation_type=GovernanceViolationType.SOD_VIOLATION,
                                title=f"Violação SOD Crítica: {role1} + {role2}",
                                description=f"Usuário {user} possui roles conflitantes {role1} e {role2}, "
                                           f"violando princípios de segregação de funções do {framework.value}.",
                                recommendation=f"Remover uma das roles conflitantes do usuário {user}. "
                                              f"Implementar aprovação de múltiplas pessoas para roles administrativas.",
                                affected_principals=[user],
                                evidence={
                                    "conflicting_roles": [role1, role2],
                                    "framework": framework.value,
                                    "all_user_roles": list(roles)
                                },
                                compliance_impact=[framework],
                                remediation_priority=1,
                                business_impact="Alto risco de fraude, violação de controles internos e não conformidade regulatória.",
                                detection_timestamp=datetime.now().isoformat()
                            )
                            findings.append(finding)
        
        return findings
    
    def _analyze_direct_assignments(self) -> List[DetailedFinding]:
        """Analisa atribuições diretas de roles (não via grupos)."""
        findings = []
        
        direct_analysis = self.processor.analyze_direct_user_assignments()
        
        if direct_analysis['total_count'] > 0:
            privileged_count = direct_analysis.get('privileged_count', 0)
            risk_level = RiskLevel.HIGH if privileged_count > 5 else RiskLevel.MEDIUM
            
            affected_users = [assign['user'] for assign in direct_analysis['direct_assignments']]
            
            finding = DetailedFinding(
                risk_level=risk_level,
                violation_type=GovernanceViolationType.DIRECT_ASSIGNMENT,
                title=f"Atribuições Diretas Detectadas: {direct_analysis['total_count']} usuários",
                description=f"Identificadas {direct_analysis['total_count']} atribuições diretas de roles, "
                           f"sendo {privileged_count} roles privilegiadas. Atribuições diretas violam "
                           f"boas práticas de governança e dificultam auditoria e gestão de acesso.",
                recommendation="Migrar atribuições diretas para grupos de segurança. Implementar "
                              "política que proíba atribuições diretas exceto em casos emergenciais.",
                affected_principals=affected_users[:20],  # Limita para não sobrecarregar
                evidence={
                    "total_direct_assignments": direct_analysis['total_count'],
                    "privileged_assignments": privileged_count,
                    "assignment_details": direct_analysis['direct_assignments'][:10]
                },
                compliance_impact=[ComplianceFramework.SOX, ComplianceFramework.ISO27001],
                remediation_priority=2,
                business_impact="Dificuldade de auditoria, risco de acesso não autorizado e violação de políticas de governança.",
                detection_timestamp=datetime.now().isoformat()
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_excessive_privileges(self) -> List[DetailedFinding]:
        """Identifica usuários com privilégios excessivos."""
        findings = []
        
        if self.processor.role_assignments_df is None or self.processor.role_assignments_df.empty:
            return findings
        
        user_roles = defaultdict(set)
        
        for _, row in self.processor.role_assignments_df.iterrows():
            user = row.get('user_principal_name')
            role = row.get('role_name', row.get('role_definition_name', ''))
            if user and role:
                user_roles[user].add(role)
        
        excessive_users = []
        for user, roles in user_roles.items():
            privileged_count = len([r for r in roles if r in self.processor.privileged_roles])
            if privileged_count > 2:  # Threshold configurável
                excessive_users.append({
                    'user': user,
                    'privileged_roles': privileged_count,
                    'roles': list(roles & self.processor.privileged_roles)
                })
        
        if excessive_users:
            risk_level = RiskLevel.HIGH if any(u['privileged_roles'] > 4 for u in excessive_users) else RiskLevel.MEDIUM
            
            finding = DetailedFinding(
                risk_level=risk_level,
                violation_type=GovernanceViolationType.EXCESSIVE_PRIVILEGES,
                title=f"Privilégios Excessivos: {len(excessive_users)} usuários afetados",
                description=f"Identificados {len(excessive_users)} usuários com privilégios excessivos. "
                           f"Usuários com múltiplas roles administrativas aumentam o risco de abuso "
                           f"de privilégios e violação do princípio de menor privilégio.",
                recommendation="Revisar necessidade de cada role administrativa. Implementar "
                              "Just-In-Time access para roles privilegiadas. Definir limite máximo "
                              "de roles administrativas por usuário.",
                affected_principals=[u['user'] for u in excessive_users],
                evidence={
                    "excessive_users": excessive_users,
                    "average_roles_per_user": sum(u['privileged_roles'] for u in excessive_users) / len(excessive_users)
                },
                compliance_impact=[ComplianceFramework.NIST, ComplianceFramework.ISO27001],
                remediation_priority=2,
                business_impact="Risco elevado de abuso de privilégios e violação de controles de acesso.",
                detection_timestamp=datetime.now().isoformat()
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_duplicate_groups(self) -> List[DetailedFinding]:
        """Identifica grupos com permissões duplicadas."""
        findings = []
        
        duplicate_analysis = self.processor.analyze_duplicate_group_permissions()
        
        if duplicate_analysis['total_duplicates'] > 0:
            duplicates = duplicate_analysis['duplicates']
            
            finding = DetailedFinding(
                risk_level=RiskLevel.MEDIUM,
                violation_type=GovernanceViolationType.DUPLICATE_GROUPS,
                title=f"Grupos Duplicados: {duplicate_analysis['total_duplicates']} conjuntos encontrados",
                description=f"Identificados {duplicate_analysis['total_duplicates']} conjuntos de grupos "
                           f"com permissões idênticas, afetando {duplicate_analysis['affected_groups']} grupos. "
                           f"Grupos duplicados criam complexidade desnecessária e risco de inconsistências.",
                recommendation="Consolidar grupos duplicados em um único grupo. Implementar "
                              "processo de revisão antes da criação de novos grupos. Estabelecer "
                              "nomenclatura padrão para grupos.",
                affected_principals=[group for duplicate in duplicates for group in duplicate['groups']],
                evidence={
                    "duplicate_sets": duplicates,
                    "total_affected_groups": duplicate_analysis['affected_groups']
                },
                compliance_impact=[ComplianceFramework.ISO27001],
                remediation_priority=3,
                business_impact="Complexidade de gestão, risco de inconsistências em permissões e dificuldade de auditoria.",
                detection_timestamp=datetime.now().isoformat()
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_suspicious_patterns(self) -> List[DetailedFinding]:
        """Detecta padrões de acesso suspeitos."""
        findings = []
        
        critical_patterns = self.processor.analyze_critical_access_patterns()
        
        for pattern in critical_patterns.get('critical_patterns', []):
            if pattern['type'] == 'MULTIPLE_IP_ADDRESSES':
                finding = DetailedFinding(
                    risk_level=RiskLevel.HIGH,
                    violation_type=GovernanceViolationType.SUSPICIOUS_ACCESS,
                    title="Múltiplos IPs por Usuário Detectados",
                    description=f"Usuários acessando de múltiplos endereços IP, indicando possível "
                               f"compartilhamento de credenciais ou comprometimento de conta.",
                    recommendation="Investigar usuários com múltiplos IPs. Implementar alertas "
                                  "para acessos de localizações incomuns. Considerar MFA adicional.",
                    affected_principals=[u['user'] for u in pattern['users']],
                    evidence={"multiple_ip_users": pattern['users']},
                    compliance_impact=[ComplianceFramework.NIST],
                    remediation_priority=2,
                    business_impact="Risco de comprometimento de contas e acesso não autorizado.",
                    detection_timestamp=datetime.now().isoformat()
                )
                findings.append(finding)
            
            elif pattern['type'] == 'EXCESSIVE_FAILED_ATTEMPTS':
                finding = DetailedFinding(
                    risk_level=RiskLevel.HIGH,
                    violation_type=GovernanceViolationType.SUSPICIOUS_ACCESS,
                    title="Tentativas Excessivas de Login Falharam",
                    description=f"Detectadas tentativas excessivas de login para múltiplos usuários, "
                               f"indicando possível ataque de força bruta ou tentativa de comprometimento.",
                    recommendation="Implementar bloqueio de conta após falhas consecutivas. "
                                  "Monitorar IPs com tentativas excessivas. Revisar logs de segurança.",
                    affected_principals=[u['user'] for u in pattern['users']],
                    evidence={"failed_attempts": pattern['users']},
                    compliance_impact=[ComplianceFramework.NIST, ComplianceFramework.ISO27001],
                    remediation_priority=1,
                    business_impact="Risco de comprometimento de contas através de ataques de força bruta.",
                    detection_timestamp=datetime.now().isoformat()
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_compliance_violations(self) -> List[DetailedFinding]:
        """Analisa violações específicas de frameworks de compliance."""
        findings = []
        
        # Análise SOX - Controles de acesso financeiro
        sox_violations = self._check_sox_compliance()
        findings.extend(sox_violations)
        
        # Análise NIST - Controles de segurança
        nist_violations = self._check_nist_compliance()
        findings.extend(nist_violations)
        
        return findings
    
    def _check_sox_compliance(self) -> List[DetailedFinding]:
        """Verifica compliance com SOX (Sarbanes-Oxley)."""
        findings = []
        
        if self.processor.role_assignments_df is None:
            return findings
        
        # Verifica se há muitos administradores globais (risco SOX)
        global_admins = self.processor.role_assignments_df[
            self.processor.role_assignments_df['role_name'].str.contains('Global Administrator', na=False)
        ]['user_principal_name'].nunique()
        
        if global_admins > 3:  # Threshold configurável
            finding = DetailedFinding(
                risk_level=RiskLevel.HIGH,
                violation_type=GovernanceViolationType.COMPLIANCE_VIOLATION,
                title="Violação SOX: Excesso de Administradores Globais",
                description=f"Identificados {global_admins} administradores globais, excedendo "
                           f"as boas práticas SOX que recomendam máximo de 2-3 administradores.",
                recommendation="Reduzir número de administradores globais. Implementar roles "
                              "mais específicas. Estabelecer processo de aprovação rigoroso.",
                affected_principals=[],
                evidence={"global_admin_count": global_admins},
                compliance_impact=[ComplianceFramework.SOX],
                remediation_priority=1,
                business_impact="Violação de controles SOX, risco de auditoria e penalidades regulatórias.",
                detection_timestamp=datetime.now().isoformat()
            )
            findings.append(finding)
        
        return findings
    
    def _check_nist_compliance(self) -> List[DetailedFinding]:
        """Verifica compliance com NIST Cybersecurity Framework."""
        findings = []
        
        # Placeholder para análises NIST específicas
        # Pode incluir verificações de MFA, políticas de senha, etc.
        
        return findings
    
    def _perform_ai_analysis(self, logs: List[Dict[str, Any]]) -> EnhancedAIAnalysisResult:
        """Executa análise com IA para padrões complexos."""
        if not self.client:
            return self._create_error_result("Cliente OpenAI não disponível.")
        
        governance_summary = self.processor.generate_comprehensive_summary()
        prompt = self._build_advanced_prompt(logs, governance_summary)
        
        try:
            response = self.client.chat.completions.create(
                model=config.openai_deployment_name,
                messages=[
                    {"role": "system", "content": self._get_advanced_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=6000,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            
            ai_output = response.choices[0].message.content
            
            # Corrige formatos antes da validação
            ai_output = self._fix_ai_response_format(ai_output)
            
            validated_result = EnhancedAIAnalysisResult.model_validate_json(ai_output)
            logger.info("Análise avançada de IA validada com sucesso.")
            return validated_result

        except ValidationError as e:
            logger.error(f"Erro de validação na análise avançada: {e}")
            return self._create_error_result(
                "A IA retornou dados em formato inesperado para análise avançada.",
                raw_response=ai_output if 'ai_output' in locals() else None
            )
        except Exception as e:
            logger.error(f"Erro na análise avançada: {str(e)}")
            return self._create_error_result(f"Falha na comunicação com a API: {e}")
    
    def _fix_ai_response_format(self, ai_output: str) -> str:
        """Corrige formatos comuns de erro na resposta da IA."""
        import re
        
        # Corrige valores de risk_level para o formato correto
        ai_output = re.sub(r'"risk_level":\s*"CRITICAL"', '"risk_level": "Critical"', ai_output)
        ai_output = re.sub(r'"risk_level":\s*"HIGH"', '"risk_level": "High"', ai_output)
        ai_output = re.sub(r'"risk_level":\s*"MEDIUM"', '"risk_level": "Medium"', ai_output)
        ai_output = re.sub(r'"risk_level":\s*"LOW"', '"risk_level": "Low"', ai_output)
        
        # Corrige violation_type para o formato correto
        ai_output = re.sub(r'"violation_type":\s*"SOD_VIOLATION"', '"violation_type": "SOD_Violation"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"DIRECT_ASSIGNMENT"', '"violation_type": "Direct_Assignment"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"EXCESSIVE_PRIVILEGES"', '"violation_type": "Excessive_Privileges"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"DUPLICATE_GROUPS"', '"violation_type": "Grupos"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"SUSPICIOUS_ACCESS"', '"violation_type": "Suspicious_Access"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"ORPHANED_ACCOUNTS"', '"violation_type": "Orphaned_Accounts"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"PRIVILEGE_ESCALATION"', '"violation_type": "Privilege_Escalation"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"COMPLIANCE_VIOLATION"', '"violation_type": "Compliance_Violation"', ai_output)
        
        return ai_output
    
    def _get_advanced_system_prompt(self) -> str:
        """Sistema prompt especializado para análise avançada."""
        return """Você é um Expert Global em Governança de Identidade e Compliance Regulatório para Microsoft Azure e Entra ID, com certificações CISSP, CISA e especialização em frameworks SOX, NIST, ISO27001, GDPR e PCI-DSS.

EXPERTISE TÉCNICA:
- Análise forense de logs de auditoria Azure/Entra ID
- Detecção de padrões complexos de violação de governança
- Correlação de eventos para identificação de ameaças internas
- Avaliação de riscos de compliance multi-framework
- Análise comportamental de usuários privilegiados

FOCO PRINCIPAL:
1. VIOLAÇÕES CRÍTICAS DE SOD - Detectar combinações perigosas de roles
2. AMEAÇAS INTERNAS - Identificar comportamentos anômalos de usuários
3. ESCALAÇÃO DE PRIVILÉGIOS - Padrões de aumento não autorizado de acesso
4. COMPLIANCE GAPS - Lacunas que violam frameworks regulatórios
5. ANOMALIAS COMPORTAMENTAIS - Padrões suspeitos baseados em ML insights

METODOLOGIA:
- Use análise contextual profunda, não apenas regras superficiais
- Correlacione eventos temporalmente para identificar campanhas de ataque
- Considere impactos de negócio e regulatórios específicos
- Priorize achados baseados em risco real vs. teórico
- Forneça evidências forenses detalhadas

Seja técnico, forense e foque em insights que apenas IA pode detectar."""
    
    def _build_advanced_prompt(self, logs: List[Dict[str, Any]], governance_summary: Dict[str, Any]) -> str:
        """Constrói prompt avançado para análise de IA."""
        schema_example = EnhancedAIAnalysisResult.model_json_schema()
        limited_logs = logs[:300] if len(logs) > 300 else logs
        
        return f"""
# ANÁLISE FORENSE AVANÇADA - GOVERNANÇA AZURE/ENTRA ID

## CONTEXTO EMPRESARIAL
- Análise de {len(logs)} eventos de auditoria
- Timeframe: {governance_summary.get('time_range', {})}
- Usuários únicos: {governance_summary.get('unique_users', 'N/A')}

## DASHBOARD DE GOVERNANÇA ATUAL
```json
{json.dumps(governance_summary.get('governance_issues', {}), indent=2)}
```

## ANÁLISES ESPECIALIZADAS EXECUTADAS

### VIOLAÇÕES SOD DETECTADAS (REGRAS)
```json
{json.dumps(governance_summary.get('detailed_analysis', {}).get('conflicts', {}), indent=2, default=str)[:1500]}
```

### PADRÕES CRÍTICOS IDENTIFICADOS
```json
{json.dumps(governance_summary.get('detailed_analysis', {}).get('critical_patterns', {}), indent=2, default=str)[:1500]}
```

### DADOS FORENSES (AMOSTRA)
```json
{json.dumps(limited_logs, indent=2, default=str)[:4000]}
```

---

**TAREFA FORENSE**: Realize análise de IA avançada focada em:

1. **CORRELAÇÃO TEMPORAL** - Identifique sequências suspeitas de eventos
2. **ANÁLISE COMPORTAMENTAL** - Detecte desvios de padrões normais de usuário  
3. **THREAT HUNTING** - Procure indicadores de ameaças internas
4. **COMPLIANCE FORENSICS** - Evidências de violações regulatórias
5. **BUSINESS IMPACT** - Quantifique riscos reais para o negócio

**FORMATO OBRIGATÓRIO**: Retorne apenas JSON válido seguindo o schema EXATO:

**VALORES PERMITIDOS**:
- risk_level: DEVE ser exatamente "Critical", "High", "Medium" ou "Low" (case-sensitive)
- violation_type: DEVE ser exatamente "SOD_Violation", "Direct_Assignment", "Excessive_Privileges", "Duplicate_Groups", "Suspicious_Access", "Orphaned_Accounts", "Privilege_Escalation" ou "Compliance_Violation"

**CAMPOS OBRIGATÓRIOS para cada finding**:
- title: string (título curto do achado)
- description: string (descrição técnica detalhada)
- recommendation: string (ação específica de remediação)
- risk_level: enum correto
- violation_type: enum correto

**CAMPOS OBRIGATÓRIOS para risk_assessment**:
- score: número inteiro 0-100
- summary: string (resumo executivo)
- governance_metrics: objeto com métricas

**CAMPOS OBRIGATÓRIOS no root**:
- executive_summary: string (resumo para executivos)
- technical_summary: string (resumo técnico)

**EXEMPLO DE ESTRUTURA**:
{{
    "risk_assessment": {{
        "score": 75,
        "summary": "Alto risco identificado...",
        "governance_metrics": {{
            "total_users": 50,
            "direct_assignments": 5,
            "sod_violations": 3
        }}
    }},
    "findings": [
        {{
            "risk_level": "Critical",
            "violation_type": "SOD_Violation",
            "title": "Usuário com roles conflitantes",
            "description": "Análise detalhada...",
            "recommendation": "Remover role X do usuário Y",
            "affected_principals": ["user@domain.com"],
            "evidence": {{}},
            "compliance_impact": ["SOX"],
            "remediation_priority": 1,
            "business_impact": "Impacto alto..."
        }}
    ],
    "executive_summary": "Resumo executivo claro...",
    "technical_summary": "Resumo técnico detalhado...",
    "next_actions": ["Ação 1", "Ação 2"],
    "analysis_metadata": {{}}
}}

**REQUISITOS CRÍTICOS**:
- Use EXATAMENTE os valores dos enums mostrados acima
- Todos os campos obrigatórios devem estar presentes
- JSON deve ser válido e parseável
- Priorize descobertas que análise por regras não detectaria
- Forneça evidências forenses concretas
"""
    
    def _consolidate_analysis_results(self, findings: List[DetailedFinding], logs: List[Dict[str, Any]]) -> EnhancedAIAnalysisResult:
        """Consolida resultados de múltiplas análises."""
        
        # Calcula métricas de governança
        governance_summary = self.processor.generate_comprehensive_summary()
        governance_metrics = self._calculate_governance_metrics(governance_summary)
        
        # Calcula score de risco baseado nos achados
        risk_score = self._calculate_consolidated_risk_score(findings)
        
        # Gera assessment de compliance - Avaliação de Conformidade
        compliance_assessment = self._generate_compliance_assessment(findings)
        
        # Cria assessment de risco consolidado
        risk_assessment = {
            "score": risk_score,
            "summary": self._generate_risk_summary(findings, risk_score),
            "governance_metrics": governance_metrics,
            "compliance_assessment": compliance_assessment
        }
        
        # Gera próximas ações baseadas nos achados
        next_actions = self._generate_next_actions(findings)
        
        return EnhancedAIAnalysisResult(
            risk_assessment=risk_assessment,
            findings=findings,
            executive_summary=self._generate_executive_summary(findings, risk_score),
            technical_summary=self._generate_technical_summary(findings),
            next_actions=next_actions,
            analysis_metadata={
                "total_logs_analyzed": len(logs),
                "analysis_timestamp": datetime.now().isoformat(),
                "findings_count": len(findings),
                "critical_findings": len([f for f in findings if f.risk_level == RiskLevel.CRITICAL]),
                "high_findings": len([f for f in findings if f.risk_level == RiskLevel.HIGH])
            }
        )
    
    def _calculate_governance_metrics(self, governance_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Calcula métricas específicas de governança."""
        issues = governance_summary.get('governance_issues', {})
        
        return {
            "total_users": governance_summary.get('unique_users', 0),
            "direct_assignments": issues.get('direct_assignments', 0),
            "sod_violations": issues.get('sod_violations', 0),
            "excessive_privilege_users": 0,  # Calculado durante análise
            "duplicate_groups": issues.get('duplicate_groups', 0),
            "suspicious_activities": issues.get('critical_patterns', 0),
            "compliance_score": max(0, 100 - (issues.get('sod_violations', 0) * 20) - 
                                   (issues.get('direct_assignments', 0) * 2))
        }
    
    def _calculate_consolidated_risk_score(self, findings: List[DetailedFinding]) -> int:
        """Calcula score de risco consolidado baseado nos achados."""
        if not findings:
            return 0
        
        weights = {
            RiskLevel.CRITICAL: 40,
            RiskLevel.HIGH: 25,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5
        }
        
        total_weight = sum(weights[finding.risk_level] for finding in findings)
        # Normaliza para escala 0-100
        return min(100, total_weight)
    
    def _generate_compliance_assessment(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Gera assessment de compliance - Avaliação de Conformidade baseado nos achados."""
        framework_violations = defaultdict(int)
        
        for finding in findings:
            for framework in finding.compliance_impact:
                framework_violations[framework.value] += 1
        
        framework_scores = {}
        for framework in ComplianceFramework:
            violations = framework_violations.get(framework.value, 0)
            score = max(0, 100 - (violations * 15))  # Cada violação reduz 15 pontos
            framework_scores[framework.value] = score
        
        overall_score = sum(framework_scores.values()) / len(framework_scores) if framework_scores else 100
        
        return {
            "overall_score": overall_score,
            "framework_scores": framework_scores,
            "critical_gaps": [f.title for f in findings if f.risk_level == RiskLevel.CRITICAL],
            "recommendations": [f.recommendation for f in findings[:5]]  # Top 5 recomendações
        }
    
    def _generate_risk_summary(self, findings: List[DetailedFinding], risk_score: int) -> str:
        """Gera resumo executivo do risco."""
        critical_count = len([f for f in findings if f.risk_level == RiskLevel.CRITICAL])
        high_count = len([f for f in findings if f.risk_level == RiskLevel.HIGH])
        
        if risk_score >= 80:
            level = "CRÍTICO"
        elif risk_score >= 60:
            level = "ALTO"
        elif risk_score >= 40:
            level = "MÉDIO"
        else:
            level = "BAIXO"
        
        return (f"Score de Risco: {risk_score}/100 (Nível {level}). "
                f"Identificados {critical_count} achados críticos e {high_count} de alto risco. "
                f"Ação imediata necessária para violações SOD e compliance.")
    
    def _generate_executive_summary(self, findings: List[DetailedFinding], risk_score: int) -> str:
        """Gera resumo executivo para liderança."""
        critical_findings = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        
        summary = f"POSTURA DE GOVERNANÇA: Risco {risk_score}/100. "
        
        if critical_findings:
            summary += f"AÇÃO IMEDIATA NECESSÁRIA: {len(critical_findings)} violações críticas detectadas, "
            summary += "incluindo violações SOD que podem impactar compliance regulatório. "
        
        summary += "Recomenda-se revisão completa de permissões e implementação de controles adicionais."
        
        return summary
    
    def _generate_technical_summary(self, findings: List[DetailedFinding]) -> str:
        """Gera resumo técnico para equipe de TI."""
        violation_types = Counter(f.violation_type.value for f in findings)
        
        summary = f"ANÁLISE TÉCNICA: {len(findings)} achados identificados. "
        summary += "Tipos principais: " + ", ".join([f"{k}: {v}" for k, v in violation_types.most_common(3)])
        summary += ". Priorizar remediação de violações SOD e atribuições diretas."
        
        return summary
    
    def _generate_next_actions(self, findings: List[DetailedFinding]) -> List[str]:
        """Gera lista de próximas ações baseada nos achados."""
        actions = []
        
        # Prioriza ações baseadas na severidade e tipo
        critical_findings = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        
        if critical_findings:
            actions.append("1. IMEDIATO: Revisar e remediar violações críticas de SOD identificadas")
        
        sod_violations = [f for f in findings if f.violation_type == GovernanceViolationType.SOD_VIOLATION]
        if sod_violations:
            actions.append("2. Implementar controles para prevenir futuras violações de segregação de funções")
        
        direct_assignments = [f for f in findings if f.violation_type == GovernanceViolationType.DIRECT_ASSIGNMENT]
        if direct_assignments:
            actions.append("3. Migrar atribuições diretas para modelo baseado em grupos")
        
        actions.append("4. Estabelecer processo de revisão periódica de permissões (trimestral)")
        actions.append("5. Implementar monitoramento contínuo para detecção de anomalias")
        
        return actions[:10]  # Limita a 10 ações
    
    def _create_error_result(self, error_message: str, raw_response: str = None) -> EnhancedAIAnalysisResult:
        """Cria resultado de erro para análise avançada."""
        desc = f"Erro na Análise Avançada: {error_message}"
        if raw_response:
            desc += f"\n\nResposta recebida: {raw_response[:500]}..."

        error_finding = DetailedFinding(
            risk_level=RiskLevel.CRITICAL,
            violation_type=GovernanceViolationType.COMPLIANCE_VIOLATION,
            title="Falha Crítica na Análise Avançada de Governança",
            description=desc,
            recommendation="Verifique a configuração do Azure OpenAI e conectividade. "
                          "Consulte logs da aplicação para diagnóstico detalhado.",
            affected_principals=[],
            evidence={"error": error_message},
            compliance_impact=[],
            remediation_priority=1,
            business_impact="Impossibilidade de análise completa de governança.",
            detection_timestamp=datetime.now().isoformat()
        )
        
        return EnhancedAIAnalysisResult(
            risk_assessment={
                "score": 100,
                "summary": "Análise avançada de governança não pôde ser concluída devido a erro crítico.",
                "governance_metrics": {
                    "total_users": 0,
                    "direct_assignments": 0,
                    "sod_violations": 0,
                    "excessive_privilege_users": 0,
                    "duplicate_groups": 0,
                    "suspicious_activities": 0,
                    "compliance_score": 0
                }
            },
            findings=[error_finding],
            executive_summary="Falha crítica no sistema de análise. Intervenção técnica necessária.",
            technical_summary="Sistema de análise avançada indisponível. Verificar configurações e logs.",
            next_actions=["Verificar configuração Azure OpenAI", "Revisar logs de erro", "Contactar suporte técnico"],
            analysis_metadata={
                "error": True,
                "error_message": error_message,
                "timestamp": datetime.now().isoformat()
            }
        )