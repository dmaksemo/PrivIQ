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

class CriticalGapAnalyzer:
    """Analisador de lacunas críticas de governança."""
    
    def __init__(self):
        """Inicializa o analisador de lacunas críticas."""
        self.critical_controls = {
            "identity": {
                "mfa_enforcement": {
                    "description": "Enforcing MFA for all users",
                    "impact": "Critical",
                    "frameworks": ["SOX", "NIST", "ISO27001"]
                },
                "privileged_access": {
                    "description": "Just-in-time privileged access",
                    "impact": "Critical",
                    "frameworks": ["SOX", "NIST"]
                },
                "emergency_access": {
                    "description": "Emergency access management",
                    "impact": "Critical",
                    "frameworks": ["SOX", "ISO27001"]
                }
            },
            "compliance": {
                "audit_logging": {
                    "description": "Comprehensive audit logging",
                    "impact": "Critical",
                    "frameworks": ["SOX", "NIST", "ISO27001"]
                },
                "data_classification": {
                    "description": "Data classification controls",
                    "impact": "High",
                    "frameworks": ["GDPR", "ISO27001"]
                },
                "policy_enforcement": {
                    "description": "Automated policy enforcement",
                    "impact": "Critical",
                    "frameworks": ["SOX", "NIST"]
                }
            },
            "governance": {
                "role_review": {
                    "description": "Regular role access review",
                    "impact": "Critical",
                    "frameworks": ["SOX", "ISO27001"]
                },
                "segregation": {
                    "description": "Segregation of duties",
                    "impact": "Critical",
                    "frameworks": ["SOX", "NIST"]
                },
                "lifecycle": {
                    "description": "Identity lifecycle management",
                    "impact": "High",
                    "frameworks": ["ISO27001", "NIST"]
                }
            }
        }

    def analyze_critical_gaps(self, current_state):
        """Analisa lacunas críticas nos controles de governança."""
        gaps = {
            "critical_findings": [],
            "severity_metrics": defaultdict(int),
            "remediation_priority": []
        }
        
        for domain, controls in self.critical_controls.items():
            for control_id, control_info in controls.items():
                if not self._validate_control(current_state, domain, control_id):
                    gaps["critical_findings"].append({
                        "domain": domain,
                        "control": control_id,
                        "description": control_info["description"],
                        "impact": control_info["impact"],
                        "affected_frameworks": control_info["frameworks"]
                    })
                    gaps["severity_metrics"][control_info["impact"]] += 1
        
        gaps["remediation_priority"] = self._prioritize_remediation(gaps["critical_findings"])
        return gaps

    def _validate_control(self, current_state, domain, control_id):
        """Valida um controle específico baseado no estado atual."""
        if not current_state or domain not in current_state:
            return False
            
        control_validators = {
            "identity": {
                "mfa_enforcement": lambda s: s.get("mfa_status", {}).get("enforced", False),
                "privileged_access": lambda s: s.get("privileged_access", {}).get("jit_enabled", False),
                "emergency_access": lambda s: s.get("emergency_accounts", {}).get("configured", False)
            },
            "compliance": {
                "audit_logging": lambda s: s.get("audit_logs", {}).get("enabled", False),
                "data_classification": lambda s: s.get("data_controls", {}).get("classification_enabled", False),
                "policy_enforcement": lambda s: s.get("policies", {}).get("automated_enforcement", False)
            },
            "governance": {
                "role_review": lambda s: s.get("access_reviews", {}).get("scheduled", False),
                "segregation": lambda s: s.get("sod_controls", {}).get("enabled", False),
                "lifecycle": lambda s: s.get("lifecycle_management", {}).get("automated", False)
            }
        }
        
        return control_validators.get(domain, {}).get(control_id, lambda x: False)(current_state[domain])

    def _prioritize_remediation(self, findings):
        """Prioriza ações de remediação baseado no impacto e frameworks afetados."""
        prioritized = []
        
        # Ordena por impacto e número de frameworks afetados
        sorted_findings = sorted(
            findings,
            key=lambda x: (getattr(x, 'impact', '') == "Critical", len(getattr(x, 'affected_frameworks', []))),
            reverse=True
        )
        
        for finding in sorted_findings:
            action = {
                "control": getattr(finding, 'control', ''),
                "description": getattr(finding, 'description', ''),
                "priority": "Immediate" if getattr(finding, 'impact', '') == "Critical" else "High",
                "frameworks": getattr(finding, 'affected_frameworks', [])
            }
            prioritized.append(action)
        
        return prioritized

class AdvancedGovernanceAnalyzer:
    """Analisador avançado de governança Azure com IA e análises especializadas."""
    
    def __init__(self):
        """Inicializa o analisador com cliente OpenAI e processador de dados."""
        logger.info("Inicializando AdvancedGovernanceAnalyzer...")
        self.client = None
        self.processor = AzureLogProcessor()
        self.gap_analyzer = CriticalGapAnalyzer()
        
        # Configurações de compliance
        logger.info("Configurando frameworks de compliance...")
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
        logger.info("Configurando detecção de padrões suspeitos...")
        self.suspicious_patterns = {
            "mass_role_assignment": {"threshold": 10, "timeframe_minutes": 30},
            "privilege_escalation": {"roles": ["Global Administrator", "Privileged Role Administrator"]},
            "unusual_locations": {"threshold": 3, "timeframe_hours": 24},
            "dormant_account_activation": {"inactive_days": 90}
        }
        
        logger.info("Verificando configuração do OpenAI...")
        if AzureOpenAI and config.is_openai_configured():
            try:
                logger.info("Iniciando cliente OpenAI...")
                http_client = httpx.Client(verify=True, timeout=180.0)
                self.client = AzureOpenAI(
                    api_key=config.openai_api_key,
                    api_version=config.openai_api_version,
                    azure_endpoint=config.openai_endpoint,
                    http_client=http_client
                )
                logger.info("Cliente OpenAI configurado com sucesso!")
            except Exception as e:
                logger.error(f"Erro ao configurar OpenAI: {str(e)}")
                raise RuntimeError(f"Falha na configuração do OpenAI: {str(e)}")
        else:
            logger.warning("OpenAI não configurado - funcionalidades de IA serão limitadas")

    def perform_comprehensive_analysis(self, logs: List[Dict[str, Any]], current_state: Optional[Dict[str, Any]] = None) -> EnhancedAIAnalysisResult:
        """Executa análise abrangente de governança com IA e regras customizadas."""
        
        if not logs:
            # Retorna resultado vazio quando não há logs
            return EnhancedAIAnalysisResult(
                findings=[],
                suggested_actions=[],
                risk_assessment={"score": 0, "level": "LOW", "reasoning": "No logs provided for analysis", "summary": "No risk assessment performed - no logs provided"},
                compliance_status={},
                raw_response=None,
                executive_summary="No analysis performed - no logs provided",
                technical_summary="No logs were provided for analysis"
            )
        
        logger.info(f"Iniciando análise abrangente de governança para {len(logs)} logs.")
        
        # Análise de lacunas críticas
        if current_state:
            critical_gaps = self.gap_analyzer.analyze_critical_gaps(current_state)
            if critical_gaps["critical_findings"]:
                logger.warning(f"Identificadas {len(critical_gaps['critical_findings'])} lacunas críticas de governança.")
        
        # Processa logs e executa análises especializadas
        logs_json = json.dumps(logs, default=str)
        self.processor.logs_df = self.processor.load_logs_from_file(logs_json)
        
        # Análises especializadas
        try:
            rule_based_findings = self._perform_rule_based_analysis()
        except Exception as e:
            logger.error(f"Erro na análise baseada em regras: {str(e)}")
            return self._create_error_result(f"Falha na análise baseada em regras: {str(e)}")
        
        if self.client:
            # Análise com IA
            try:
                ai_findings = self._perform_ai_analysis(logs)
                all_findings = rule_based_findings + ai_findings.findings
            except Exception as e:
                logger.error(f"Erro na análise com IA: {str(e)}")
                all_findings = rule_based_findings
                logger.warning("Análise limitada - Falha na análise com IA")
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
        
        # Análise de lacunas críticas
        if hasattr(self, 'gap_analyzer') and hasattr(self.gap_analyzer, 'critical_gaps'):
            critical_gaps = getattr(self.gap_analyzer, 'critical_gaps', None)
            if critical_gaps and critical_gaps.get('critical_findings'):
                for gap in critical_gaps['critical_findings']:
                    # Processa e valida os frameworks afetados
                    valid_frameworks = self._process_framework_impacts(gap["affected_frameworks"])
                    
                    if not valid_frameworks:  # Se não houver frameworks válidos, use um padrão
                        valid_frameworks = [ComplianceFramework.ISO27001]
                    
                    finding = DetailedFinding(
                        risk_level=RiskLevel.CRITICAL,
                        violation_type=GovernanceViolationType.COMPLIANCE_VIOLATION,
                        title=f"Lacuna Crítica: {gap['description']}",
                        description=f"Controle crítico ausente no domínio {gap['domain']}: {gap['description']}. "
                                  f"Este controle é essencial para compliance com {', '.join(f.value for f in valid_frameworks)}.",
                        recommendation=f"Implementar controle de {gap['description']} imediatamente. "
                                     f"Priorizar esta ação devido ao impacto {gap['impact']} nos frameworks de compliance.",
                        affected_principals=[],
                        evidence={
                            "domain": gap["domain"],
                            "control": gap["control"],
                            "affected_frameworks": [f.value for f in valid_frameworks]
                        },
                        compliance_impact=valid_frameworks,
                        remediation_priority=1,
                        business_impact="Lacuna crítica em controles de governança pode resultar em não-conformidade e riscos operacionais.",
                        detection_timestamp=datetime.now().isoformat()
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_sox_compliance(self) -> List[DetailedFinding]:
        """Verifica compliance com SOX (Sarbanes-Oxley)."""
        findings = []
        
        if self.processor.role_assignments_df is None:
            return findings
        
        # Verifica se há muitos administradores globais (risco SOX)
        if 'role_name' not in self.processor.role_assignments_df.columns:
            return findings
            
        global_admins = self.processor.role_assignments_df[
            self.processor.role_assignments_df['role_name'].str.contains('Global Administrator', na=False)
        ]['user_principal_name'].nunique() if 'user_principal_name' in self.processor.role_assignments_df.columns else 0
        
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
                compliance_impact=[ComplianceFramework.SOX, ComplianceFramework.ISO27001],
                remediation_priority=1,
                business_impact="Violação de controles SOX, risco de auditoria e penalidades regulatórias.",
                detection_timestamp=datetime.now().isoformat()
            )
            findings.append(finding)
        
        return findings
    
    def _check_nist_compliance(self) -> List[DetailedFinding]:
        """Verifica compliance com NIST Cybersecurity Framework."""
        findings = []
        
        if self.processor.role_assignments_df is None or self.processor.role_assignments_df.empty:
            return findings
            
        # 1. Verificação de MFA
        high_risk_roles = ["Global Administrator", "Security Administrator", "Exchange Administrator"]
        high_risk_users = self.processor.role_assignments_df[
            self.processor.role_assignments_df['role_name'].isin(high_risk_roles)
        ]['user_principal_name'].unique()
        
        if len(high_risk_users) > 0:
            mfa_status = self.processor.check_mfa_status(list(high_risk_users))
            non_mfa_users = [user for user, status in mfa_status.items() if not status]
            
            if non_mfa_users:
                finding = DetailedFinding(
                    risk_level=RiskLevel.CRITICAL,
                    violation_type=GovernanceViolationType.COMPLIANCE_VIOLATION,
                    title="Violação NIST: MFA não habilitado para roles críticas",
                    description=f"Identificados {len(non_mfa_users)} usuários com roles críticas sem MFA habilitado. "
                               f"NIST requer autenticação forte para todas as contas privilegiadas.",
                    recommendation="Habilitar MFA imediatamente para todas as contas privilegiadas. "
                                  "Implementar políticas de conformidade que exijam MFA.",
                    affected_principals=non_mfa_users,
                    evidence={
                        "non_mfa_users": non_mfa_users,
                        "critical_roles": high_risk_roles
                    },
                    compliance_impact=[ComplianceFramework.NIST],
                    remediation_priority=1,
                    business_impact="Risco crítico de comprometimento de contas privilegiadas.",
                    detection_timestamp=datetime.now().isoformat()
                )
                findings.append(finding)
        
        # 2. Verificação de Sessões Privilegiadas
        privileged_sessions = self.processor.analyze_privileged_sessions()
        long_sessions = [
            session for session in privileged_sessions 
            if session.get('duration_hours', 0) > self.compliance_frameworks[ComplianceFramework.NIST]['privileged_session_timeout']
        ]
        
        if long_sessions:
            finding = DetailedFinding(
                risk_level=RiskLevel.HIGH,
                violation_type=GovernanceViolationType.COMPLIANCE_VIOLATION,
                title="Violação NIST: Sessões privilegiadas excedendo limite",
                description=f"Detectadas {len(long_sessions)} sessões privilegiadas excedendo "
                           f"o limite de {self.compliance_frameworks[ComplianceFramework.NIST]['privileged_session_timeout']} horas.",
                recommendation="Implementar limite de tempo para sessões privilegiadas. "
                              "Forçar re-autenticação após o período definido.",
                affected_principals=[session['user'] for session in long_sessions],
                evidence={
                    "long_sessions": long_sessions,
                    "max_duration": self.compliance_frameworks[ComplianceFramework.NIST]['privileged_session_timeout']
                },
                compliance_impact=[ComplianceFramework.NIST],
                remediation_priority=2,
                business_impact="Risco elevado de abuso de sessões privilegiadas.",
                detection_timestamp=datetime.now().isoformat()
            )
            findings.append(finding)
            
        # 3. Verificação de Revisão de Acessos
        last_review = self.processor.get_last_access_review()
        if last_review:
            days_since_review = (datetime.now() - last_review).days
            if days_since_review > self.compliance_frameworks[ComplianceFramework.NIST]['access_review_days']:
                finding = DetailedFinding(
                    risk_level=RiskLevel.MEDIUM,
                    violation_type=GovernanceViolationType.COMPLIANCE_VIOLATION,
                    title="Violação NIST: Revisão de acessos atrasada",
                    description=f"Última revisão de acessos foi há {days_since_review} dias, excedendo "
                               f"o limite de {self.compliance_frameworks[ComplianceFramework.NIST]['access_review_days']} dias.",
                    recommendation="Realizar revisão de acessos imediatamente. "
                                  "Estabelecer processo automatizado de revisão periódica.",
                    affected_principals=[],
                    evidence={
                        "last_review_date": last_review.isoformat(),
                        "days_since_review": days_since_review,
                        "required_interval": self.compliance_frameworks[ComplianceFramework.NIST]['access_review_days']
                    },
                    compliance_impact=[ComplianceFramework.NIST],
                    remediation_priority=3,
                    business_impact="Risco de acumulação de acessos desnecessários.",
                    detection_timestamp=datetime.now().isoformat()
                )
                findings.append(finding)
        
        return findings
    
    def _perform_ai_analysis(self, logs: List[Dict[str, Any]]) -> EnhancedAIAnalysisResult:
        """Executa análise com IA para padrões complexos."""
        if not self.client:
            return self._create_error_result("Cliente OpenAI não disponível.")
            
        # Valida se há dados suficientes para análise
        if not logs or len(logs) < 5:
            return self._create_error_result("Dados insuficientes para análise detalhada.")
        
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
        ai_output = re.sub(r'"violation_type":\s*"DUPLICATE_GROUPS"', '"violation_type": "Duplicate_Groups"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"SUSPICIOUS_ACCESS"', '"violation_type": "Suspicious_Access"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"ORPHANED_ACCOUNTS"', '"violation_type": "Orphaned_Accounts"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"PRIVILEGE_ESCALATION"', '"violation_type": "Privilege_Escalation"', ai_output)
        ai_output = re.sub(r'"violation_type":\s*"COMPLIANCE_VIOLATION"', '"violation_type": "Compliance_Violation"', ai_output)
        
        return ai_output
    
    def _get_advanced_system_prompt(self) -> str:
        """Sistema prompt especializado para análise avançada."""
        return """Você é um Expert Global em Governança de Identidade e Compliance Regulatório para Microsoft Azure e Entra ID, com certificações CISSP, CISA e especialização em frameworks SOX, NIST, ISO 27001, GDPR e PCI-DSS.

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

Seja técnico, forense e foque em insights que apenas IA pode detectar.

FORMATOS ACEITOS:
- Risk Level: CRITICAL, HIGH, MEDIUM, LOW
- Compliance Frameworks: SOX, NIST, ISO27001, GDPR, HIPAA, PCI_DSS
- Violation Types: SOD_Violation, Direct_Assignment, Excessive_Privileges, etc.

Por favor, use EXATAMENTE estes valores ao gerar sua resposta."""
    
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
    
    def _create_error_result(self, error_message: str) -> EnhancedAIAnalysisResult:
        """Cria um resultado de erro padronizado."""
        return EnhancedAIAnalysisResult(
            findings=[],
            suggested_actions=[
                "Verificar logs do sistema para detalhes do erro",
                "Revisar a configuração do analisador",
                "Reprocessar a análise após correção"
            ],
            risk_assessment={
                "score": 0,
                "level": "UNKNOWN",
                "reasoning": error_message,
                "summary": "Análise falhou devido a um erro"
            },
            compliance_status={
                "error": error_message,
                "status": "ERROR"
            },
            raw_response=None,
            executive_summary=f"A análise falhou: {error_message}",
            technical_summary=f"Erro técnico durante a análise: {error_message}"
        )

    def _generate_executive_summary(self, findings: List[DetailedFinding], risk_score: float) -> str:
        """Gera um resumo executivo da análise."""
        if not findings:
            return "Não foram identificados problemas de governança significativos nesta análise."

        # Contadores
        critical_findings = len([f for f in findings if f.risk_level == RiskLevel.CRITICAL])
        high_findings = len([f for f in findings if f.risk_level == RiskLevel.HIGH])
        total_findings = len(findings)

        # Nível geral de risco
        risk_level = (
            "CRÍTICO" if risk_score >= 80 else
            "ALTO" if risk_score >= 60 else
            "MÉDIO" if risk_score >= 40 else
            "BAIXO"
        )

        # Principais frameworks afetados
        affected_frameworks = set()
        for finding in findings:
            if hasattr(finding, 'compliance_impact'):
                affected_frameworks.update(f.value for f in finding.compliance_impact)

        # Montagem do resumo
        summary_parts = [
            f"Análise de Governança - Nível de Risco {risk_level} (Score: {risk_score:.1f}/100)",
            f"Total de {total_findings} achados identificados:",
            f"- {critical_findings} críticos" if critical_findings else None,
            f"- {high_findings} de alto risco" if high_findings else None
        ]

        if affected_frameworks:
            summary_parts.append(f"Frameworks impactados: {', '.join(sorted(affected_frameworks))}")

        # Principais áreas de preocupação
        top_violations = Counter(f.violation_type.value for f in findings).most_common(2)
        if top_violations:
            summary_parts.append("Principais áreas de preocupação:")
            summary_parts.extend(f"- {violation}" for violation, _ in top_violations)

        return "\n".join(filter(None, summary_parts))

    def _generate_technical_summary(self, findings: List[DetailedFinding]) -> str:
        """Gera um resumo técnico detalhado da análise."""
        if not findings:
            return "Nenhuma violação técnica identificada na análise atual."

        # Agrupamento por tipo de violação
        violations_by_type = defaultdict(list)
        for finding in findings:
            violations_by_type[finding.violation_type].append(finding)

        # Construção do resumo técnico
        summary_parts = ["Detalhamento Técnico das Violações:"]

        for violation_type, type_findings in violations_by_type.items():
            summary_parts.append(f"\n{violation_type.value}:")
            for finding in type_findings:
                summary_parts.extend([
                    f"- Nível de Risco: {finding.risk_level.value}",
                    f"  Título: {finding.title}",
                    f"  Descrição: {finding.description}",
                    "  Impacto em Frameworks: " + 
                    ", ".join(f.value for f in finding.compliance_impact)
                    if hasattr(finding, 'compliance_impact') and finding.compliance_impact
                    else "N/A"
                ])

        return "\n".join(summary_parts)

    def _generate_next_actions(self, findings: List[DetailedFinding]) -> List[str]:
        """Gera lista de próximas ações baseada nos achados."""
        if not findings:
            return ["Manter monitoramento contínuo de atividades de governança"]

        actions = set()
        for finding in findings:
            if finding.recommendation:
                actions.add(finding.recommendation)

        # Ações específicas por tipo de violação
        violation_types = set(f.violation_type for f in findings)
        for v_type in violation_types:
            if v_type == GovernanceViolationType.SOD_VIOLATION:
                actions.add("Revisar e atualizar matriz de segregação de funções")
            elif v_type == GovernanceViolationType.EXCESSIVE_PRIVILEGES:
                actions.add("Implementar revisão periódica de privilégios elevados")
            elif v_type == GovernanceViolationType.SUSPICIOUS_ACCESS:
                actions.add("Reforçar monitoramento de padrões de acesso suspeitos")

        # Prioriza ações críticas
        critical_actions = {
            action for action in actions
            if any(
                f.risk_level == RiskLevel.CRITICAL and action in f.recommendation
                for f in findings
            )
        }

        # Organiza e retorna ações
        return (
            list(critical_actions) +
            [a for a in actions if a not in critical_actions]
        )[:10]  # Limita a 10 ações principais

    def _generate_risk_reasoning(self, findings: List[DetailedFinding], risk_score: float) -> str:
        """Gera explicação detalhada do raciocínio por trás do score de risco."""
        if not findings:
            return "Nenhum risco significativo identificado na análise atual."

        # Análise de fatores de risco
        risk_factors = []

        # Fator 1: Quantidade e severidade dos achados
        critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
        
        if critical_count > 0:
            risk_factors.append(
                f"Identificados {critical_count} achados críticos que requerem ação imediata"
            )
        if high_count > 0:
            risk_factors.append(
                f"Presença de {high_count} violações de alto risco que podem escalar"
            )

        # Fator 2: Impacto em compliance
        frameworks_impacted = set()
        for finding in findings:
            if hasattr(finding, 'compliance_impact'):
                frameworks_impacted.update(f.value for f in finding.compliance_impact)
        
        if frameworks_impacted:
            risk_factors.append(
                f"Impacto em múltiplos frameworks de compliance: {', '.join(frameworks_impacted)}"
            )

        # Fator 3: Padrões de violação
        violation_patterns = Counter(f.violation_type for f in findings)
        frequent_violations = [v for v, c in violation_patterns.items() if c > 1]
        
        if frequent_violations:
            risk_factors.append(
                "Padrões recorrentes de violação detectados: " +
                ", ".join(v.value for v in frequent_violations)
            )

        # Fator 4: Análise de tendência de risco
        if risk_score >= 80:
            trend = "CRÍTICA - Requer ação imediata"
        elif risk_score >= 60:
            trend = "ALTA - Necessita atenção urgente"
        elif risk_score >= 40:
            trend = "MÉDIA - Monitoramento próximo requerido"
        else:
            trend = "BAIXA - Manter vigilância padrão"

        # Montagem do raciocínio final
        reasoning_parts = [
            f"Análise de Risco (Score: {risk_score:.1f}/100) - Tendência: {trend}",
            "\nFatores de Risco Identificados:"
        ]
        reasoning_parts.extend(f"- {factor}" for factor in risk_factors)

        # Adiciona recomendação geral
        if risk_score >= 60:
            reasoning_parts.append(
                "\nRECOMENDAÇÃO: Necessária intervenção imediata para mitigar riscos críticos."
            )
        else:
            reasoning_parts.append(
                "\nRECOMENDAÇÃO: Manter monitoramento e implementar melhorias incrementais."
            )

        return "\n".join(reasoning_parts)

    def _generate_risk_summary(self, findings: List[DetailedFinding], risk_score: float) -> str:
        """Gera um resumo do risco baseado nos achados e score."""
        # Contagem de achados por nível de risco
        risk_counts = Counter(f.risk_level for f in findings)
        critical_count = risk_counts[RiskLevel.CRITICAL]
        high_count = risk_counts[RiskLevel.HIGH]
        
        # Base do resumo
        if risk_score >= 80:
            base_summary = "RISCO CRÍTICO"
        elif risk_score >= 60:
            base_summary = "RISCO ALTO"
        elif risk_score >= 40:
            base_summary = "RISCO MÉDIO"
        else:
            base_summary = "RISCO BAIXO"
        
        # Detalhamento
        details = []
        if critical_count > 0:
            details.append(f"{critical_count} achados críticos")
        if high_count > 0:
            details.append(f"{high_count} achados de alto risco")
            
        # Principais áreas afetadas
        affected_areas = Counter(f.violation_type for f in findings)
        top_areas = [area.value for area, _ in affected_areas.most_common(2)]
        
        # Montagem do resumo final
        summary_parts = [
            f"{base_summary} (Score: {risk_score:.1f}/100)",
            f"Detalhes: {', '.join(details)}" if details else None,
            f"Principais áreas afetadas: {', '.join(top_areas)}" if top_areas else None
        ]
        
        return " | ".join(filter(None, summary_parts))

    def _generate_compliance_assessment(self, findings: List[DetailedFinding]) -> Dict[str, Any]:
        """Gera avaliação detalhada de compliance baseada nos achados."""
        # Contadores por framework
        framework_violations = defaultdict(int)
        critical_violations = defaultdict(int)
        
        for finding in findings:
            if hasattr(finding, 'compliance_impact') and finding.compliance_impact:
                for framework in finding.compliance_impact:
                    framework_violations[framework.value] += 1
                    if finding.risk_level == RiskLevel.CRITICAL:
                        critical_violations[framework.value] += 1
        
        # Calcula scores por framework
        framework_scores = {}
        for framework in ComplianceFramework:
            violations = framework_violations.get(framework.value, 0)
            criticals = critical_violations.get(framework.value, 0)
            # Score base 100, -15 por violação normal, -30 por crítica
            score = max(0, 100 - (violations * 15) - (criticals * 30))
            framework_scores[framework.value] = score
        
        # Score geral de compliance
        overall_score = (
            sum(framework_scores.values()) / len(framework_scores)
            if framework_scores else 100
        )
        
        # Gera recomendações prioritárias
        recommendations = []
        for finding in sorted(
            findings,
            key=lambda x: (x.risk_level == RiskLevel.CRITICAL, x.remediation_priority),
            reverse=True
        )[:5]:
            recommendations.append(finding.recommendation)
        
        return {
            "overall_score": overall_score,
            "framework_scores": framework_scores,
            "violations_by_framework": dict(framework_violations),
            "critical_violations": dict(critical_violations),
            "recommendations": recommendations,
            "compliance_status": {
                "critical_gaps": [
                    f.title for f in findings
                    if f.risk_level == RiskLevel.CRITICAL
                ],
                "high_priority_items": [
                    f.title for f in findings
                    if f.risk_level == RiskLevel.HIGH and f.remediation_priority == 1
                ],
                "frameworks_at_risk": [
                    framework for framework, score in framework_scores.items()
                    if score < 70
                ]
            },
            "assessment_timestamp": datetime.now().isoformat()
        }

    def _consolidate_analysis_results(self, findings: List[DetailedFinding], logs: List[Dict[str, Any]]) -> EnhancedAIAnalysisResult:
        """Consolida resultados de múltiplas análises."""
        
        # Calcula métricas de governança
        governance_summary = self.processor.generate_comprehensive_summary()
        governance_metrics = self._calculate_governance_metrics(governance_summary)
        
        # Calcula score de risco baseado nos achados
        risk_score = self._calculate_consolidated_risk_score(findings)
        
        # Gera assessment de compliance
        compliance_assessment = self._generate_compliance_assessment(findings)
        
        # Cria assessment de risco consolidado
        risk_assessment = {
            "score": risk_score,
            "level": "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW",
            "summary": self._generate_risk_summary(findings, risk_score),
            "governance_metrics": governance_metrics,
            "compliance_assessment": compliance_assessment,
            "reasoning": self._generate_risk_reasoning(findings, risk_score)
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
        
        # Cálculo de pontuação base de governança
        base_score = 100
        
        # Deduções por tipo de violação
        deductions = {
            'sod_violations': 20,  # -20 pontos por violação SOD
            'direct_assignments': 5,  # -5 pontos por atribuição direta
            'duplicate_groups': 3,  # -3 pontos por grupo duplicado
            'excessive_privileges': 10,  # -10 pontos por usuário com privilégios excessivos
            'suspicious_activities': 15  # -15 pontos por atividade suspeita
        }
        
        # Aplica deduções
        for issue_type, deduction in deductions.items():
            if issue_type in issues:
                base_score -= (issues[issue_type] * deduction)
        
        # Garante que o score não seja negativo
        compliance_score = max(0, base_score)
        
        return {
            "total_users": governance_summary.get('unique_users', 0),
            "direct_assignments": issues.get('direct_assignments', 0),
            "sod_violations": issues.get('sod_violations', 0),
            "excessive_privilege_users": issues.get('excessive_privileges', 0),
            "duplicate_groups": issues.get('duplicate_groups', 0),
            "suspicious_activities": issues.get('suspicious_activities', 0),
            "compliance_score": compliance_score,
            "risk_indicators": {
                "critical_violations": issues.get('critical_violations', 0),
                "high_risk_findings": issues.get('high_risk_findings', 0),
                "medium_risk_findings": issues.get('medium_risk_findings', 0)
            },
            "temporal_metrics": {
                "analysis_period_days": governance_summary.get('analysis_period_days', 30),
                "last_review_date": governance_summary.get('last_review_date', None),
                "trending_direction": governance_summary.get('risk_trend', 'stable')
            }
        }
    
    def _calculate_consolidated_risk_score(self, findings: List[DetailedFinding]) -> int:
        """Calcula score de risco consolidado baseado nos achados."""
        if not findings:
            return 0
        
        # Pesos por nível de risco
        risk_weights = {
            RiskLevel.CRITICAL: 40,  # Um achado crítico já eleva significativamente o risco
            RiskLevel.HIGH: 25,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5
        }
        
        # Pesos por tipo de violação
        violation_weights = {
            GovernanceViolationType.SOD_VIOLATION: 2.0,  # Multiplicador para violações SOD
            GovernanceViolationType.PRIVILEGE_ESCALATION: 1.8,
            GovernanceViolationType.SUSPICIOUS_ACCESS: 1.5,
            GovernanceViolationType.COMPLIANCE_VIOLATION: 1.3,
            GovernanceViolationType.EXCESSIVE_PRIVILEGES: 1.2,
            GovernanceViolationType.DIRECT_ASSIGNMENT: 1.1,
            GovernanceViolationType.DUPLICATE_GROUPS: 1.0,
            GovernanceViolationType.ORPHANED_ACCOUNTS: 1.0
        }
        
        total_score = 0
        for finding in findings:
            # Score base pelo nível de risco
            base_score = risk_weights[finding.risk_level]
            
            # Multiplicador pelo tipo de violação
            multiplier = violation_weights.get(finding.violation_type, 1.0)
            
            # Ajuste pela prioridade de remediação (1 é mais urgente, 3 menos urgente)
            priority_factor = 1 + (1 / finding.remediation_priority)
            
            # Calcula score do achado
            finding_score = base_score * multiplier * priority_factor
            
            # Adiciona ao total
            total_score += finding_score
        
        # Normaliza para escala 0-100
        normalized_score = min(100, total_score)
        
        return int(normalized_score)
    
    def _generate_risk_reasoning(self, findings: List[DetailedFinding], risk_score: int) -> str:
        """Gera explicação detalhada do score de risco."""
        if not findings:
            return "Nenhum risco significativo identificado."
        
        reasoning = []
        
        # Análise por nível de risco
        critical_findings = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        high_findings = [f for f in findings if f.risk_level == RiskLevel.HIGH]
        
        if critical_findings:
            reasoning.append(f"Identificados {len(critical_findings)} achados críticos que requerem ação imediata:")
            for f in critical_findings[:3]:  # Top 3 críticos
                reasoning.append(f"- {f.title}")
        
        if high_findings:
            reasoning.append(f"\nDetectados {len(high_findings)} achados de alto risco:")
            for f in high_findings[:3]:  # Top 3 alto risco
                reasoning.append(f"- {f.title}")
        
        # Análise de tendência
        if risk_score >= 80:
            reasoning.append("\nTendência: CRÍTICA - Exposição significativa a riscos de segurança e compliance.")
        elif risk_score >= 60:
            reasoning.append("\nTendência: ALTA - Necessidade de ações corretivas prioritárias.")
        elif risk_score >= 40:
            reasoning.append("\nTendência: MÉDIA - Requer atenção e melhorias nos controles.")
        else:
            reasoning.append("\nTendência: BAIXA - Manter monitoramento e controles atuais.")
        
        return "\n".join(reasoning)
    
    def _generate_next_actions(self, findings: List[DetailedFinding]) -> List[str]:
        """Gera lista priorizada de próximas ações baseada nos achados."""
        if not findings:
            return ["Manter monitoramento contínuo de governança."]
        
        # Agrupa achados por prioridade
        priority_findings = defaultdict(list)
        for finding in findings:
            priority_findings[finding.remediation_priority].append(finding)
        
        next_actions = []
        
        # Processa achados críticos (prioridade 1)
        if 1 in priority_findings:
            next_actions.append("AÇÕES IMEDIATAS (24-48h):")
            for finding in priority_findings[1]:
                next_actions.append(f"- {finding.recommendation}")
        
        # Processa achados de alta prioridade (2)
        if 2 in priority_findings:
            next_actions.append("\nAÇÕES DE CURTO PRAZO (1-2 semanas):")
            for finding in priority_findings[2][:3]:  # Top 3
                next_actions.append(f"- {finding.recommendation}")
        
        # Processa achados de média prioridade (3)
        if 3 in priority_findings:
            next_actions.append("\nAÇÕES DE MÉDIO PRAZO (2-4 semanas):")
            for finding in priority_findings[3][:3]:  # Top 3
                next_actions.append(f"- {finding.recommendation}")
        
        # Adiciona ações de governança contínua
        next_actions.extend([
            "\nAÇÕES CONTÍNUAS:",
            "- Revisar periodicamente atribuições de roles privilegiadas",
            "- Monitorar padrões de acesso suspeitos",
            "- Manter documentação de exceções e aprovações",
            "- Conduzir revisões trimestrais de compliance"
        ])
        
        return next_actions

    def analyze_governance_risks(self, logs: List[dict]) -> EnhancedAIAnalysisResult:
        """Analisa riscos de governança nos logs do Azure."""
        try:
            logger.info("Iniciando análise de governança...")
            
            # Verifica dados de entrada
            if not logs:
                logger.error("Nenhum log fornecido para análise")
                raise ValueError("Logs vazios ou inválidos")

            # Processa logs básicos
            logger.info("Processando logs básicos...")
            processed_data = self.processor.process_logs(logs)
            if not processed_data:
                logger.error("Falha no processamento de logs básicos")
                raise RuntimeError("Falha no processamento de logs")

            # Análise de gaps críticos
            logger.info("Analisando gaps críticos...")
            current_state = self._extract_current_state(processed_data)
            gaps = self.gap_analyzer.analyze_critical_gaps(current_state)
            
            if not gaps:
                logger.warning("Nenhum gap crítico identificado - isso é esperado?")

            # Análise de conformidade
            logger.info("Verificando conformidade com frameworks...")
            compliance_status = self._analyze_compliance(processed_data)
            
            # Detecção de padrões suspeitos
            logger.info("Detectando padrões suspeitos...")
            suspicious_patterns = self._detect_suspicious_patterns(processed_data)
            
            # Gera resultado final
            logger.info("Gerando resultado final da análise...")
            return self._generate_enhanced_result(
                processed_data,
                gaps,
                compliance_status,
                suspicious_patterns
            )

        except Exception as e:
            logger.error(f"Falha Crítica na Análise de Governança: {str(e)}", exc_info=True)
            raise RuntimeError(f"Falha Crítica na Análise Avançada de Governança: {str(e)}")