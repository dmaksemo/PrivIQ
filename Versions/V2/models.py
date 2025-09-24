# models.py
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

class RiskLevel(str, Enum):
    """Define os únicos níveis de risco permitidos para consistência."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class GovernanceViolationType(str, Enum):
    """Tipos específicos de violações de governança."""
    SOD_VIOLATION = "SOD_Violation"
    DIRECT_ASSIGNMENT = "Direct_Assignment"
    EXCESSIVE_PRIVILEGES = "Excessive_Privileges"
    DUPLICATE_GROUPS = "Duplicate_Groups"
    SUSPICIOUS_ACCESS = "Suspicious_Access"
    ORPHANED_ACCOUNTS = "Orphaned_Accounts"
    PRIVILEGE_ESCALATION = "Privilege_Escalation"
    COMPLIANCE_VIOLATION = "Compliance_Violation"

class ComplianceFramework(str, Enum):
    """Frameworks de compliance suportados."""
    SOX = "SOX"
    NIST = "NIST"
    ISO27001 = "ISO27001"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"

class GovernanceMetric(BaseModel):
    """Métricas específicas de governança."""
    total_users: int = Field(0, description="Total de usuários analisados")
    direct_assignments: int = Field(0, description="Número de atribuições diretas")
    sod_violations: int = Field(0, description="Violações de segregação de funções")
    excessive_privilege_users: int = Field(0, description="Usuários com privilégios excessivos")
    duplicate_groups: int = Field(0, description="Grupos com permissões duplicadas")
    suspicious_activities: int = Field(0, description="Atividades suspeitas detectadas")
    compliance_score: float = Field(0.0, ge=0.0, le=100.0, description="Score de compliance")

class DetailedFinding(BaseModel):
    """Achado de segurança com detalhes expandidos para governança."""
    risk_level: RiskLevel = Field(..., description="O nível de risco classificado.")
    violation_type: GovernanceViolationType = Field(..., description="Tipo específico de violação.")
    title: str = Field(..., description="Um título curto e direto para o achado.")
    description: str = Field(..., description="A explicação técnica detalhada do problema encontrado.")
    recommendation: str = Field(..., description="Ação prática e específica para mitigar o risco.")
    affected_principals: List[str] = Field([], description="Lista de usuários, grupos ou SPNs afetados.")
    evidence: Dict[str, Any] = Field({}, description="Evidências técnicas que suportam o achado.")
    compliance_impact: List[ComplianceFramework] = Field([], description="Frameworks de compliance afetados.")
    remediation_priority: int = Field(1, ge=1, le=5, description="Prioridade de remediação (1=Mais urgente, 5=Menos urgente).")
    business_impact: str = Field("", description="Impacto potencial no negócio.")
    detection_timestamp: Optional[str] = Field(None, description="Timestamp da detecção.")

class TrendAnalysis(BaseModel):
    """Análise de tendências de governança."""
    trend_direction: str = Field(..., description="Direção da tendência: 'improving', 'degrading', 'stable'")
    key_changes: List[str] = Field([], description="Principais mudanças observadas")
    predictions: List[str] = Field([], description="Predições baseadas em tendências")

class ComplianceAssessment(BaseModel):
    """Avaliação de compliance expandida."""
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Score geral de compliance")
    framework_scores: Dict[str, float] = Field({}, description="Scores por framework de compliance")
    critical_gaps: List[str] = Field([], description="Lacunas críticas de compliance")
    recommendations: List[str] = Field([], description="Recomendações para melhoria de compliance")

class RiskAssessment(BaseModel):
    """Define a estrutura da avaliação geral de risco expandida."""
    score: int = Field(..., ge=0, le=100, description="Score de risco de 0 a 100.")
    summary: str = Field(..., description="Um resumo executivo da postura de segurança geral.")
    governance_metrics: GovernanceMetric = Field(default_factory=GovernanceMetric, description="Métricas específicas de governança.")
    trend_analysis: Optional[TrendAnalysis] = Field(None, description="Análise de tendências.")
    compliance_assessment: Optional[ComplianceAssessment] = Field(None, description="Avaliação de compliance.")

class EnhancedAIAnalysisResult(BaseModel):
    """Resultado expandido da análise de IA com foco em governança."""
    risk_assessment: RiskAssessment
    findings: List[DetailedFinding]
    executive_summary: str = Field(..., description="Resumo executivo para liderança.")
    technical_summary: str = Field(..., description="Resumo técnico para equipe de TI.")
    next_actions: List[str] = Field([], description="Próximas ações recomendadas.")
    analysis_metadata: Dict[str, Any] = Field({}, description="Metadados da análise.")

# Mantemos o modelo original para compatibilidade
class Finding(BaseModel):
    """Define a estrutura de um único 'achado' de segurança."""
    risk_level: RiskLevel = Field(..., description="O nível de risco classificado.")
    title: str = Field(..., description="Um título curto e direto para o achado.")
    description: str = Field(..., description="A explicação técnica detalhada do problema encontrado.")
    recommendation: str = Field(..., description="Ação prática e específica para mitigar o risco.")
    affected_principals: List[str] = Field([], description="Lista de usuários, grupos ou SPNs afetados.")

class AIAnalysisResult(BaseModel):
    """O modelo de dados raiz que a IA DEVE retornar (mantido para compatibilidade)."""
    risk_assessment: RiskAssessment
    findings: List[Finding]