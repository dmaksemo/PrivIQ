# models.py
from pydantic import BaseModel, Field
from typing import List
from enum import Enum

class RiskLevel(str, Enum):
    """Define os únicos níveis de risco permitidos para consistência."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class Finding(BaseModel):
    """Define a estrutura de um único 'achado' de segurança."""
    risk_level: RiskLevel = Field(..., description="O nível de risco classificado.")
    title: str = Field(..., description="Um título curto e direto para o achado.")
    description: str = Field(..., description="A explicação técnica detalhada do problema encontrado.")
    recommendation: str = Field(..., description="Ação prática e específica para mitigar o risco.")
    affected_principals: List[str] = Field([], description="Lista de usuários, grupos ou SPNs afetados.")

class RiskAssessment(BaseModel):
    """Define a estrutura da avaliação geral de risco."""
    score: int = Field(..., ge=0, le=100, description="Score de risco de 0 a 100.")
    summary: str = Field(..., description="Um resumo executivo da postura de segurança geral.")

class AIAnalysisResult(BaseModel):
    """O modelo de dados raiz que a IA DEVE retornar."""
    risk_assessment: RiskAssessment
    findings: List[Finding]