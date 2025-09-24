# azure_log_analyzer.py

import json
import logging
from typing import List, Dict, Any

import httpx
from pydantic import ValidationError

try:
    from openai import AzureOpenAI
except ImportError:
    AzureOpenAI = None

from config import config
from models import AIAnalysisResult
from data_processor import AzureLogProcessor

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class AzureLogAnalyzer:
    """Analisador inteligente de logs Azure com foco em governança e compliance."""
    
    def __init__(self):
        """Inicializa o analisador e o cliente Azure OpenAI."""
        self.client = None
        self.processor = AzureLogProcessor()
        
        if AzureOpenAI and config.is_openai_configured():
            try:
                http_client = httpx.Client(verify=True, timeout=120.0)
                self.client = AzureOpenAI(
                    api_key=config.openai_api_key,
                    api_version=config.openai_api_version,
                    azure_endpoint=config.openai_endpoint,
                    http_client=http_client
                )
                logger.info("Cliente AzureOpenAI inicializado com sucesso.")
            except Exception as e:
                logger.error(f"Falha ao inicializar AzureOpenAI: {e}")

    def _calculate_standardized_score(self, governance_summary: Dict[str, Any]) -> int:
        """
        Calcula um score padronizado baseado em métricas objetivas dos logs.
        Retorna um valor entre 0 (menor risco) e 100 (maior risco).
        """
        score = 0
        analysis = governance_summary.get('detailed_analysis', {})
        
        # Pesos para diferentes tipos de problemas
        WEIGHTS = {
            'direct_assignments': 25,  # Atribuições diretas
            'conflicts': 35,           # Conflitos SOD
            'duplicates': 15,          # Grupos duplicados
            'critical_patterns': 25     # Padrões críticos
        }
        
        # Avalia atribuições diretas
        direct_assignments = len(analysis.get('direct_assignments', {}))
        if direct_assignments > 0:
            score += min(WEIGHTS['direct_assignments'] * (direct_assignments / 10), WEIGHTS['direct_assignments'])
            
        # Avalia conflitos SOD
        conflicts = len(analysis.get('conflicts', {}))
        if conflicts > 0:
            score += min(WEIGHTS['conflicts'] * (conflicts / 5), WEIGHTS['conflicts'])
            
        # Avalia grupos duplicados
        duplicates = len(analysis.get('duplicates', {}))
        if duplicates > 0:
            score += min(WEIGHTS['duplicates'] * (duplicates / 3), WEIGHTS['duplicates'])
            
        # Avalia padrões críticos
        critical_patterns = len(analysis.get('critical_patterns', {}))
        if critical_patterns > 0:
            score += min(WEIGHTS['critical_patterns'] * (critical_patterns / 3), WEIGHTS['critical_patterns'])
            
        return min(round(score), 100)  # Garante que o score máximo é 100

    def analyze_security_patterns(self, logs: List[Dict[str, Any]]) -> AIAnalysisResult:
        """
        Executa análise abrangente de segurança e governança com contexto específico.
        """
        if not self.client:
            return self._create_error_result("Cliente OpenAI não foi inicializado.")

        if not logs:
            return self._create_error_result("Nenhum log foi fornecido para análise.")

        logger.info(f"Iniciando análise de governança para {len(logs)} logs.")
        
        # Primeiro processa os logs para obter insights estruturados
        logs_json = json.dumps(logs, default=str)
        self.processor.logs_df = self.processor.load_logs_from_file(logs_json)
        governance_summary = self.processor.generate_comprehensive_summary()
        
        # Calcula o score padronizado
        risk_score = self._calculate_standardized_score(governance_summary)
        logger.info(f"Score de risco calculado: {risk_score}")
        
        prompt = self._build_enhanced_prompt(logs, governance_summary)
        
        try:
            response = self.client.chat.completions.create(
                model=config.openai_deployment_name,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4096,
                temperature=0,  # Set to 0 for deterministic outputs
                response_format={"type": "json_object"}
            )
            
            ai_output = response.choices[0].message.content
            validated_result = AIAnalysisResult.model_validate_json(ai_output)
            logger.info("Análise de IA validada com sucesso.")
            return validated_result

        except ValidationError as e:
            logger.error(f"Erro de validação: {e}")
            return self._create_error_result(
                "A IA retornou dados em formato inesperado.",
                raw_response=ai_output if 'ai_output' in locals() else None
            )
        except Exception as e:
            logger.error(f"Erro na análise: {str(e)}")
            return self._create_error_result(f"Falha na comunicação com a API: {e}")

    def _get_system_prompt(self) -> str:
        """Define o prompt de sistema especializado em governança Azure."""
        return """Você é um Especialista Sênior em Governança e Segurança do Microsoft Azure e Entra ID, com mais de 10 anos de experiência em análise de compliance e auditoria de permissões.

Sua especialidade inclui:
- Detecção de violações de Segregation of Duties (SOD)
- Identificação de atribuições diretas de roles vs. atribuições via grupos
- Análise de permissões duplicadas e redundantes
- Avaliação de riscos de privilege escalation
- Compliance com frameworks de segurança (NIST, ISO 27001, SOX)

Foque nos seguintes aspectos críticos:
1. VIOLAÇÕES SOD: Identifique usuários com roles conflitantes que violam segregação de funções
2. ATRIBUIÇÕES DIRETAS: Detecte usuários com roles atribuídas diretamente (não via grupos)
3. PERMISSÕES EXCESSIVAS: Encontre usuários com múltiplas roles privilegiadas
4. GRUPOS DUPLICADOS: Identifique grupos com conjuntos de permissões idênticos
5. PADRÕES SUSPEITOS: Analise acessos fora do horário, múltiplos IPs, falhas excessivas

Seja técnico, preciso e forneça recomendações acionáveis."""

    def _build_enhanced_prompt(self, logs: List[Dict[str, Any]], governance_summary: Dict[str, Any]) -> str:
        """Constrói um prompt enriquecido com análise prévia dos logs."""
        json_schema_example = AIAnalysisResult.model_json_schema()
        risk_score = self._calculate_standardized_score(governance_summary)
        
        limited_logs = logs[:500] if len(logs) > 500 else logs
        
        return f"""
# ANÁLISE DE GOVERNANÇA E COMPLIANCE - LOGS AZURE/ENTRA ID

## RESUMO EXECUTIVO DOS DADOS ANALISADOS
{json.dumps(governance_summary.get('governance_issues', {}), indent=2)}

## DETALHES DE PROBLEMAS IDENTIFICADOS

### 1. ATRIBUIÇÕES DIRETAS DE ROLES (Violação de Boas Práticas)
```json
{json.dumps(governance_summary.get('detailed_analysis', {}).get('direct_assignments', {}), indent=2, default=str)[:2000]}
```

### 2. CONFLITOS DE PERMISSÕES E VIOLAÇÕES SOD
```json
{json.dumps(governance_summary.get('detailed_analysis', {}).get('conflicts', {}), indent=2, default=str)[:2000]}
```

### 3. GRUPOS COM PERMISSÕES DUPLICADAS
```json
{json.dumps(governance_summary.get('detailed_analysis', {}).get('duplicates', {}), indent=2, default=str)[:2000]}
```

### 4. PADRÕES DE ACESSO CRÍTICOS
```json
{json.dumps(governance_summary.get('detailed_analysis', {}).get('critical_patterns', {}), indent=2, default=str)[:2000]}
```

## LOGS BRUTOS PARA ANÁLISE CONTEXTUAL
```json
{json.dumps(limited_logs, indent=2, default=str)[:8000]}
```

---

**TAREFA**: Com base nos dados acima, forneça uma análise completa de governança focada em:

1. **Violações de SOD** - Usuários com roles conflitantes
2. **Riscos de Atribuição Direta** - Users com roles fora de grupos
3. **Permissões Excessivas** - Acúmulo de privilégios
4. **Redundâncias de Grupos** - Grupos duplicados
5. **Atividades Suspeitas** - Padrões anômalos

Para cada problema, forneça:
- Risk Level apropriado (Critical/High/Medium/Low)
- Título conciso e técnico
- Descrição detalhada do problema
- Recomendação específica e acionável
- Lista dos principals afetados

**IMPORTANTE**: Retorne APENAS um objeto JSON válido seguindo este esquema:

```json
{json.dumps(json_schema_example, indent=2)}
```
"""

    def _create_error_result(self, error_message: str, raw_response: str = None) -> AIAnalysisResult:
        """Cria um resultado de erro padronizado."""
        desc = f"Erro na Análise: {error_message}"
        if raw_response:
            desc += f"\n\nResposta recebida: {raw_response[:500]}..."

        error_finding = {
            "risk_level": "Critical",
            "title": "Falha Crítica na Análise de Governança",
            "description": desc,
            "recommendation": "Verifique a configuração do Azure OpenAI e tente novamente. Consulte os logs da aplicação para mais detalhes.",
            "affected_principals": []
        }
        
        return AIAnalysisResult(
            risk_assessment={
                "score": 100, 
                "summary": "A análise de governança não pôde ser concluída devido a um erro crítico no sistema."
            },
            findings=[error_finding]
        )

    def generate_governance_report(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Gera um relatório específico de governança sem usar IA (para comparação)."""
        logs_json = json.dumps(logs, default=str)
        self.processor.logs_df = self.processor.load_logs_from_file(logs_json)
        return self.processor.generate_comprehensive_summary()