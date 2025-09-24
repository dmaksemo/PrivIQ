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
from models import AIAnalysisResult # Importa nosso novo modelo de dados

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class AzureLogAnalyzer:
    def __init__(self):
        """Inicializa o analisador e o cliente Azure OpenAI."""
        self.client = None
        if AzureOpenAI and config.is_openai_configured():
            try:
                http_client = httpx.Client(verify=True, timeout=90.0) # Timeout maior
                self.client = AzureOpenAI(
                    api_key=config.openai_api_key,
                    api_version=config.openai_api_version,
                    azure_endpoint=config.openai_endpoint,
                    http_client=http_client
                )
                logger.info("Cliente AzureOpenAI inicializado com sucesso.")
            except Exception as e:
                logger.error(f"Falha ao inicializar AzureOpenAI: {e}")

    def analyze_security_patterns(self, logs: List[Dict[str, Any]]) -> AIAnalysisResult:
        """
        Executa uma análise de segurança abrangente e valida a resposta da IA.
        """
        if not self.client:
            return self._create_error_result("Cliente OpenAI não foi inicializado.")

        if not logs:
            return self._create_error_result("Nenhum log foi fornecido para análise.")

        logger.info(f"Iniciando análise de segurança para {len(logs)} logs.")
        prompt = self._build_prompt(logs)
        
        try:
            response = self.client.chat.completions.create(
                model=config.openai_deployment_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=4096,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            ai_output = response.choices[0].message.content
            
            # Validação com Pydantic: A etapa mais importante!
            validated_result = AIAnalysisResult.model_validate_json(ai_output)
            logger.info("IA retornou JSON válido e compatível com o esquema Pydantic.")
            return validated_result

        except ValidationError as e:
            logger.error(f"Erro de validação Pydantic! A IA não seguiu o esquema. Erros: {e}")
            return self._create_error_result(
                "A IA retornou dados em formato inesperado.",
                raw_response=ai_output
            )
        except Exception as e:
            logger.error(f"Falha na chamada ao Azure OpenAI: {str(e)}")
            return self._create_error_result(f"Falha na comunicação com a API: {e}")

    def _build_prompt(self, logs: List[Dict[str, Any]]) -> str:
        """
        Constrói o "Prompt Mestre" para garantir uma saída JSON estruturada e consistente.
        """
        json_schema_example = AIAnalysisResult.model_json_schema()
        
        return f"""
<|im_start|>system
Você é um Analista Sênior de Segurança em Nuvem (Cloud Security Analyst), especialista em Azure. Sua tarefa é analisar detalhadamente logs de atribuição de permissões (Role Assignments) do Azure e retornar uma análise técnica, objetiva e precisa, exclusivamente em formato JSON, seguindo rigorosamente o esquema fornecido.

**Instruções:**
- Siga EXATAMENTE o esquema JSON apresentado, sem adicionar ou omitir campos.
- Para cada achado, descreva o risco, o impacto, os principais envolvidos e recomendações técnicas.
- Justifique cada avaliação de risco de forma concisa e fundamentada.
- Caso não haja riscos, retorne uma lista `findings` vazia.
- Não inclua comentários, explicações ou qualquer texto fora do objeto JSON.
- Use linguagem técnica, impessoal e direta.

Seu objetivo é fornecer uma análise de segurança clara, estruturada e pronta para consumo automatizado.

<|im_end|>
<|im_start|>user
Realize uma análise de segurança abrangente sobre os logs do Azure fornecidos abaixo.

<regras_de_saida>
1.  Sua resposta DEVE ser um único objeto JSON, sem nenhum texto, comentário ou ```json``` antes ou depois.
2.  Siga EXATAMENTE o esquema JSON fornecido em `<json_schema>`. Não invente ou omita campos.
3.  Para o campo `risk_level`, use APENAS um dos seguintes valores: "Critical", "High", "Medium", "Low".
4.  O campo `score` em `risk_assessment` deve ser um número de 0 (seguro) a 100 (muito arriscado), refletindo sua análise geral.
5.  Se nenhum risco for encontrado, retorne uma lista `findings` vazia `[]`.
</regras_de_saida>

<json_schema>
{json.dumps(json_schema_example, indent=2, ensure_ascii=False)}
</json_schema>

<logs_para_analise>
{json.dumps(logs, indent=2, ensure_ascii=False)}
</logs_para_analise>
<|im_end|>
<|im_start|>assistant
"""

    def _create_error_result(self, error_message: str, raw_response: str = None) -> AIAnalysisResult:
        """Cria um objeto de resultado Pydantic padronizado para erros."""
        desc = f"Descrição do Erro: {error_message}"
        if raw_response:
            desc += f"\nResposta bruta recebida: {raw_response}"

        error_finding = {
            "risk_level": "Critical",
            "title": "Falha na Análise de Segurança",
            "description": desc,
            "recommendation": "Verifique os logs da aplicação ou a configuração do Azure OpenAI.",
            "affected_principals": []
        }
        return AIAnalysisResult(
            risk_assessment={"score": 100, "summary": "A análise não pôde ser concluída devido a um erro crítico."},
            findings=[error_finding]
        )