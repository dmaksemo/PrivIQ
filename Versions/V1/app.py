# app.py

import streamlit as st
import pandas as pd
import json
from datetime import datetime
import os
import sys
from collections import defaultdict # Usado para agrupar as recomendações

# Adiciona o diretório atual ao path para importações
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Importa os módulos customizados
try:
    from data_processor import AzureLogProcessor
    from azure_log_analyzer import AzureLogAnalyzer
    from visualization_generator import SecurityVisualizationGenerator
    from models import AIAnalysisResult
except ImportError as e:
    st.error(f"Erro ao importar módulos: {e}. Certifique-se de ter o arquivo 'models.py' e 'pydantic' instalado.")
    st.stop()

from config import config

# Configuração da página
st.set_page_config(page_title="Azure Security Analytics", page_icon="🛡️", layout="wide")

# CSS customizado
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem; font-weight: bold; color: #0078d4; text-align: center; margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f8f9fa; padding: 1.5rem; border-radius: 0.5rem;
        border-left: 5px solid #0078d4; margin: 1rem 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        color: #31333F; /* Garante que o texto seja sempre escuro e visível */
    }
    .risk-Critical { border-left-color: #721c24; } /* Vermelho escuro */
    .risk-High { border-left-color: #dc3545; } /* Vermelho */
    .risk-Medium { border-left-color: #ffc107; } /* Amarelo */
    .risk-Low { border-left-color: #28a745; } /* Verde */
</style>
""", unsafe_allow_html=True)

def initialize_session_state():
    """Inicializa as variáveis de estado da sessão."""
    if 'analysis_result' not in st.session_state:
        st.session_state.analysis_result = None
    if 'logs_df' not in st.session_state:
        st.session_state.logs_df = None
    if 'processor' not in st.session_state:
        st.session_state.processor = AzureLogProcessor()

# NOVA FUNÇÃO: Gera o resumo de recomendações agrupadas
def generate_recommendations_summary(result: AIAnalysisResult) -> str:
    """Agrupa recomendações por tipo de achado para criar um plano de ação."""
    if not result.findings:
        return "Nenhuma recomendação a ser resumida."

    # Usamos defaultdict(set) para agrupar e automaticamente remover duplicatas
    recommendations_by_title = defaultdict(set)
    for finding in result.findings:
        recommendations_by_title[finding.title].add(finding.recommendation)
        
    # Formata a saída em Markdown
    markdown_summary = []
    for title, recommendations in recommendations_by_title.items():
        markdown_summary.append(f"#### Para achados do tipo: '{title}'")
        for rec in recommendations:
            markdown_summary.append(f"- {rec}")
        markdown_summary.append("\n")
        
    return "\n".join(markdown_summary)

def render_detailed_report(result: AIAnalysisResult):
    """Renderiza o relatório textual detalhado com expanders e o novo resumo."""
    st.subheader("📝 Relatório Detalhado dos Achados")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"**Resumo Executivo da IA:**")
        st.info(f"*{result.risk_assessment.summary}*")
    with col2:
        st.metric("Score de Risco Geral", f"{result.risk_assessment.score} / 100")

    st.markdown("---")
    st.write("Abaixo estão os detalhes de cada problema de segurança identificado.")
    if result.findings:
        for finding in result.findings:
            st.markdown(f'<div class="metric-card risk-{finding.risk_level.value}">', unsafe_allow_html=True)
            with st.container():
                st.subheader(f"🚨 {finding.risk_level.value}: {finding.title}")
                with st.expander("Clique para ver detalhes e recomendação"):
                    st.markdown(f"**Descrição Detalhada:** {finding.description}")
                    st.markdown("---")
                    st.markdown(f"**Recomendação:** {finding.recommendation}")
                    if finding.affected_principals:
                        st.markdown("**Principais Afetados:**")
                        st.code('\n'.join(finding.affected_principals), language=None)
            st.markdown('</div>', unsafe_allow_html=True)
            
        # ADIÇÃO: Exibe o novo resumo de recomendações no final
        st.markdown("---")
        st.subheader("📋 Plano de Ação: Resumo das Recomendações")
        st.info("Abaixo estão as ações recomendadas, agrupadas por tipo de problema, para facilitar a mitigação dos riscos.")
        recommendations_summary = generate_recommendations_summary(result)
        st.markdown(recommendations_summary, unsafe_allow_html=True)
        
    else:
        st.success("✅ Nenhum achado de segurança significativo foi identificado pela IA.")

def render_visual_dashboards(result: AIAnalysisResult):
    """Renderiza os dashboards com gráficos."""
    st.subheader("📈 Dashboards Visuais")
    
    viz_generator = SecurityVisualizationGenerator()
    
    col1, col2 = st.columns(2)
    with col1:
        fig_dist = viz_generator.create_risk_distribution_chart(result)
        st.plotly_chart(fig_dist, width='stretch')
        
    with col2:
        fig_gauge = viz_generator.create_risk_gauge_chart(result)
        st.plotly_chart(fig_gauge, width='stretch')

    fig_findings = viz_generator.create_findings_by_type_chart(result)
    st.plotly_chart(fig_findings, width='stretch')


def main():
    """Função principal da aplicação."""
    initialize_session_state()
    
    st.markdown('<h1 class="main-header">🛡️ Análise Inteligente de Segurança do Azure</h1>', unsafe_allow_html=True)
    
    # --- BARRA LATERAL ---
    with st.sidebar:
        st.header("⚙️ Configuração")
        st.subheader("📊 Status da Conexão")
        
        openai_configured = config.is_openai_configured()
        openai_status = "✅ Conectado" if openai_configured else "⚠️ Não Configurado"
        st.markdown(f"**Azure OpenAI:** {openai_status}")
        
        if not openai_configured:
            st.expander("🔧 Configurar Azure OpenAI").warning("Defina as variáveis de ambiente.")
        
        st.divider()
        st.subheader("Parâmetros")
        max_logs_to_analyze = st.slider("Máximo de Logs para Análise", 50, 5000, 500, 50)

    # --- CONTEÚDO PRINCIPAL ---
    st.subheader("1. Carregamento e Validação de Logs")
    uploaded_file = st.file_uploader("Selecione o arquivo de log JSON do Azure", type=['json'], label_visibility="collapsed")
    
    if uploaded_file:
        try:
            file_bytes = uploaded_file.getvalue()
            file_content = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            file_content = file_bytes.decode("latin-1")
        
        df = st.session_state.processor.load_logs_from_file(file_content)
        st.session_state.logs_df = df
        st.success(f"✅ Arquivo validado e processado! {len(df)} eventos carregados.")
        
    if st.session_state.logs_df is not None:
        st.divider()
        st.subheader("2. Execução da Análise de IA")
        if st.button("🚀 Iniciar Análise de Segurança", type="primary", width='stretch'):
            with st.spinner("Analisando logs com a IA... Isso pode levar um momento."):
                analyzer = AzureLogAnalyzer()
                logs_as_dict = st.session_state.logs_df.head(max_logs_to_analyze).to_dict(orient='records')
                st.session_state.analysis_result = analyzer.analyze_security_patterns(logs_as_dict)
            st.rerun()

    if st.session_state.analysis_result:
        st.divider()
        st.subheader("3. Resultados da Análise")
        
        tab1, tab2 = st.tabs(["📋 Relatório Detalhado", "📊 Dashboards Visuais"])
        
        with tab1:
            render_detailed_report(st.session_state.analysis_result)
        
        with tab2:
            render_visual_dashboards(st.session_state.analysis_result)

if __name__ == "__main__":
    main()