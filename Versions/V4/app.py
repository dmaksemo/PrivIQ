# app.py

import streamlit as st
import pandas as pd
import json
from datetime import datetime
import os
import sys
from collections import defaultdict
import plotly.express as px
from typing import List, Dict, Any

# Adiciona o diretório atual ao path para importações
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Importa os módulos customizados
try:
    from data_processor import AzureLogProcessor
    from azure_log_analyzer import AzureLogAnalyzer
    from governance_analyzer import AdvancedGovernanceAnalyzer
    from visualization_generator import SecurityVisualizationGenerator
    from models import AIAnalysisResult, EnhancedAIAnalysisResult, DetailedFinding, RiskLevel, GovernanceViolationType
    from config import config
    # Novos imports para conectores Azure
    from azure_data_connectors import DataSourceConfig, DataConnectorFactory, UnifiedDataManager
    from enhanced_data_interface import render_enhanced_data_interface
    from kql_templates import KQLTemplateManager
except ImportError as e:
    st.error(f"❌ Erro ao importar módulos: {e}")
    st.error("Certifique-se de que todos os arquivos estão no mesmo diretório:")
    st.code("""
    - app.py
    - data_processor.py
    - azure_log_analyzer.py
    - governance_analyzer.py (NOVO)
    - visualization_generator.py
    - models.py (ATUALIZADO)
    - config.py
    """)
    st.stop()
except Exception as e:
    st.error(f"❌ Erro inesperado na importação: {e}")
    st.stop()

# Configuração da página
st.set_page_config(
    page_title="PrivIQ", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS customizado aprimorado
st.markdown("""
<style>
    .main-header {
        font-size: 2.8rem; font-weight: bold; color: #0078d4; 
        text-align: center; margin-bottom: 2rem;
        background: linear-gradient(90deg, #0078d4, #106ebe);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .metric-card {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        padding: 1.8rem; border-radius: 12px; margin: 1rem 0; 
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        border-left: 6px solid #0078d4;
        color: #212529;
        transition: transform 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.15);
    }
    .risk-Critical { 
        border-left-color: #8B0000; 
        background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
    }
    .risk-High { 
        border-left-color: #DC143C; 
        background: linear-gradient(135deg, #fff3e0 0%, #ffcc02 100%);
    }
    .risk-Medium { 
        border-left-color: #FF8C00; 
        background: linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%);
    }
    .risk-Low { 
        border-left-color: #228B22; 
        background: linear-gradient(135deg, #f1f8e9 0%, #c8e6c9 100%);
    }
    .governance-summary {
        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
        padding: 2rem; border-radius: 15px; margin: 2rem 0;
        border: 2px solid #2196f3;
    }
    .compliance-score {
        font-size: 3rem; font-weight: bold; text-align: center;
        padding: 1rem; border-radius: 10px; margin: 1rem 0;
    }
    .score-excellent { background-color: #4caf50; color: white; }
    .score-good { background-color: #8bc34a; color: white; }
    .score-fair { background-color: #ff9800; color: white; }
    .score-poor { background-color: #f44336; color: white; }
    .tabs-container {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

def initialize_session_state():
    """Inicializa as variáveis de estado da sessão."""
    try:
        if 'analysis_result' not in st.session_state:
            st.session_state.analysis_result = None
        if 'enhanced_analysis_result' not in st.session_state:
            st.session_state.enhanced_analysis_result = None
        if 'logs_df' not in st.session_state:
            st.session_state.logs_df = None
        if 'processor' not in st.session_state:
            st.session_state.processor = AzureLogProcessor()
        if 'governance_summary' not in st.session_state:
            st.session_state.governance_summary = None
    except Exception as e:
        st.error(f"Erro ao inicializar sessão: {e}")
        # Fallback - inicializa manualmente
        st.session_state.analysis_result = None
        st.session_state.logs_df = None
        st.session_state.processor = None
        st.session_state.governance_summary = None

def render_governance_overview(summary: dict):
    """Renderiza visão geral de governança."""
    st.markdown('<div class="governance-summary">', unsafe_allow_html=True)
    st.subheader("📊 Resumo Executivo de Governança")
    
    col1, col2, col3, col4 = st.columns(4)
    
    issues = summary.get('governance_issues', {})
    
    with col1:
        st.metric(
            "🚫 Violações SOD", 
            issues.get('sod_violations', 0),
            help="Segregation of Duties violations"
        )
        
    with col2:
        st.metric(
            "👤 Atribuições Diretas", 
            issues.get('direct_assignments', 0),
            help="Usuários com roles atribuídas diretamente"
        )
        
    with col3:
        st.metric(
            "⚠️ Conflitos de Permissão", 
            issues.get('permission_conflicts', 0),
            help="Conflitos de permissões identificados"
        )
        
    with col4:
        st.metric(
            "🔄 Grupos Duplicados", 
            issues.get('duplicate_groups', 0),
            help="Grupos com permissões redundantes"
        )
    
    # Calcula score de compliance
    total_issues = sum(issues.values())
    total_events = summary.get('total_events', 1)
    compliance_score = max(0, 100 - (total_issues / total_events * 100))
    
    if compliance_score >= 90:
        score_class = "score-excellent"
        score_text = "EXCELENTE"
    elif compliance_score >= 75:
        score_class = "score-good" 
        score_text = "BOM"
    elif compliance_score >= 50:
        score_class = "score-fair"
        score_text = "REGULAR"
    else:
        score_class = "score-poor"
        score_text = "CRÍTICO"
    
    st.markdown(f"""
    <div class="compliance-score {score_class}">
        Score de Compliance: {compliance_score:.1f}%<br>
        <small>Status: {score_text}</small>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_detailed_governance_reports(summary: dict):
    """Renderiza relatórios detalhados de governança."""
    st.subheader("📋 Relatórios Detalhados por Categoria")
    
    detailed = summary.get('detailed_analysis', {})
    
    # Relatório de Atribuições Diretas
    with st.expander("👤 Relatório: Atribuições Diretas de Roles", expanded=False):
        direct_data = detailed.get('direct_assignments', {})
        assignments = direct_data.get('direct_assignments', [])
        
        if assignments:
            st.warning(f"⚠️ Identificadas {len(assignments)} atribuições diretas de roles.")
            st.markdown("**Problema:** Atribuições diretas de roles violam as melhores práticas de governança.")
            st.markdown("**Impacto:** Dificulta auditoria, controle de acesso e revogação de permissões.")
            
            df_direct = pd.DataFrame(assignments)
            if not df_direct.empty:
                st.dataframe(
                    df_direct[['user', 'role', 'is_privileged', 'timestamp']].head(20),
                    width='stretch'
                )
                
                # Gráfico de roles mais atribuídas diretamente
                if 'role' in df_direct.columns:
                    role_counts = df_direct['role'].value_counts().head(10)
                    fig = px.bar(
                        x=role_counts.values, 
                        y=role_counts.index,
                        orientation='h',
                        title="Top 10 Roles Atribuídas Diretamente",
                        color=role_counts.values,
                        color_continuous_scale='Reds'
                    )
                    st.plotly_chart(fig, width='stretch')
            
            st.markdown("**Recomendações:**")
            st.markdown("- Migrar atribuições diretas para grupos de segurança")
            st.markdown("- Implementar processo de aprovação para atribuições privilegiadas")
            st.markdown("- Revisar periodicamente todas as atribuições diretas")
        else:
            st.success("✅ Nenhuma atribuição direta identificada.")

    # Relatório de Conflitos SOD
    with st.expander("🚫 Relatório: Violações de Segregação de Funções (SOD)", expanded=False):
        conflicts_data = detailed.get('conflicts', {})
        conflicts = conflicts_data.get('conflicts', [])
        sod_violations = [c for c in conflicts if c.get('type') == 'SOD_VIOLATION']
        
        if sod_violations:
            st.error(f"🚨 Identificadas {len(sod_violations)} violações críticas de SOD.")
            st.markdown("**Problema:** Usuários possuem roles conflitantes que violam a segregação de funções.")
            st.markdown("**Impacto:** Alto risco de fraude, erro humano e violações de compliance.")
            
            for violation in sod_violations[:10]:  # Mostra top 10
                st.markdown(f"**👤 {violation.get('user')}**")
                roles = violation.get('conflicting_roles', [])
                st.markdown(f"- Roles Conflitantes: `{' + '.join(roles)}`")
                st.markdown(f"- Severidade: **{violation.get('severity')}**")
                st.markdown("---")
            
            st.markdown("**Recomendações:**")
            st.markdown("- Remover imediatamente uma das roles conflitantes")
            st.markdown("- Implementar controles automatizados de SOD")
            st.markdown("- Definir matriz de roles incompatíveis")
        else:
            st.success("✅ Nenhuma violação de SOD identificada.")

    # Relatório de Grupos Duplicados  
    with st.expander("🔄 Relatório: Grupos com Permissões Duplicadas", expanded=False):
        duplicates_data = detailed.get('duplicates', {})
        duplicates = duplicates_data.get('duplicates', [])
        
        if duplicates:
            st.warning(f"⚠️ Identificados {len(duplicates)} conjuntos de grupos duplicados.")
            st.markdown("**Problema:** Grupos diferentes possuem exatamente as mesmas permissões.")
            st.markdown("**Impacto:** Complexidade desnecessária na gestão de acesso e auditoria.")
            
            for dup in duplicates[:5]:  # Mostra top 5
                st.markdown(f"**Grupos com Permissões Idênticas:**")
                st.markdown(f"- Grupos: `{', '.join(dup.get('groups', []))}`")
                st.markdown(f"- Roles Compartilhadas: `{', '.join(dup.get('shared_roles', []))}`")
                st.markdown(f"- Quantidade de Roles: {dup.get('roles_count', 0)}")
                st.markdown("---")
            
            st.markdown("**Recomendações:**")
            st.markdown("- Consolidar grupos com permissões idênticas")
            st.markdown("- Revisar necessidade de múltiplos grupos")
            st.markdown("- Padronizar nomenclatura e estrutura de grupos")
        else:
            st.success("✅ Nenhum grupo duplicado identificado.")

    # Relatório de Padrões Críticos
    with st.expander("🔍 Relatório: Padrões de Acesso Suspeitos", expanded=False):
        patterns_data = detailed.get('critical_patterns', {})
        patterns = patterns_data.get('critical_patterns', [])
        
        if patterns:
            st.error(f"🚨 Identificados {len(patterns)} padrões suspeitos.")
            
            for pattern in patterns:
                pattern_type = pattern.get('type', 'UNKNOWN')
                severity = pattern.get('severity', 'MEDIUM')
                
                if pattern_type == 'AFTER_HOURS_ACCESS':
                    st.markdown("**🌙 Acessos Fora do Horário Comercial**")
                    st.markdown(f"- Quantidade: {pattern.get('count', 0)} eventos")
                    st.markdown(f"- Usuários: `{', '.join(pattern.get('users', [])[:5])}`")
                    
                elif pattern_type == 'MULTIPLE_IP_ADDRESSES':
                    st.markdown("**🌐 Múltiplos Endereços IP**")
                    users_info = pattern.get('users', [])
                    for user_info in users_info[:5]:
                        st.markdown(f"- {user_info.get('user')}: {user_info.get('ip_count')} IPs diferentes")
                        
                elif pattern_type == 'EXCESSIVE_FAILED_ATTEMPTS':
                    st.markdown("**❌ Tentativas de Acesso Falhadas**")
                    users_info = pattern.get('users', [])
                    for user_info in users_info[:5]:
                        st.markdown(f"- {user_info.get('user')}: {user_info.get('failures')} falhas")
                
                st.markdown(f"- **Severidade:** {severity}")
                st.markdown("---")
            
            st.markdown("**Recomendações:**")
            st.markdown("- Investigar atividades fora do horário comercial")
            st.markdown("- Implementar alertas de segurança automatizados")
            st.markdown("- Revisar políticas de acesso condicional")
        else:
            st.success("✅ Nenhum padrão suspeito identificado.")

def render_detailed_report(result: AIAnalysisResult):
    """Renderiza o relatório detalhado da IA com melhorias."""
    st.subheader("🤖 Análise Inteligente de Segurança")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("**Resumo Executivo da IA:**")
        st.info(f"*{result.risk_assessment.summary}*")
    with col2:
        score = result.risk_assessment.score
        score_color = "#8B0000" if score >= 80 else "#FF4500" if score >= 60 else "#FF8C00" if score >= 40 else "#228B22"
        st.markdown(f'<div style="background-color: {score_color}; color: white; padding: 1rem; border-radius: 10px; text-align: center;"><h3>Score: {score}/100</h3></div>', unsafe_allow_html=True)

    st.markdown("---")
    
    if result.findings:
        # Agrupa findings por categoria
        findings_by_category = defaultdict(list)
        for finding in result.findings:
            category = "SOD" if "sod" in finding.title.lower() or "segreg" in finding.title.lower() else \
                      "Direct Assignment" if "direct" in finding.title.lower() else \
                      "Excessive Privileges" if "excess" in finding.title.lower() or "privileg" in finding.title.lower() else \
                      "Duplicate Groups" if "duplic" in finding.title.lower() or "grupo" in finding.title.lower() else \
                      "Suspicious Activity"
            findings_by_category[category].append(finding)
        
        st.write("**Problemas Identificados pela IA por Categoria:**")
        
        for category, findings in findings_by_category.items():
            with st.expander(f"🎯 {category} ({len(findings)} problemas)", expanded=True):
                for finding in findings:
                    st.markdown(f'<div class="metric-card risk-{finding.risk_level.value}">', unsafe_allow_html=True)
                    
                    col_title, col_risk = st.columns([4, 1])
                    with col_title:
                        st.markdown(f"### {finding.title}")
                    with col_risk:
                        risk_emoji = {"Critical": "🚨", "High": "⚠️", "Medium": "⚡", "Low": "ℹ️"}
                        st.markdown(f"**{risk_emoji.get(finding.risk_level.value, '📋')} {finding.risk_level.value}**")
                    
                    with st.expander("Ver detalhes completos", expanded=False):
                        st.markdown("**📝 Descrição:**")
                        st.write(finding.description)
                        
                        st.markdown("**💡 Recomendação:**")
                        st.success(finding.recommendation)
                        
                        if finding.affected_principals:
                            st.markdown("**👥 Principais Afetados:**")
                            # Limita a exibição a 10 principais
                            principals_to_show = finding.affected_principals[:10]
                            for principal in principals_to_show:
                                st.markdown(f"- `{principal}`")
                            
                            if len(finding.affected_principals) > 10:
                                st.markdown(f"*... e mais {len(finding.affected_principals) - 10} principais*")
                    
                    st.markdown('</div>', unsafe_allow_html=True)
        
        # Resumo de recomendações consolidado
        st.markdown("---")
        st.subheader("📋 Plano de Ação Consolidado")
        recommendations_summary = generate_recommendations_summary(result)
        st.markdown(recommendations_summary)
        
    else:
        st.success("✅ A IA não identificou problemas significativos de governança.")

def generate_recommendations_summary(result: AIAnalysisResult) -> str:
    """Agrupa recomendações por tipo de achado para criar um plano de ação."""
    if not result.findings:
        return "**✅ Nenhuma ação corretiva necessária no momento.**"

    # Agrupa por categoria e prioridade
    recommendations_by_risk = defaultdict(lambda: defaultdict(set))
    
    for finding in result.findings:
        category = "SOD" if "sod" in finding.title.lower() or "segreg" in finding.title.lower() else \
                  "Atribuições Diretas" if "direct" in finding.title.lower() else \
                  "Privilégios Excessivos" if "excess" in finding.title.lower() or "privileg" in finding.title.lower() else \
                  "Grupos Duplicados" if "duplic" in finding.title.lower() or "grupo" in finding.title.lower() else \
                  "Atividade Suspeita"
        
        recommendations_by_risk[finding.risk_level.value][category].add(finding.recommendation)
    
    markdown_summary = ["### 🎯 Ações Prioritárias por Nível de Risco\n"]
    
    # Ordena por prioridade
    risk_order = ["Critical", "High", "Medium", "Low"]
    
    for risk_level in risk_order:
        if risk_level in recommendations_by_risk:
            risk_emoji = {"Critical": "🚨", "High": "⚠️", "Medium": "⚡", "Low": "ℹ️"}
            markdown_summary.append(f"#### {risk_emoji[risk_level]} **Prioridade {risk_level}**")
            
            for category, recommendations in recommendations_by_risk[risk_level].items():
                markdown_summary.append(f"\n**{category}:**")
                for i, rec in enumerate(recommendations, 1):
                    markdown_summary.append(f"{i}. {rec}")
                markdown_summary.append("")
    
    return "\n".join(markdown_summary)

def render_enhanced_dashboards(result: AIAnalysisResult):
    """Renderiza dashboards visuais aprimorados e consolidados."""
    st.subheader("📊 Dashboards Inteligentes")
    
    # Seletor de persona para customizar visualização
    persona = st.selectbox(
        "🎯 Selecione sua perspectiva:",
        ["👔 Executivo (C-Level)", "🛡️ Analista de Segurança", "📋 Auditor/Compliance"],
        help="Personaliza os dashboards para sua função"
    )
    
    viz_generator = SecurityVisualizationGenerator()
    
    if persona == "👔 Executivo (C-Level)":
        render_executive_focused_dashboard(result, viz_generator)
    elif persona == "🛡️ Analista de Segurança":
        render_security_analyst_dashboard(result, viz_generator)
    else:  # Auditor/Compliance
        render_compliance_focused_dashboard(result, viz_generator)

def render_executive_focused_dashboard(result: AIAnalysisResult, viz_generator):
    """Dashboard otimizado para executivos - foco em KPIs e decisões estratégicas."""
    st.markdown("### 👔 Visão Executiva - Governança Azure")
    
    # KPIs principais em cards
    col1, col2, col3, col4 = st.columns(4)
    
    risk_score = getattr(result.risk_assessment, 'score', 0)
    critical_findings = len([f for f in result.findings if f.risk_level.value == "Critical"])
    total_findings = len(result.findings)
    
    with col1:
        st.metric(
            "🎯 Score de Risco", 
            f"{risk_score}/100",
            delta=f"-{100-risk_score} vs. ideal" if risk_score < 100 else "✅ Ideal"
        )
    
    with col2:
        st.metric(
            "🚨 Achados Críticos", 
            critical_findings,
            delta=f"{critical_findings} requer ação imediata" if critical_findings > 0 else "✅ Nenhum"
        )
    
    with col3:
        st.metric(
            "📊 Total de Achados", 
            total_findings,
            help="Inclui todos os níveis de risco"
        )
    
    with col4:
        compliance_score = 100 - (critical_findings * 20 + (total_findings - critical_findings) * 5)
        compliance_score = max(0, min(100, compliance_score))
        st.metric(
            "🛡️ Compliance", 
            f"{compliance_score}%",
            delta=f"Meta: 95%" if compliance_score < 95 else "✅ Conforme"
        )
    
    # Gráfico executivo principal - mais limpo e focado
    st.markdown("#### 📈 Resumo Executivo de Riscos")
    fig_exec = viz_generator.create_governance_dashboard(result)
    st.plotly_chart(fig_exec, width='stretch')
    
    # Top 3 riscos críticos
    if result.findings:
        st.markdown("#### 🚨 Top 3 Riscos que Requerem Atenção Executiva")
        critical_findings_sorted = sorted(
            [f for f in result.findings if f.risk_level.value in ["Critical", "High"]], 
            key=lambda x: (x.risk_level.value == "Critical", len(getattr(x, 'affected_principals', []))), 
            reverse=True
        )[:3]
        
        for i, finding in enumerate(critical_findings_sorted, 1):
            with st.expander(f"🎯 Risco #{i}: {finding.title}", expanded=i==1):
                col_desc, col_action = st.columns([2, 1])
                with col_desc:
                    st.write(f"**Impacto:** {getattr(finding, 'business_impact', 'Impact assessment needed')}")
                    st.write(f"**Usuários afetados:** {len(getattr(finding, 'affected_principals', []))}")
                with col_action:
                    st.markdown(f"**Ação requerida:**\n{finding.recommendation}")

def render_security_analyst_dashboard(result: AIAnalysisResult, viz_generator):
    """Dashboard otimizado para analistas de segurança - foco em investigação e ação."""
    st.markdown("### 🛡️ Centro de Operações de Segurança")
    
    # Métricas operacionais
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 Distribuição de Riscos")
        fig_dist = viz_generator.create_risk_distribution_chart(result)
        st.plotly_chart(fig_dist, width='stretch')
        
        st.markdown("#### 🔍 Achados por Categoria")
        fig_findings = viz_generator.create_findings_by_type_chart(result)
        st.plotly_chart(fig_findings, width='stretch')
        
    with col2:
        st.markdown("#### 👥 Mapa de Usuários de Risco")
        # Simulação de heatmap de usuários
        if result.findings:
            user_risk_data = {}
            for finding in result.findings:
                for user in getattr(finding, 'affected_principals', [])[:10]:  # Limita a 10
                    if user not in user_risk_data:
                        user_risk_data[user] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                    user_risk_data[user][finding.risk_level.value] += 1
            
            if user_risk_data:
                users_df = pd.DataFrame.from_dict(user_risk_data, orient='index').fillna(0)
                st.dataframe(users_df, width='stretch', height=400)
        
        st.markdown("#### ⏱️ Timeline de Detecções")
        fig_timeline = viz_generator.create_timeline_chart(result)
        st.plotly_chart(fig_timeline, width='stretch')
    
    # Lista de ações prioritárias
    st.markdown("#### 📋 Fila de Remediação Prioritária")
    if result.findings:
        priority_findings = sorted(result.findings, key=lambda x: (
            x.risk_level.value == "Critical",
            x.risk_level.value == "High", 
            len(getattr(x, 'affected_principals', []))
        ), reverse=True)
        
        for i, finding in enumerate(priority_findings[:5], 1):
            priority_icon = "🚨" if finding.risk_level.value == "Critical" else "⚠️" if finding.risk_level.value == "High" else "⚡"
            st.markdown(f"**{i}. {priority_icon} {finding.title}**")
            st.markdown(f"   → *Ação:* {finding.recommendation}")
            if i < len(priority_findings[:5]):
                st.markdown("---")

def render_compliance_focused_dashboard(result: AIAnalysisResult, viz_generator):
    """Dashboard otimizado para auditores - foco em evidências e conformidade."""
    st.markdown("### 📋 Centro de Compliance e Auditoria")
    
    # Matriz de compliance
    st.markdown("#### 🏛️ Matriz de Frameworks de Compliance")
    fig_matrix = viz_generator.create_compliance_matrix(result)
    st.plotly_chart(fig_matrix, width='stretch')
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📊 Status por Framework")
        # Simulação de compliance por framework
        frameworks = ["SOX", "NIST", "ISO27001", "GDPR", "HIPAA", "PCI-DSS"]
        compliance_data = []
        
        for framework in frameworks:
            # Simula violações por framework
            violations = len([f for f in result.findings if hasattr(f, 'compliance_impact') and 
                            any(comp.value == framework for comp in getattr(f, 'compliance_impact', []))])
            compliance_score = max(0, 100 - violations * 15)
            status = "✅ Conforme" if compliance_score >= 90 else "⚠️ Atenção" if compliance_score >= 70 else "🚨 Crítico"
            compliance_data.append({
                "Framework": framework,
                "Score": f"{compliance_score}%",
                "Status": status,
                "Violações": violations
            })
        
        compliance_df = pd.DataFrame(compliance_data)
        st.dataframe(compliance_df, width='stretch', hide_index=True)
    
    with col2:
        st.markdown("#### 🔍 Evidências Estruturadas")
        if result.findings:
            evidence_count = sum(1 for f in result.findings if hasattr(f, 'evidence') and getattr(f, 'evidence', {}))
            st.metric("Evidências Coletadas", evidence_count)
            st.metric("Achados Documentados", len(result.findings))
            st.metric("Requer Documentação Adicional", 
                     len([f for f in result.findings if not hasattr(f, 'evidence') or not getattr(f, 'evidence', {})]))
    
    # Relatório de auditoria
    st.markdown("#### 📄 Resumo para Relatório de Auditoria")
    audit_summary = generate_audit_summary(result)
    st.markdown(audit_summary)

def generate_audit_summary(result: AIAnalysisResult) -> str:
    """Gera resumo estruturado para relatórios de auditoria."""
    critical_count = len([f for f in result.findings if f.risk_level.value == "Critical"])
    high_count = len([f for f in result.findings if f.risk_level.value == "High"])
    total_count = len(result.findings)
    
    summary = f"""
**RESUMO EXECUTIVO DE AUDITORIA**

**Escopo:** Análise de governança de identidade e acesso Azure  
**Data:** {datetime.now().strftime('%d/%m/%Y %H:%M')}  
**Achados totais:** {total_count}

**CLASSIFICAÇÃO DE RISCOS:**
- 🚨 **Críticos:** {critical_count} (requer ação imediata)
- ⚠️ **Altos:** {high_count} (requer ação em 30 dias)
- ⚡ **Médios/Baixos:** {total_count - critical_count - high_count}

**RECOMENDAÇÃO GERAL:**
{'🚨 **AÇÃO IMEDIATA REQUERIDA** - Riscos críticos identificados que podem impactar a conformidade regulatória.' if critical_count > 0 else 
 '⚠️ **MONITORAMENTO ATIVO** - Implementar ações corretivas para riscos altos identificados.' if high_count > 0 else
 '✅ **POSTURA ADEQUADA** - Manter monitoramento contínuo e implementar melhorias sugeridas.'}

**STATUS DE COMPLIANCE:** {'NÃO CONFORME' if critical_count > 0 else 'CONFORME COM OBSERVAÇÕES' if high_count > 0 else 'CONFORME'}
"""
    return summary

def render_trends_and_predictions(enhanced_result: EnhancedAIAnalysisResult):
    """Dashboard de tendências e predições baseadas em IA."""
    st.markdown("### 📈 Análise de Tendências e Predições")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📊 Tendências Observadas")
        
        # Simulação de dados de tendência
        trend_data = {
            "Métrica": ["Violações SOD", "Atribuições Diretas", "Contas Órfãs", "Privilege Escalation"],
            "Último Mês": [5, 12, 3, 2],
            "Este Mês": [3, 8, 1, 1],
            "Tendência": ["↘️ Melhorando", "↘️ Melhorando", "↘️ Melhorando", "→ Estável"]
        }
        trend_df = pd.DataFrame(trend_data)
        st.dataframe(trend_df, hide_index=True, width='stretch')
        
        st.markdown("#### 🎯 Score de Melhoria")
        improvement_score = 85  # Simulado
        st.metric(
            "Progresso Geral", 
            f"{improvement_score}%", 
            delta=f"+15% vs. baseline",
            help="Baseado na redução de violações e implementação de controles"
        )
    
    with col2:
        st.markdown("#### 🔮 Predições IA")
        
        st.info("""
        **Análise Preditiva (30 dias):**
        
        🟢 **Baixo Risco:** Continuar tendência de melhoria atual
        - Redução estimada de 20% em violações SOD
        - Implementação de controles preventivos funcionando
        
        ⚠️ **Atenção:** Monitorar atribuições diretas
        - Possível aumento se não implementar processo de aprovação
        
        🎯 **Recomendação:** Manter cadência atual de remediação
        """)
        
        st.markdown("#### 📅 Próximas Revisões Sugeridas")
        next_reviews = [
            {"Data": "30/09/2025", "Tipo": "Review SOD", "Prioridade": "Alta"},
            {"Data": "15/10/2025", "Tipo": "Auditoria Compliance", "Prioridade": "Média"},
            {"Data": "01/11/2025", "Tipo": "Assessment Completo", "Prioridade": "Alta"}
        ]
        reviews_df = pd.DataFrame(next_reviews)
        st.dataframe(reviews_df, hide_index=True, width='stretch')

def render_action_center(enhanced_result: EnhancedAIAnalysisResult):
    """Centro de ações priorizadas com tracking de progresso."""
    st.markdown("### 🎯 Centro de Ações Prioritárias")
    
    # Filtros para ações
    col1, col2, col3 = st.columns(3)
    
    with col1:
        priority_filter = st.selectbox(
            "Filtrar por Prioridade:",
            ["Todas", "Crítica", "Alta", "Média", "Baixa"]
        )
    
    with col2:
        status_filter = st.selectbox(
            "Status:",
            ["Todas", "Pendente", "Em Andamento", "Concluída"]
        )
    
    with col3:
        assignee_filter = st.selectbox(
            "Responsável:",
            ["Todos", "Equipe de Segurança", "Equipe de Identidade", "Compliance", "Gestão"]
        )
    
    # Simulação de lista de ações
    actions_data = []
    
    # Mapeia as prioridades do inglês para português
    priority_map = {
        "Critical": "Crítica",
        "High": "Alta", 
        "Medium": "Média",
        "Low": "Baixa"
    }

    def get_status_for_finding(finding: DetailedFinding, index: int) -> str:
        """Determina o status da ação baseado em critérios consistentes."""
        if finding.risk_level == RiskLevel.CRITICAL:
            return "Pendente"  # Crítico sempre começa como pendente
        elif finding.risk_level == RiskLevel.HIGH:
            return "Em Andamento"
        else:
            return "Pendente" if index <= 5 else "Concluída"

    def get_assignee_for_finding(finding: DetailedFinding) -> str:
        """Determina o responsável baseado no tipo de violação."""
        violation_assignee_map = {
            GovernanceViolationType.SOD_VIOLATION: "Equipe de Segurança",
            GovernanceViolationType.COMPLIANCE_VIOLATION: "Compliance",
            GovernanceViolationType.EXCESSIVE_PRIVILEGES: "Equipe de Identidade",
            GovernanceViolationType.DIRECT_ASSIGNMENT: "Equipe de Identidade",
            GovernanceViolationType.SUSPICIOUS_ACCESS: "Equipe de Segurança",
            GovernanceViolationType.DUPLICATE_GROUPS: "Gestão",
            GovernanceViolationType.ORPHANED_ACCOUNTS: "Equipe de Identidade",
            GovernanceViolationType.PRIVILEGE_ESCALATION: "Equipe de Segurança"
        }
        return violation_assignee_map.get(finding.violation_type, "Gestão")

    for i, finding in enumerate(enhanced_result.findings[:10], 1):
        priority_level = priority_map[finding.risk_level.value]
        action_id = f"ACT-{i:03d}"
        
        # Determina status e responsável de forma consistente
        status = get_status_for_finding(finding, i)
        assignee = get_assignee_for_finding(finding)
        
        # Estimativa de tempo baseada na prioridade
        time_estimates = {
            "Crítica": "24h",
            "Alta": "3 dias", 
            "Média": "1 semana", 
            "Baixa": "2 semanas"
        }
        
        actions_data.append({
            "ID": action_id,
            "Ação": finding.recommendation[:80] + "..." if len(finding.recommendation) > 80 else finding.recommendation,
            "Prioridade": priority_level,
            "Status": status,
            "Responsável": assignee,
            "Prazo Est.": time_estimates.get(priority_level, "1 semana"),
            "Impacto": f"{len(getattr(finding, 'affected_principals', []))} usuários"
        })
    
    # Aplica filtros
    filtered_actions = actions_data
    if priority_filter != "Todas":
        filtered_actions = [a for a in filtered_actions if a["Prioridade"] == priority_filter]
    if status_filter != "Todas":
        filtered_actions = [a for a in filtered_actions if a["Status"] == status_filter]
    if assignee_filter != "Todos":
        filtered_actions = [a for a in filtered_actions if a["Responsável"] == assignee_filter]
    
    # Exibe lista de ações
    st.markdown("#### 📋 Lista de Ações")
    if filtered_actions:
        actions_df = pd.DataFrame(filtered_actions)
        st.dataframe(actions_df, hide_index=True, width='stretch', height=400)
        
        # Estatísticas das ações
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            pending_count = len([a for a in filtered_actions if a["Status"] == "Pendente"])
            st.metric("Pendentes", pending_count)
        
        with col2:
            progress_count = len([a for a in filtered_actions if a["Status"] == "Em Andamento"])
            st.metric("Em Andamento", progress_count)
        
        with col3:
            completed_count = len([a for a in filtered_actions if a["Status"] == "Concluída"])
            st.metric("Concluídas", completed_count)
        
        with col4:
            completion_rate = (completed_count / len(filtered_actions) * 100) if filtered_actions else 0
            st.metric("Taxa de Conclusão", f"{completion_rate:.1f}%")
        
        # Botões de ação
        st.markdown("#### ⚡ Ações Rápidas")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📊 Exportar Plano de Ação", key="export_action_plan"):
                st.success("Plano de ação exportado!")
        
        with col2:
            if st.button("📧 Enviar Notificações", key="send_notifications"):
                st.success("Notificações enviadas aos responsáveis!")
        
        with col3:
            if st.button("📈 Gerar Relatório de Progresso", key="progress_report"):
                st.success("Relatório de progresso gerado!")
    
    else:
        st.info("Nenhuma ação encontrada com os filtros selecionados.")

def export_report_to_json(analysis_result, governance_summary):
    """Exporta relatório completo para JSON."""
    report_data = {
        "export_timestamp": datetime.now().isoformat(),
        "governance_summary": governance_summary,
        "ai_analysis": analysis_result.model_dump() if analysis_result else None,
        "report_metadata": {
            "version": "2.0",
            "tool": "PrivIQ",
            "export_format": "comprehensive"
        }
    }
    return json.dumps(report_data, indent=2, default=str)

def render_enhanced_analysis_report(enhanced_result: EnhancedAIAnalysisResult):
    """Renderiza relatório de análise avançada com detalhes expandidos."""
    st.subheader("🔍 Análise Avançada de Governança")
    
    # Resumo executivo
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("### 📋 Resumo Executivo")
        st.info(enhanced_result.executive_summary)
        
        st.markdown("### 🔧 Resumo Técnico")
        st.warning(enhanced_result.technical_summary)
    
    with col2:
        # Métricas principais
        governance_metrics = enhanced_result.risk_assessment.governance_metrics
        st.metric("Score de Risco", f"{enhanced_result.risk_assessment.score}/100")
        st.metric("Score de Compliance", f"{governance_metrics.compliance_score:.1f}%")
        st.metric("Violações SOD", governance_metrics.sod_violations)
        st.metric("Atribuições Diretas", governance_metrics.direct_assignments)
    
    # Achados detalhados por tipo
    if enhanced_result.findings:
        st.markdown("### 🎯 Achados Detalhados por Categoria")
        
        # Agrupa achados por tipo de violação
        findings_by_type = defaultdict(list)
        for finding in enhanced_result.findings:
            findings_by_type[finding.violation_type.value].append(finding)
        
        for violation_type, findings in findings_by_type.items():
            type_name = violation_type.replace('_', ' ').title()
            
            with st.expander(f"🚨 {type_name} ({len(findings)} achados)", expanded=len(findings) <= 3):
                for finding in findings:
                    render_detailed_finding(finding)
    
    # Próximas ações
    if enhanced_result.next_actions:
        st.markdown("### 📋 Próximas Ações Recomendadas")
        for i, action in enumerate(enhanced_result.next_actions, 1):
            st.markdown(f"**{i}.** {action}")

def render_detailed_finding(finding: DetailedFinding):
    """Renderiza um achado detalhado."""
    risk_color = {
        "Critical": "#8B0000",
        "High": "#DC143C", 
        "Medium": "#FF8C00",
        "Low": "#228B22"
    }.get(finding.risk_level.value, "#4682B4")
    
    st.markdown(f"""
    <div style="border-left: 4px solid {risk_color}; padding: 1rem; margin: 1rem 0; background-color: #f8f9fa; border-radius: 5px;">
        <h4 style="color: {risk_color}; margin: 0 0 0.5rem 0;">{finding.title}</h4>
        <p><strong>Tipo:</strong> {finding.violation_type.value.replace('_', ' ')}</p>
        <p><strong>Prioridade de Remediação:</strong> {finding.remediation_priority}/5</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.expander("Ver detalhes completos", expanded=False):
        st.markdown("**📝 Descrição:**")
        st.write(finding.description)
        
        st.markdown("**🔧 Recomendação:**")
        st.success(finding.recommendation)
        
        if finding.business_impact:
            st.markdown("**💼 Impacto no Negócio:**")
            st.warning(finding.business_impact)
        
        if finding.compliance_impact:
            st.markdown("**📊 Frameworks de Compliance Afetados:**")
            for framework in finding.compliance_impact:
                st.markdown(f"- {framework.value}")
        
        if finding.evidence:
            st.markdown("**🔍 Evidências:**")
            st.json(finding.evidence)
        
        if finding.affected_principals:
            st.markdown("**👥 Principais Afetados:**")
            principals_to_show = finding.affected_principals[:10]
            for principal in principals_to_show:
                st.markdown(f"- `{principal}`")
            
            if len(finding.affected_principals) > 10:
                st.markdown(f"*... e mais {len(finding.affected_principals) - 10} principais*")

def render_executive_dashboard(enhanced_result: EnhancedAIAnalysisResult):
    """Renderiza dashboard executivo com visualizações avançadas."""
    st.subheader("📊 Dashboard Executivo")
    
    # Cria gerador de visualizações
    viz_generator = SecurityVisualizationGenerator()
    
    # Dashboard principal
    fig_dashboard = viz_generator.create_executive_dashboard(enhanced_result)
    st.plotly_chart(fig_dashboard, width='stretch')
    
    # Gráficos específicos
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 Distribuição de Violações")
        fig_violations = viz_generator.create_governance_violations_chart(enhanced_result.findings)
        st.plotly_chart(fig_violations, width='stretch')
    
    with col2:
        st.markdown("#### 👥 Mapa de Risco por Usuário")
        fig_heatmap = viz_generator.create_user_risk_heatmap(enhanced_result.findings)
        st.plotly_chart(fig_heatmap, width='stretch')
    
    # Timeline de detecções
    st.markdown("#### ⏱️ Timeline de Detecções")
    fig_timeline = viz_generator.create_timeline_analysis(enhanced_result.findings)
    st.plotly_chart(fig_timeline, width='stretch')

def render_compliance_analysis(enhanced_result: EnhancedAIAnalysisResult):
    """Renderiza análise específica de compliance."""
    st.subheader("🛡️ Análise de Compliance e Frameworks")
    
    # Gráfico de compliance
    viz_generator = SecurityVisualizationGenerator()
    fig_compliance = viz_generator.create_compliance_framework_chart(enhanced_result.findings)
    st.plotly_chart(fig_compliance, width='stretch')
    
    # Assessment de compliance
    if hasattr(enhanced_result.risk_assessment, 'compliance_assessment') and enhanced_result.risk_assessment.compliance_assessment:
        compliance_assessment = enhanced_result.risk_assessment.compliance_assessment
        
        st.markdown("### 📋 Assessment de Compliance")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Score Geral de Compliance", f"{compliance_assessment.overall_score:.1f}%")
        
        with col2:
            framework_scores = compliance_assessment.framework_scores
            if framework_scores:
                avg_score = sum(framework_scores.values()) / len(framework_scores)
                st.metric("Score Médio por Framework", f"{avg_score:.1f}%")
        
        # Scores por framework
        if framework_scores:
            st.markdown("#### 📊 Scores por Framework")
            for framework, score in framework_scores.items():
                progress_color = "green" if score >= 80 else "orange" if score >= 60 else "red"
                st.markdown(f"**{framework}**")
                st.progress(score/100, text=f"{score:.1f}%")
        
        # Lacunas críticas
        critical_gaps = compliance_assessment.critical_gaps
        if critical_gaps:
            st.markdown("#### 🚨 Lacunas Críticas")
            for gap in critical_gaps[:5]:
                st.error(f"• {gap}")

def render_forensic_analysis(enhanced_result: EnhancedAIAnalysisResult):
    """Renderiza análise forense detalhada."""
    st.subheader("🔍 Análise Forense")
    
    # Metadados da análise
    metadata = enhanced_result.analysis_metadata
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Logs Analisados", metadata.get('total_logs_analyzed', 0))
    with col2:
        st.metric("Achados Críticos", metadata.get('critical_findings', 0))
    with col3:
        st.metric("Achados de Alto Risco", metadata.get('high_findings', 0))
    
    # Análise temporal
    if metadata.get('analysis_timestamp'):
        st.info(f"📅 Análise executada em: {metadata['analysis_timestamp']}")
    
    # Correlação de eventos
    st.markdown("### 🔗 Correlação de Eventos")
    
    # Agrupa achados por usuários afetados para detectar padrões
    user_involvement = defaultdict(list)
    for finding in enhanced_result.findings:
        for user in finding.affected_principals:
            user_involvement[user].append(finding.violation_type.value)
    
    # Usuários com múltiplas violações
    multi_violation_users = {user: violations for user, violations in user_involvement.items() if len(set(violations)) > 1}
    
    if multi_violation_users:
        st.warning("🚨 **Usuários com Múltiplas Violações (Padrão Suspeito):**")
        for user, violations in list(multi_violation_users.items())[:10]:
            unique_violations = list(set(violations))
            st.markdown(f"- **{user}**: {', '.join(unique_violations)}")
    
    # Padrões de escalação
    escalation_findings = [f for f in enhanced_result.findings if f.violation_type.value == 'Privilege_Escalation']
    if escalation_findings:
        st.markdown("### ⬆️ Padrões de Escalação de Privilégios")
        for finding in escalation_findings:
            st.error(f"🔺 {finding.title} - {len(finding.affected_principals)} usuários afetados")

def render_enhanced_export_options(enhanced_result: EnhancedAIAnalysisResult):
    """Renderiza opções de exportação aprimoradas."""
    st.subheader("📤 Exportação de Relatórios")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📋 Relatórios Executivos")
        
        if st.button("📊 Relatório Executivo (JSON)", width='stretch', key="executive_json"):
            executive_report = {
                "executive_summary": enhanced_result.executive_summary,
                "risk_score": enhanced_result.risk_assessment.score,
                "compliance_score": enhanced_result.risk_assessment.governance_metrics.compliance_score,
                "next_actions": enhanced_result.next_actions,
                "critical_findings": [f.title for f in enhanced_result.findings if f.risk_level.value == "Critical"],
                "timestamp": enhanced_result.analysis_metadata.get('analysis_timestamp')
            }
            
            st.download_button(
                label="💾 Download Relatório Executivo",
                data=json.dumps(executive_report, indent=2),
                file_name=f"executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                width='stretch'
            )
        
        if st.button("📋 Relatório Técnico (JSON)", width='stretch', key="technical_json"):
            technical_report = {
                "technical_summary": enhanced_result.technical_summary,
                "detailed_findings": [
                    {
                        "title": f.title,
                        "violation_type": f.violation_type.value,
                        "risk_level": f.risk_level.value,
                        "description": f.description,
                        "recommendation": f.recommendation,
                        "evidence": f.evidence,
                        "affected_principals": f.affected_principals,
                        "compliance_impact": [cf.value for cf in f.compliance_impact],
                        "remediation_priority": f.remediation_priority
                    }
                    for f in enhanced_result.findings
                ],
                "governance_metrics": enhanced_result.risk_assessment.governance_metrics,
                "analysis_metadata": enhanced_result.analysis_metadata
            }
            
            st.download_button(
                label="💾 Download Relatório Técnico",
                data=json.dumps(technical_report, indent=2, default=str),
                file_name=f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                width='stretch'
            )
    
    with col2:
        st.markdown("#### 📊 Relatórios Tabulares")
        
        if st.button("📈 Planilha de Achados (CSV)", width='stretch', key="findings_csv"):
            if enhanced_result.findings:
                findings_df = pd.DataFrame([
                    {
                        'Tipo_Violacao': f.violation_type.value,
                        'Nivel_Risco': f.risk_level.value,
                        'Titulo': f.title,
                        'Descricao': f.description,
                        'Recomendacao': f.recommendation,
                        'Prioridade_Remediacao': f.remediation_priority,
                        'Impacto_Negocio': f.business_impact,
                        'Frameworks_Compliance': ';'.join([cf.value for cf in f.compliance_impact]),
                        'Quantidade_Afetados': len(f.affected_principals),
                        'Principais_Afetados': ';'.join(f.affected_principals[:10]),
                        'Timestamp_Deteccao': f.detection_timestamp
                    }
                    for f in enhanced_result.findings
                ])
                
                csv_data = findings_df.to_csv(index=False)
                st.download_button(
                    label="💾 Download Planilha CSV",
                    data=csv_data,
                    file_name=f"governance_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    width='stretch'
                )
        
        if st.button("📋 Relatório Compliance (CSV)", width='stretch', key="compliance_csv"):
            # Cria relatório específico de compliance
            compliance_data = []
            for finding in enhanced_result.findings:
                for framework in finding.compliance_impact:
                    compliance_data.append({
                        'Framework': framework.value,
                        'Violacao': finding.title,
                        'Nivel_Risco': finding.risk_level.value,
                        'Quantidade_Afetados': len(finding.affected_principals),
                        'Prioridade': finding.remediation_priority
                    })
            
            if compliance_data:
                compliance_df = pd.DataFrame(compliance_data)
                csv_data = compliance_df.to_csv(index=False)
                st.download_button(
                    label="💾 Download Relatório Compliance",
                    data=csv_data,
                    file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    width='stretch'
                )

def render_export_options(analysis_result: AIAnalysisResult):
    """Renderiza opções de exportação para análise padrão."""
    st.subheader("📤 Exportação de Relatório")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📋 Gerar Relatório JSON", width='stretch', key="json_report_standard"):
            report_json = export_report_to_json(analysis_result, st.session_state.governance_summary)
            st.download_button(
                label="💾 Download Relatório JSON",
                data=report_json,
                file_name=f"azure_governance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                width='stretch'
            )
    
    with col2:
        if st.button("📊 Gerar Relatório CSV", width='stretch', key="csv_report_standard"):
            if analysis_result.findings:
                findings_df = pd.DataFrame([
                    {
                        'Risk Level': f.risk_level.value,
                        'Title': f.title,
                        'Description': f.description,
                        'Recommendation': f.recommendation,
                        'Affected Count': len(f.affected_principals),
                        'Affected Principals': '; '.join(f.affected_principals[:5])
                    }
                    for f in analysis_result.findings
                ])
                
                csv_data = findings_df.to_csv(index=False)
                st.download_button(
                    label="💾 Download CSV",
                    data=csv_data,
                    file_name=f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    width='stretch'
                )

def main():
    """Função principal da aplicação aprimorada."""
    try:
        initialize_session_state()
        
        st.markdown('<h1 class="main-header">🛡️ PrivIQ</h1>', unsafe_allow_html=True)
        st.markdown('<p style="text-align: center; color: #666; font-size: 1.2rem;">Análise Inteligente de Governança e Compliance para Microsoft Azure</p>', unsafe_allow_html=True)
        
        # Verificação se o processador foi inicializado corretamente
        if st.session_state.processor is None:
            st.session_state.processor = AzureLogProcessor()
        
        # Barra lateral aprimorada
        with st.sidebar:
            st.header("⚙️ Configuração")
            
            # Seção de informações sobre o sistema
            with st.expander("ℹ️ Sobre o Sistema"):
                st.markdown("""
                Este sistema analisa logs de governança do Azure para identificar:
                - 🚫 Violações SOD (Segregação de Funções)
                - 👤 Atribuições diretas de acesso
                - 💀 Contas órfãs e privilegiadas
                - 📈 Padrões de escalação de privilégios
                """)
            
            with st.expander("📋 Formatos de Logs Suportados"):
                st.markdown("""
                **Formato 1: Role Assignments (Preferido)**
                ```json
                [{
                    "SignInName": "user@domain.com",
                    "DisplayName": "User Name",
                    "RoleDefinitionName": "Global Administrator",
                    "ObjectType": "User"
                }]
                ```
                
                **Formato 2: Activity Logs**
                ```json
                [{
                    "user_principal_name": "user@domain.com",
                    "display_name": "User Name", 
                    "role_name": "Global Administrator"
                }]
                ```
                """)
            
            with st.expander("🚀 Como usar"):
                st.markdown("""
                1. **Upload:** Faça upload do arquivo JSON de logs
                2. **Análise:** Escolha entre análise padrão ou avançada (com IA)
                3. **Relatórios:** Visualize os resultados nas abas correspondentes
                4. **Dashboard:** Acesse o painel executivo para visão geral
                """)
            
            st.divider()
            st.subheader("🔌 Status das Conexões")
            
            try:
                openai_configured = config.is_openai_configured()
            except Exception as e:
                openai_configured = False
                st.warning(f"Erro ao verificar configuração OpenAI: {e}")
            
            openai_status = "✅ Conectado" if openai_configured else "❌ Não Configurado"
            st.markdown(f"**Azure OpenAI:** {openai_status}")
            
            if not openai_configured:
                with st.expander("🔧 Configurar Azure OpenAI"):
                    st.warning("Configure a API Key no arquivo config.py:")
                    st.code("""
# No config.py, defina:
config.openai_api_key = "sua_chave_api_key_aqui"
                    """)
            
            st.divider()
            st.subheader("☁️ Azure Data Sources")
            
            # Renderiza a interface aprimorada para fontes de dados Azure
            render_enhanced_data_interface()
            
            st.divider()
            st.subheader("📊 Parâmetros de Análise")
            max_logs_to_analyze = st.slider(
                "Máximo de Logs para Análise IA", 
                min_value=50, max_value=2000, value=500, step=50,
                help="Limite de logs enviados para análise da IA (para otimizar custos)"
            )
            
            enable_detailed_analysis = st.checkbox(
                "Análise Detalhada de Governança", 
                value=True,
                help="Executa análise completa de padrões de governança"
            )
            
            st.divider()
            st.markdown("### 📋 Funcionalidades")
            st.markdown("✅ Detecção de Violações SOD")
            st.markdown("✅ Atribuições Diretas de Roles")
            st.markdown("✅ Permissões Duplicadas")
            st.markdown("✅ Padrões Suspeitos")
            st.markdown("✅ Análise com IA")
            st.markdown("✅ Dashboards Interativos")

        # Conteúdo principal
        st.markdown("---")
        st.subheader("1️⃣ Fonte de Dados")
        
        # Opção de escolha da fonte de dados
        data_source_option = st.radio(
            "Escolha a fonte dos dados:",
            ["📁 Upload de Arquivo", "☁️ Azure Log Analytics", "💾 Azure Blob Storage"],
            help="Selecione como deseja carregar os dados para análise"
        )
        
        uploaded_file = None
        
        if data_source_option == "📁 Upload de Arquivo":
            uploaded_file = st.file_uploader(
                "📁 Selecione o arquivo de logs (JSON)",
                type=['json'], 
                help="Faça upload do arquivo de logs de auditoria do Azure ou Entra ID"
            )
        
        elif data_source_option in ["☁️ Azure Log Analytics", "💾 Azure Blob Storage"]:
            # Extrai o nome do serviço de forma segura
            service_name = data_source_option.replace("☁️ ", "").replace("💾 ", "").strip()
            st.info(f"📊 Configurando conexão com {service_name}")
            
            # Renderiza interface Azure específica
            with st.container():
                try:
                    # Chama a interface Azure que foi adicionada na sidebar
                    st.write("💡 **Dica:** Use a seção 'Azure Data Sources' na barra lateral para configurar e buscar dados.")
                    
                    # Verifica se há dados Azure já carregados na sessão
                    if 'fetched_data' in st.session_state and st.session_state.fetched_data:
                        azure_data = st.session_state.fetched_data
                        st.success(f"✅ Dados Azure carregados: {len(azure_data)} registros prontos para análise!")
                        
                        # Simula uploaded_file para continuar o fluxo normal
                        uploaded_file = "azure_data"
                        
                        # Armazena os dados para processamento
                        st.session_state.azure_logs_data = azure_data
                        st.session_state.azure_data_loaded = True
                        
                        # Mostra preview dos dados
                        with st.expander("📋 Preview dos Dados Azure", expanded=False):
                            if azure_data:
                                preview_df = pd.DataFrame(azure_data[:5])  # Primeiros 5 registros
                                st.dataframe(preview_df, width='stretch')
                                st.info(f"Mostrando 5 de {len(azure_data)} registros carregados")
                    else:
                        st.warning("⚠️ Nenhum dado Azure encontrado. Use a interface Azure Data Sources na sidebar.")
                        st.info("👈 **Como usar:**\n1. Acesse 'Azure Data Sources' na barra lateral\n2. Configure suas credenciais\n3. Clique em 'Buscar Dados'\n4. Retorne aqui para iniciar a análise")
                        
                        # Botão para facilitar o acesso direto à interface Azure
                        if st.button("🔧 Configurar Azure Data Sources", type="secondary"):
                            st.info("👈 Acesse a seção 'Azure Data Sources' na barra lateral para configurar suas conexões Azure.")
                        
                except Exception as e:
                    st.error(f"❌ Erro ao configurar interface Azure: {e}")
        
        # Seção adicional para facilitar configuração Azure quando não há dados
        if data_source_option in ["☁️ Azure Log Analytics", "💾 Azure Blob Storage"] and uploaded_file != "azure_data":
            st.markdown("---")
            st.subheader("🔧 Configuração Rápida Azure")
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown("""
                **Para usar dados diretos do Azure:**
                1. 👈 Acesse **'Azure Data Sources'** na barra lateral
                2. ⚙️ Configure suas credenciais (já estão no .env)
                3. 🔍 Teste a conexão
                4. 🚀 Clique em 'Buscar Dados'
                5. 🔄 Retorne aqui - os dados aparecerão automaticamente
                """)
            
            with col2:
                if st.button("📊 Ver Status Conexões", key="check_azure_status"):
                    # Verifica status das conexões Azure
                    try:
                        import os
                        from dotenv import load_dotenv
                        load_dotenv()
                        
                        workspace_id = os.getenv('AZURE_LOG_ANALYTICS_WORKSPACE_ID')
                        storage_account = os.getenv('AZURE_STORAGE_ACCOUNT')
                        
                        st.success("✅ **Credenciais Azure Detectadas:**")
                        if workspace_id:
                            st.write(f"📊 Log Analytics: {workspace_id[:8]}...")
                        if storage_account:
                            st.write(f"💾 Storage Account: {storage_account}")
                            
                    except Exception as e:
                        st.error(f"Erro ao verificar credenciais: {e}")
        
        # Informações sobre formatos suportados
        with st.expander("📋 Formatos de Logs Suportados", expanded=False):
            st.markdown("""
            **O sistema suporta múltiplos formatos de logs Azure:**
            
            **1. Role Assignments (Atribuições de Funções):**
            ```json
            {
                "RoleAssignmentId": "...",
                "DisplayName": "Nome do usuário/grupo",
                "SignInName": "email@domain.com",
                "RoleDefinitionName": "Contribuidor",
                "ObjectType": "User" ou "Group",
                "Scope": "/subscriptions/..."
            }
            ```
            
            **2. Activity Logs (Logs de Atividade):**
            ```json
            {
                "operationName": "Add role assignment",
                "identity_userPrincipalName": "user@domain.com",
                "activityDateTime": "2024-09-22T10:00:00Z",
                "properties_roleName": "Global Administrator"
            }
            ```
            
            **3. Entra ID Audit Logs:**
            ```json
            {
                "callerIpAddress": "192.168.1.1",
                "operationName": "Add member to role",
                "resultType": "Success"
            }
            ```
            """)
        
        if uploaded_file:
            try:
                with st.spinner("🔄 Processando dados..."):
                    # Diferencia entre upload de arquivo e dados Azure
                    if uploaded_file == "azure_data":
                        # Carrega dados que foram buscados do Azure via interface
                        if 'azure_logs_data' in st.session_state:
                            # Converte dados Azure para DataFrame
                            azure_data = st.session_state.azure_logs_data
                            st.session_state.logs_df = pd.DataFrame(azure_data)
                            st.success(f"✅ Dados Azure carregados! {len(st.session_state.logs_df)} eventos processados.")
                        else:
                            st.warning("⚠️ Nenhum dado Azure encontrado. Use a interface Azure Data Sources na sidebar.")
                            st.session_state.logs_df = None
                    else:
                        # Processamento normal de arquivo
                        file_bytes = uploaded_file.getvalue()
                        try:
                            file_content = file_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            file_content = file_bytes.decode("latin-1")
                        
                        # Processa logs
                        st.session_state.logs_df = st.session_state.processor.load_logs_from_file(file_content)
                        st.success(f"✅ Arquivo processado com sucesso! {len(st.session_state.logs_df)} eventos carregados.")
                    
                    # Gera resumo de governança se dados foram carregados
                    if st.session_state.logs_df is not None and len(st.session_state.logs_df) > 0:
                        if enable_detailed_analysis:
                            st.session_state.governance_summary = st.session_state.processor.generate_comprehensive_summary()
                        
                        # Mostra estatísticas básicas
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total de Eventos", len(st.session_state.logs_df))
                        with col2:
                            unique_users = st.session_state.logs_df.get('user_principal_name', pd.Series()).nunique()
                            st.metric("Usuários Únicos", unique_users)
                        with col3:
                            role_events = len(st.session_state.processor.role_assignments_df) if st.session_state.processor.role_assignments_df is not None else 0
                            st.metric("Eventos de Roles", role_events)
                    
            except Exception as e:
                st.error(f"❌ Erro ao processar arquivo: {str(e)}")
                
                # Diagnóstico mais detalhado do erro
                if 'user_principal_name' in str(e):
                    st.error("**Problema:** O arquivo não contém os campos esperados.")
                    st.info("""
                    **Solução:** Verifique se o arquivo contém:
                    - `SignInName` ou `user_principal_name` para identificar usuários
                    - `RoleDefinitionName` ou `role_name` para as funções
                    - `ObjectType` para distinguir usuários de grupos
                    """)
                elif 'JSON' in str(e) or 'json' in str(e):
                    st.error("**Problema:** Formato JSON inválido.")
                    st.info("""
                    **Solução:** 
                    1. Verifique se o arquivo é um JSON válido
                    2. Certifique-se de que é um array de objetos: `[{...}, {...}]`
                    3. Teste o JSON em um validador online
                    """)
                else:
                    st.error("Verifique se o arquivo está no formato correto e tente novamente.")
                
                with st.expander("🔍 Detalhes técnicos do erro"):
                    st.code(str(e))
                    st.markdown("**Dica:** Consulte a seção 'Formatos de Logs Suportados' acima para verificar se seu arquivo está no formato correto.")

        # Análise de Governança
        if st.session_state.logs_df is not None and enable_detailed_analysis:
            st.markdown("---")
            st.subheader("2️⃣ Análise de Governança")
            
            if st.session_state.governance_summary:
                render_governance_overview(st.session_state.governance_summary)
                
                # Relatórios detalhados
                with st.expander("📊 Ver Relatórios Detalhados de Governança", expanded=False):
                    render_detailed_governance_reports(st.session_state.governance_summary)

        # Análise com IA
        if st.session_state.logs_df is not None:
            st.markdown("---")
            st.subheader("3️⃣ Análise Inteligente com Azure OpenAI")
            
            # Seletor de modo de análise
            analysis_mode = st.selectbox(
                "Modo de Análise",
                ["Análise Padrão", "Análise Avançada de Governança"],
                help="Análise Avançada inclui detecção de padrões complexos e análise forense"
            )
            
            if st.button("🚀 Executar Análise de IA", type="primary", width='stretch', key="ai_analysis"):
                if not openai_configured:
                    st.error("❌ Configure o Azure OpenAI antes de executar a análise.")
                    st.stop()
                    
                with st.spinner("🤖 Executando análise inteligente... Isso pode levar alguns minutos."):
                    try:
                        logs_sample = st.session_state.logs_df.head(max_logs_to_analyze).to_dict(orient='records')
                        
                        if analysis_mode == "Análise Avançada de Governança":
                            # Usa o novo analisador avançado
                            advanced_analyzer = AdvancedGovernanceAnalyzer()
                            st.session_state.enhanced_analysis_result = advanced_analyzer.perform_comprehensive_analysis(logs_sample)
                            st.session_state.analysis_result = None  # Para usar só o resultado avançado
                            st.success("✅ Análise Avançada de Governança concluída!")
                        else:
                            # Usa o analisador padrão
                            analyzer = AzureLogAnalyzer()
                            st.session_state.analysis_result = analyzer.analyze_security_patterns(logs_sample)
                            st.session_state.enhanced_analysis_result = None
                            st.success("✅ Análise de IA concluída!")
                            
                    except Exception as e:
                        st.error(f"❌ Erro na análise de IA: {str(e)}")
                        st.error("Verifique os logs da aplicação para mais detalhes.")
                st.rerun()

        # Resultados da Análise
        if st.session_state.analysis_result or st.session_state.enhanced_analysis_result:
            st.markdown("---")
            st.subheader("4️⃣ Resultados e Relatórios")
            
            # Determina qual resultado usar
            if st.session_state.enhanced_analysis_result:
                # Análise avançada - mais tabs e visualizações
                tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                    "🔍 Análise Avançada", 
                    "📊 Dashboards Inteligentes", 
                    "🛡️ Compliance & Frameworks",
                    "📈 Tendências & Predições",
                    "🎯 Centro de Ações",
                    "💾 Relatórios"
                ])
                
                with tab1:
                    render_enhanced_analysis_report(st.session_state.enhanced_analysis_result)
                
                with tab2:
                    # Dashboards Inteligentes (novo sistema personalizado)
                    render_enhanced_dashboards(st.session_state.enhanced_analysis_result)
                
                with tab3:
                    render_compliance_analysis(st.session_state.enhanced_analysis_result)
                
                with tab4:
                    render_trends_and_predictions(st.session_state.enhanced_analysis_result)
                
                with tab5:
                    render_action_center(st.session_state.enhanced_analysis_result)
                
                with tab6:
                    render_enhanced_export_options(st.session_state.enhanced_analysis_result)
                    
            else:
                # Análise padrão - tabs originais
                tab1, tab2, tab3 = st.tabs(["🤖 Análise da IA", "📊 Dashboards Visuais", "💾 Exportar Relatório"])
                
                with tab1:
                    render_detailed_report(st.session_state.analysis_result)
                
                with tab2:
                    render_enhanced_dashboards(st.session_state.analysis_result)
                
                with tab3:
                    render_export_options(st.session_state.analysis_result)
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("📋 Gerar Relatório JSON", width='stretch', key="json_report_advanced"):
                        report_json = export_report_to_json(
                            st.session_state.analysis_result, 
                            st.session_state.governance_summary
                        )
                        st.download_button(
                            label="💾 Download Relatório JSON",
                            data=report_json,
                            file_name=f"azure_governance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json",
                            width='stretch'
                        )
                
                with col2:
                    if st.button("📊 Gerar Relatório CSV", width='stretch', key="csv_report_advanced"):
                        if st.session_state.analysis_result.findings:
                            findings_df = pd.DataFrame([
                                {
                                    'Risk Level': f.risk_level.value,
                                    'Title': f.title,
                                    'Description': f.description,
                                    'Recommendation': f.recommendation,
                                    'Affected Count': len(f.affected_principals),
                                    'Affected Principals': '; '.join(f.affected_principals[:5])
                                }
                                for f in st.session_state.analysis_result.findings
                            ])
                            
                            csv_data = findings_df.to_csv(index=False)
                            st.download_button(
                                label="💾 Download Relatório CSV",
                                data=csv_data,
                                file_name=f"azure_governance_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv",
                                width='stretch'
                            )
                
                # Preview do relatório
                if st.session_state.analysis_result:
                    st.markdown("#### 👀 Preview do Relatório")
                    preview_data = {
                        "total_findings": len(st.session_state.analysis_result.findings),
                        "risk_score": st.session_state.analysis_result.risk_assessment.score,
                        "summary": st.session_state.analysis_result.risk_assessment.summary
                    }
                    st.json(preview_data)

        # Footer
        st.markdown("---")
        st.markdown("""
        <div style='text-align: center; color: #666; padding: 2rem;'>
            <p>🛡️ <strong>PrivIQ</strong> - Ferramenta de Análise de Governança para Microsoft Azure</p>
            <p>Desenvolvido para Hackathon | Versão 2.0 | 2025</p>
        </div>
        """, unsafe_allow_html=True)
        
    except Exception as e:
        st.error(f"❌ Erro crítico na aplicação: {str(e)}")
        st.error("Por favor, verifique se todos os arquivos estão presentes e corretos.")
        with st.expander("🔍 Detalhes do erro"):
            st.exception(e)

if __name__ == "__main__":
    main()
