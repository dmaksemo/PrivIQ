# integration_example.py

"""
Exemplo de como integrar as novas funcionalidades de conectores Azure 
com o app principal (app.py).

Este arquivo demonstra:
1. Como modificar o app.py para usar os novos conectores
2. Interface unificada para múltiplas fontes
3. Configuração dinâmica de fontes de dados
4. Cache e otimização de performance
"""

import streamlit as st
import asyncio
from typing import Dict, List, Any, Optional

# Importações dos novos módulos
from azure_data_connectors import (
    UnifiedDataManager, 
    DataConnectorFactory,
    DataSourceConfig
)
from enhanced_data_interface import EnhancedDataInterface, render_enhanced_data_interface
from kql_templates import KQLTemplateManager, CustomKQLTemplates

# Importações existentes
from data_processor import AzureLogProcessor
from azure_log_analyzer import AzureLogAnalyzer
from governance_analyzer import AdvancedGovernanceAnalyzer
from visualization_generator import SecurityVisualizationGenerator
from models import EnhancedAIAnalysisResult

class EnhancedAzureGovernanceApp:
    """Versão aprimorada do app com integração Azure nativa."""
    
    def __init__(self):
        self.data_manager = UnifiedDataManager()
        self.kql_manager = KQLTemplateManager()
        self.processor = AzureLogProcessor()
        self.analyzer = AzureLogAnalyzer()
        self.governance_analyzer = AdvancedGovernanceAnalyzer()
        self.viz_generator = SecurityVisualizationGenerator()
        
        # Inicializa conectores se configurados
        self._initialize_default_connectors()
    
    def _initialize_default_connectors(self):
        """Inicializa conectores padrão baseado nas configurações."""
        try:
            from config import config
            
            # Log Analytics
            if config.is_log_analytics_configured():
                la_config = DataSourceConfig(
                    source_type='log_analytics',
                    workspace_id=config.log_analytics_workspace_id,
                    tenant_id=config.log_analytics_tenant_id,
                    client_id=config.log_analytics_client_id if config.log_analytics_client_id else None,
                    client_secret=config.log_analytics_client_secret if config.log_analytics_client_secret else None
                )
                la_connector = DataConnectorFactory.create_connector(la_config)
                self.data_manager.register_connector('log_analytics', la_connector)
                st.success("✅ Azure Log Analytics configurado")
            
            # Blob Storage  
            if config.is_blob_storage_configured():
                bs_config = DataSourceConfig(
                    source_type='storage_account',
                    storage_account_name=config.storage_account_name,
                    container_name=config.storage_container_name,
                    connection_string=None  # Usar Managed Identity
                )
                bs_connector = DataConnectorFactory.create_connector(bs_config)
                self.data_manager.register_connector('blob_storage', bs_connector)
                st.success("✅ Azure Blob Storage configurado")
                
        except Exception as e:
            st.warning(f"⚠️ Alguns conectores não puderam ser inicializados: {e}")
    
    def render_main_interface(self):
        """Renderiza interface principal aprimorada."""
        
        st.markdown('<h1 class="main-header">🛡️ PrivIQ - Enterprise Edition</h1>', 
                   unsafe_allow_html=True)
        
        # Sidebar aprimorada
        self._render_enhanced_sidebar()
        
        # Seleção de modo de operação
        operation_mode = st.selectbox(
            "🎯 Modo de Operação:",
            options=["quick_analysis", "deep_governance", "real_time_monitoring", "compliance_audit"],
            format_func=self._format_operation_mode,
            help="Selecione o tipo de análise desejada"
        )
        
        if operation_mode == "quick_analysis":
            self._render_quick_analysis()
        elif operation_mode == "deep_governance":
            self._render_deep_governance()
        elif operation_mode == "real_time_monitoring":
            self._render_real_time_monitoring()
        elif operation_mode == "compliance_audit":
            self._render_compliance_audit()
    
    def _render_enhanced_sidebar(self):
        """Sidebar aprimorada com configurações avançadas."""
        
        with st.sidebar:
            st.markdown("### ⚙️ Configurações Avançadas")
            
            # Status dos conectores
            st.markdown("#### 🔌 Status das Conexões")
            connection_status = self.data_manager.validate_all_connections()
            
            for connector, status in connection_status.items():
                status_icon = "✅" if status else "❌"
                st.markdown(f"{status_icon} **{connector.replace('_', ' ').title()}**")
            
            # Configurações de cache
            st.markdown("#### 💾 Cache e Performance")
            enable_cache = st.checkbox("Habilitar Cache", value=True)
            cache_ttl = st.slider("TTL do Cache (minutos)", 1, 60, 5)
            
            # Configurações de análise
            st.markdown("#### 🔍 Configurações de Análise")
            max_logs = st.number_input("Máximo de Logs", 1000, 100000, 10000)
            enable_ai = st.checkbox("Análise com IA", value=True)
            
            # Templates KQL
            st.markdown("#### 📊 Templates Disponíveis")
            templates = self.kql_manager.list_templates()
            for template in templates:
                info = self.kql_manager.get_template_info(template)
                with st.expander(f"📋 {info['name']}"):
                    st.write(info['description'])
    
    def _format_operation_mode(self, mode: str) -> str:
        """Formata modos de operação."""
        formats = {
            "quick_analysis": "⚡ Análise Rápida (5 min)",
            "deep_governance": "🔬 Análise Profunda de Governança", 
            "real_time_monitoring": "📡 Monitoramento em Tempo Real",
            "compliance_audit": "📋 Auditoria de Compliance"
        }
        return formats.get(mode, mode)
    
    def _render_quick_analysis(self):
        """Interface para análise rápida."""
        
        st.subheader("⚡ Análise Rápida de Governança")
        st.info("Análise otimizada para insights imediatos (últimas 24h)")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Seleção de fonte simplificada
            data_source = st.radio(
                "Fonte de Dados:",
                options=["azure_log_analytics", "azure_blob_storage", "manual_upload"],
                format_func=lambda x: {
                    "azure_log_analytics": "📊 Log Analytics (Tempo Real)",
                    "azure_blob_storage": "💾 Blob Storage", 
                    "manual_upload": "📁 Upload Manual"
                }[x]
            )
        
        with col2:
            if st.button("🚀 Executar Análise", type="primary"):
                self._execute_quick_analysis(data_source)
    
    def _render_deep_governance(self):
        """Interface para análise profunda de governança."""
        
        st.subheader("🔬 Análise Profunda de Governança")
        
        # Interface aprimorada de seleção de dados
        config_data, data = render_enhanced_data_interface()
        
        if data:
            st.markdown("### 🎯 Opções de Análise")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                analyze_sod = st.checkbox("🚫 Violações SOD", value=True)
                analyze_direct = st.checkbox("👤 Atribuições Diretas", value=True)
            
            with col2:
                analyze_excessive = st.checkbox("⚡ Privilégios Excessivos", value=True)
                analyze_suspicious = st.checkbox("🔍 Padrões Suspeitos", value=True)
            
            with col3:
                analyze_compliance = st.checkbox("📋 Compliance", value=True)
                analyze_trends = st.checkbox("📈 Análise de Tendências", value=False)
            
            if st.button("🔬 Executar Análise Profunda", type="primary"):
                self._execute_deep_analysis(data, {
                    'sod': analyze_sod,
                    'direct': analyze_direct,
                    'excessive': analyze_excessive,
                    'suspicious': analyze_suspicious,
                    'compliance': analyze_compliance,
                    'trends': analyze_trends
                })
    
    def _render_real_time_monitoring(self):
        """Interface para monitoramento em tempo real."""
        
        st.subheader("📡 Monitoramento em Tempo Real")
        
        if 'log_analytics' not in self.data_manager.connectors:
            st.error("❌ Azure Log Analytics é necessário para monitoramento em tempo real")
            st.info("Configure as credenciais do Log Analytics na sidebar")
            return
        
        # Configurações de monitoramento
        col1, col2 = st.columns(2)
        
        with col1:
            refresh_interval = st.selectbox(
                "Intervalo de Atualização:",
                options=[30, 60, 300, 600],
                format_func=lambda x: f"{x} segundos"
            )
            
            alert_threshold = st.selectbox(
                "Nível de Alerta:",
                options=["Critical", "High", "Medium", "Low"],
                index=1
            )
        
        with col2:
            monitor_types = st.multiselect(
                "Tipos de Monitoramento:",
                options=["role_assignments", "privileged_operations", "sign_in_analysis"],
                default=["role_assignments", "privileged_operations"],
                format_func=lambda x: {
                    "role_assignments": "👥 Atribuições de Roles",
                    "privileged_operations": "⚡ Operações Privilegiadas", 
                    "sign_in_analysis": "🔐 Análise de Sign-ins"
                }[x]
            )
        
        # Dashboard de monitoramento
        if st.button("📡 Iniciar Monitoramento"):
            self._start_real_time_monitoring(refresh_interval, alert_threshold, monitor_types)
    
    def _render_compliance_audit(self):
        """Interface para auditoria de compliance."""
        
        st.subheader("📋 Auditoria de Compliance")
        
        # Seleção de framework
        framework = st.selectbox(
            "Framework de Compliance:",
            options=["SOX", "NIST", "ISO27001", "GDPR", "HIPAA", "PCI_DSS"],
            help="Selecione o framework para análise específica"
        )
        
        # Período de auditoria
        col1, col2 = st.columns(2)
        
        with col1:
            start_date = st.date_input("Data Início")
            
        with col2:
            end_date = st.date_input("Data Fim")
        
        # Opções avançadas
        with st.expander("🔧 Opções Avançadas"):
            include_evidence = st.checkbox("Incluir Evidências Técnicas", value=True)
            generate_remediation = st.checkbox("Gerar Plano de Remediação", value=True)
            export_format = st.selectbox("Formato de Exportação", ["PDF", "Excel", "JSON"])
        
        if st.button("📋 Executar Auditoria de Compliance"):
            self._execute_compliance_audit(framework, start_date, end_date, {
                'evidence': include_evidence,
                'remediation': generate_remediation,
                'export_format': export_format
            })
    
    async def _execute_quick_analysis(self, data_source: str):
        """Executa análise rápida."""
        
        with st.spinner("Executando análise rápida..."):
            try:
                # Parâmetros otimizados para análise rápida
                query_params = {
                    'analysis_type': 'comprehensive_governance',
                    'timeframe': '1d',  # Últimas 24h
                    'limit': 1000
                }
                
                # Busca dados
                if data_source == "azure_log_analytics":
                    connector = self.data_manager.connectors.get('log_analytics')
                    if connector:
                        data = await connector.fetch_data(query_params)
                    else:
                        st.error("Log Analytics não configurado")
                        return
                elif data_source == "azure_blob_storage":
                    connector = self.data_manager.connectors.get('blob_storage')
                    if connector:
                        data = await connector.fetch_data({'max_blobs': 10})
                    else:
                        st.error("Blob Storage não configurado")
                        return
                else:
                    st.info("Por favor, faça upload de um arquivo JSON")
                    return
                
                # Análise rápida
                if data:
                    summary = self._generate_quick_summary(data)
                    self._render_quick_results(summary)
                else:
                    st.warning("Nenhum dado encontrado para análise")
                    
            except Exception as e:
                st.error(f"Erro na análise rápida: {str(e)}")
    
    def _generate_quick_summary(self, data: List[Dict]) -> Dict[str, Any]:
        """Gera resumo rápido dos dados."""
        
        import pandas as pd
        
        df = pd.DataFrame(data)
        
        summary = {
            'total_events': len(data),
            'unique_users': 0,
            'risk_events': 0,
            'admin_operations': 0,
            'timespan': 'Últimas 24h'
        }
        
        if 'user_principal_name' in df.columns:
            summary['unique_users'] = df['user_principal_name'].nunique()
        
        if 'risk_level' in df.columns:
            summary['risk_events'] = len(df[df['risk_level'].isin(['High', 'Critical'])])
        
        if 'operation_name' in df.columns:
            admin_ops = df['operation_name'].str.contains('Administrator|Role|Policy', na=False)
            summary['admin_operations'] = admin_ops.sum()
        
        return summary
    
    def _render_quick_results(self, summary: Dict[str, Any]):
        """Renderiza resultados da análise rápida."""
        
        st.success("✅ Análise rápida concluída!")
        
        # Métricas principais
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("📊 Total de Eventos", f"{summary['total_events']:,}")
        
        with col2:
            st.metric("👥 Usuários Únicos", summary['unique_users'])
        
        with col3:
            st.metric("⚠️ Eventos de Risco", summary['risk_events'])
        
        with col4:
            st.metric("⚡ Operações Admin", summary['admin_operations'])
        
        # Recomendações rápidas
        st.markdown("### 💡 Recomendações Imediatas")
        
        if summary['risk_events'] > 0:
            st.warning(f"🚨 {summary['risk_events']} eventos de risco detectados - Requer atenção imediata")
        
        if summary['admin_operations'] > 50:
            st.info(f"⚡ Alto volume de operações administrativas ({summary['admin_operations']}) - Revisar logs")
        
        if summary['risk_events'] == 0:
            st.success("✅ Nenhum evento de risco crítico detectado no período")

# Exemplo de integração com o app principal
def integrate_with_main_app():
    """
    Mostra como integrar as novas funcionalidades com app.py existente.
    
    PASSOS PARA INTEGRAÇÃO:
    
    1. Adicionar imports no app.py:
    """
    integration_code = '''
# No início do app.py, adicionar:
from azure_data_connectors import UnifiedDataManager, DataConnectorFactory
from enhanced_data_interface import render_enhanced_data_interface
from kql_templates import KQLTemplateManager

# Na função principal, substituir upload de arquivo por:
def enhanced_main():
    # ... código existente ...
    
    # NOVA: Interface unificada de dados
    st.sidebar.markdown("### 🔌 Fonte de Dados")
    config_data, logs = render_enhanced_data_interface()
    
    if logs:
        # Usar logs obtidos (mesma lógica existente)
        processor = AzureLogProcessor()
        analyzer = AzureLogAnalyzer()
        # ... resto do código permanece igual ...
    '''
    
    return integration_code

# Exemplo de uso completo
if __name__ == "__main__":
    # Configuração da página Streamlit
    st.set_page_config(
        page_title="PrivIQ - Enterprise",
        page_icon="🛡️",
        layout="wide"
    )
    
    # Inicializa e executa app aprimorado
    app = EnhancedAzureGovernanceApp()
    app.render_main_interface()