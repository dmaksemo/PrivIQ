# enhanced_data_interface.py

import streamlit as st
import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import pandas as pd

from azure_data_connectors import (
    DataSourceConfig, 
    UnifiedDataManager, 
    DataConnectorFactory,
    AzureLogAnalyticsConnector,
    AzureBlobStorageConnector
)
from config import config

class EnhancedDataInterface:
    """Interface melhorada para seleção e configuração de fontes de dados."""
    
    def __init__(self):
        self.data_manager = UnifiedDataManager()
        self.initialized_sources = set()
    
    def render_data_source_selector(self) -> Dict[str, Any]:
        """Renderiza interface para seleção de fonte de dados."""
        
        st.subheader("🔌 Configuração de Fonte de Dados")
        
        # Seleção do tipo de fonte
        source_type = st.selectbox(
            "Selecione a Fonte de Dados:",
            options=["manual", "azure_log_analytics", "azure_blob_storage", "hybrid"],
            format_func=self._format_source_option,
            help="Escolha como os logs serão obtidos para análise"
        )
        
        config_data = {"source_type": source_type}
        
        if source_type == "manual":
            config_data.update(self._render_manual_upload())
        elif source_type == "azure_log_analytics":
            config_data.update(self._render_log_analytics_config())
        elif source_type == "azure_blob_storage":
            config_data.update(self._render_blob_storage_config())
        elif source_type == "hybrid":
            config_data.update(self._render_hybrid_config())
        
        return config_data
    
    def _format_source_option(self, option: str) -> str:
        """Formata opções de fonte de dados para exibição."""
        formats = {
            "manual": "📁 Upload Manual de Arquivo",
            "azure_log_analytics": "📊 Azure Log Analytics (Tempo Real)",
            "azure_blob_storage": "💾 Azure Blob Storage",
            "hybrid": "🔄 Múltiplas Fontes (Híbrido)"
        }
        return formats.get(option, option)
    
    def _render_manual_upload(self) -> Dict[str, Any]:
        """Interface para upload manual de arquivos."""
        st.info("📁 **Upload Manual**: Faça upload de arquivos JSON com logs de auditoria")
        
        uploaded_files = st.file_uploader(
            "Selecione arquivos de log (JSON)",
            type=['json'],
            accept_multiple_files=True,
            help="Faça upload de arquivos JSON contendo logs de auditoria do Azure"
        )
        
        return {
            "uploaded_files": uploaded_files,
            "data": self._process_uploaded_files(uploaded_files) if uploaded_files else []
        }
    
    def _render_log_analytics_config(self) -> Dict[str, Any]:
        """Interface simplificada para configuração do Azure Log Analytics."""
        st.info("📊 **Azure Log Analytics**: Conexão configurada automaticamente")
        st.success(f"🔗 Conectado ao Workspace: `{config.log_analytics_workspace_id[:8]}...`")
        
        # Apenas parâmetros de consulta (credenciais vêm do .env)
        st.subheader("⚙️ Parâmetros de Consulta")
        
        col3, col4 = st.columns(2)
        
        with col3:
            analysis_type = st.selectbox(
                "Tipo de Análise",
                options=[
                    "comprehensive_governance",
                    "role_assignments", 
                    "sign_in_analysis",
                    "privileged_operations"
                ],
                format_func=self._format_analysis_type
            )
            
            timeframe = st.selectbox(
                "Período",
                options=["1d", "7d", "30d", "90d"],
                index=2,
                format_func=lambda x: f"Últimos {x}"
            )
        
        with col4:
            limit = st.number_input(
                "Limite de Registros",
                min_value=100,
                max_value=50000,
                value=10000,
                step=500
            )
            
            user_filter = st.text_input(
                "Filtro de Usuário (Opcional)",
                placeholder="nome@dominio.com",
                help="Filtrar logs por usuário específico"
            )
        
        # Teste de conexão usando credenciais do .env
        if st.button("🔍 Testar Conexão", key="test_log_analytics"):
            connection_status = self._test_log_analytics_connection_with_env()
            if connection_status:
                st.success("✅ Conexão estabelecida com sucesso!")
            else:
                st.error("❌ Falha na conexão. Verifique as configurações no .env")
        
        return {
            "workspace_id": config.log_analytics_workspace_id,
            "tenant_id": config.log_analytics_tenant_id,
            "client_id": config.log_analytics_client_id,
            "client_secret": config.log_analytics_client_secret,
            "query_params": {
                "analysis_type": analysis_type,
                "timeframe": timeframe,
                "limit": limit,
                "user_filter": user_filter if user_filter else None
            }
        }
    
    def _render_blob_storage_config(self) -> Dict[str, Any]:
        """Interface simplificada para configuração do Azure Blob Storage."""
        st.info("💾 **Azure Blob Storage**: Configuração automática")
        st.success(f"🔗 Conectado à Storage Account: `{config.storage_account_name}` | Container: `{config.storage_container_name}`")
        
        # Apenas parâmetros de busca (credenciais vêm do .env)
        st.subheader("🔍 Parâmetros de Busca")
        
        col3, col4 = st.columns(2)
        
        with col3:
            # Escolha entre prefixo ou nome específico
            filter_type = st.radio(
                "Tipo de Filtro:",
                ["Prefixo", "Nome Específico", "Todos os Arquivos"]
            )
            
            if filter_type == "Prefixo":
                blob_prefix = st.text_input(
                    "Prefixo dos Blobs",
                    value="",
                    help="Prefixo para filtrar blobs (ex: audit-logs/ ou AuditLogs_)"
                )
            elif filter_type == "Nome Específico":
                blob_prefix = st.text_input(
                    "Nome Exato do Arquivo",
                    value="",
                    placeholder="Ex: AuditLogs_2025-08-20.json",
                    help="Nome completo do arquivo blob (incluindo extensão)"
                )
            else:
                blob_prefix = ""  # Buscar todos
            
            max_blobs = st.number_input(
                "Máximo de Blobs",
                min_value=1,
                max_value=1000,
                value=10 if filter_type == "Nome Específico" else 100,
                help="Número máximo de blobs a processar"
            )
        
        with col4:
            date_filter = st.date_input(
                "Filtro por Data (Opcional)",
                value=None,
                help="Processar apenas blobs após esta data"
            )
        
        # Teste de conexão usando credenciais do .env
        if st.button("🔍 Testar Conexão", key="test_blob_storage"):
            connection_status = self._test_blob_storage_connection_with_env()
            if connection_status:
                st.success("✅ Conexão estabelecida com sucesso!")
            else:
                st.error("❌ Falha na conexão. Verifique as configurações no .env")
        
        return {
            "storage_account_name": config.storage_account_name,
            "container_name": config.storage_container_name,
            "connection_string": config.storage_connection_string,  # USAR Connection String do .env
            "storage_connection_string": config.storage_connection_string,
            "query_params": {
                "blob_prefix": blob_prefix,
                "filter_type": filter_type,
                "max_blobs": max_blobs,
                "date_filter": date_filter
            }
        }
    
    def _render_hybrid_config(self) -> Dict[str, Any]:
        """Interface para configuração híbrida (múltiplas fontes)."""
        st.info("🔄 **Modo Híbrido**: Combine dados de múltiplas fontes para análise abrangente")
        
        st.subheader("📊 Fontes Ativas")
        
        # Seleção de fontes
        use_log_analytics = st.checkbox(
            "📈 Incluir Azure Log Analytics",
            value=True,
            help="Dados em tempo real do workspace"
        )
        
        use_blob_storage = st.checkbox(
            "💾 Incluir Azure Blob Storage", 
            value=True,
            help="Logs históricos armazenados"
        )
        
        use_manual = st.checkbox(
            "📁 Incluir Upload Manual",
            value=False,
            help="Arquivos adicionais via upload"
        )
        
        hybrid_config = {"sources": []}
        
        if use_log_analytics:
            st.markdown("**Configuração Log Analytics:**")
            la_config = self._render_log_analytics_config()
            hybrid_config["log_analytics"] = la_config
            hybrid_config["sources"].append("log_analytics")
        
        if use_blob_storage:
            st.markdown("**Configuração Blob Storage:**")
            bs_config = self._render_blob_storage_config()
            hybrid_config["blob_storage"] = bs_config
            hybrid_config["sources"].append("blob_storage")
        
        if use_manual:
            st.markdown("**Upload Manual:**")
            manual_config = self._render_manual_upload()
            hybrid_config["manual"] = manual_config
            hybrid_config["sources"].append("manual")
        
        return hybrid_config
    
    def _format_analysis_type(self, analysis_type: str) -> str:
        """Formata tipos de análise para exibição."""
        formats = {
            "comprehensive_governance": "🛡️ Análise Completa de Governança",
            "role_assignments": "👥 Atribuições de Roles",
            "sign_in_analysis": "🔐 Análise de Sign-ins",
            "privileged_operations": "⚡ Operações Privilegiadas"
        }
        return formats.get(analysis_type, analysis_type)
    
    def _process_uploaded_files(self, uploaded_files) -> List[Dict[str, Any]]:
        """Processa arquivos enviados manualmente."""
        all_logs = []
        
        if not uploaded_files:
            return all_logs
        
        for uploaded_file in uploaded_files:
            try:
                content = uploaded_file.read()
                logs = json.loads(content)
                
                if isinstance(logs, list):
                    all_logs.extend(logs)
                else:
                    all_logs.append(logs)
                
                st.success(f"✅ Arquivo {uploaded_file.name} processado: {len(logs)} registros")
                
            except json.JSONDecodeError:
                st.error(f"❌ Erro ao processar {uploaded_file.name}: formato JSON inválido")
            except Exception as e:
                st.error(f"❌ Erro inesperado com {uploaded_file.name}: {str(e)}")
        
        return all_logs
    
    def _test_log_analytics_connection_with_env(self) -> bool:
        """Testa conexão com Log Analytics usando credenciais do .env."""
        try:
            la_config = DataSourceConfig(
                source_type='log_analytics',
                workspace_id=config.log_analytics_workspace_id,
                tenant_id=config.log_analytics_tenant_id,
                client_id=config.log_analytics_client_id,
                client_secret=config.log_analytics_client_secret
            )
            
            connector = AzureLogAnalyticsConnector(la_config)
            return connector.validate_connection()
            
        except Exception as e:
            st.error(f"Erro no teste de conexão: {str(e)}")
            return False
    
    def _test_blob_storage_connection_with_env(self) -> bool:
        """Testa conexão com Blob Storage usando credenciais do .env."""
        try:
            bs_config = DataSourceConfig(
                source_type='storage_account',
                storage_account_name=config.storage_account_name,
                container_name=config.storage_container_name,
                storage_connection_string=config.storage_connection_string,
                storage_key=config.storage_key
            )
            
            connector = AzureBlobStorageConnector(bs_config)
            return connector.validate_connection()
            
        except Exception as e:
            st.error(f"Erro no teste de conexão: {str(e)}")
            return False

    def _test_log_analytics_connection(self, workspace_id: str, tenant_id: str, 
                                     client_id: str = "", client_secret: str = "") -> bool:
        """Testa conexão com Log Analytics."""
        try:
            la_config = DataSourceConfig(
                source_type='log_analytics',
                workspace_id=workspace_id,
                tenant_id=tenant_id,
                client_id=client_id if client_id else None,
                client_secret=client_secret if client_secret else None
            )
            
            connector = AzureLogAnalyticsConnector(la_config)
            return connector.validate_connection()
            
        except Exception as e:
            st.error(f"Erro no teste de conexão: {str(e)}")
            return False
    
    def _test_blob_storage_connection(self, storage_account: str, container_name: str, 
                                    connection_string: str = "") -> bool:
        """Testa conexão com Blob Storage."""
        try:
            bs_config = DataSourceConfig(
                source_type='storage_account',
                storage_account_name=storage_account,
                container_name=container_name,
                connection_string=connection_string if connection_string else None
            )
            
            connector = AzureBlobStorageConnector(bs_config)
            return connector.validate_connection()
            
        except Exception as e:
            st.error(f"Erro no teste de conexão: {str(e)}")
            return False
    
    async def fetch_data_async(self, config_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca dados de forma assíncrona baseado na configuração."""
        
        source_type = config_data["source_type"]
        
        if source_type == "manual":
            return config_data.get("data", [])
        
        elif source_type == "azure_log_analytics":
            return await self._fetch_log_analytics_data(config_data)
        
        elif source_type == "azure_blob_storage":
            return await self._fetch_blob_storage_data(config_data)
        
        elif source_type == "hybrid":
            return await self._fetch_hybrid_data(config_data)
        
        return []
    
    async def _fetch_log_analytics_data(self, config_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca dados do Log Analytics."""
        la_config = DataSourceConfig(
            source_type='log_analytics',
            workspace_id=config_data["workspace_id"],
            tenant_id=config_data["tenant_id"],
            client_id=config_data.get("client_id"),
            client_secret=config_data.get("client_secret")
        )
        
        connector = AzureLogAnalyticsConnector(la_config)
        self.data_manager.register_connector("log_analytics", connector)
        
        return await connector.fetch_data(config_data["query_params"])
    
    async def _fetch_blob_storage_data(self, config_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca dados do Blob Storage."""
        bs_config = DataSourceConfig(
            source_type='storage_account',
            storage_account_name=config_data["storage_account_name"],
            container_name=config_data["container_name"],
            connection_string=config_data.get("connection_string"),
            storage_connection_string=config_data.get("storage_connection_string"),
            storage_key=config.storage_key
        )
        
        connector = AzureBlobStorageConnector(bs_config)
        self.data_manager.register_connector("blob_storage", connector)
        
        return await connector.fetch_data(config_data["query_params"])
    
    async def _fetch_hybrid_data(self, config_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca dados de múltiplas fontes."""
        all_data = []
        
        # Registra conectores baseado na configuração
        for source in config_data["sources"]:
            if source == "log_analytics" and "log_analytics" in config_data:
                la_data = await self._fetch_log_analytics_data(config_data["log_analytics"])
                all_data.extend(la_data)
            
            elif source == "blob_storage" and "blob_storage" in config_data:
                bs_data = await self._fetch_blob_storage_data(config_data["blob_storage"])
                all_data.extend(bs_data)
            
            elif source == "manual" and "manual" in config_data:
                manual_data = config_data["manual"].get("data", [])
                all_data.extend(manual_data)
        
        return all_data
    
    def render_data_summary(self, data: List[Dict[str, Any]]):
        """Renderiza resumo dos dados obtidos."""
        if not data:
            st.warning("⚠️ Nenhum dado foi obtido das fontes configuradas")
            return
        
        st.success(f"✅ **{len(data):,}** registros obtidos com sucesso!")
        
        # Métricas rápidas
        col1, col2, col3, col4 = st.columns(4)
        
        df = pd.DataFrame(data)
        
        with col1:
            unique_users = len(df.get('user_principal_name', pd.Series()).dropna().unique()) if 'user_principal_name' in df.columns else 0
            st.metric("👥 Usuários Únicos", unique_users)
        
        with col2:
            unique_operations = len(df.get('operation_name', pd.Series()).dropna().unique()) if 'operation_name' in df.columns else 0
            st.metric("⚙️ Operações Únicas", unique_operations)
        
        with col3:
            date_range = "N/A"
            if 'timestamp' in df.columns or 'TimeGenerated' in df.columns:
                time_col = 'timestamp' if 'timestamp' in df.columns else 'TimeGenerated'
                df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
                min_date = df[time_col].min()
                max_date = df[time_col].max()
                if pd.notna(min_date) and pd.notna(max_date):
                    days = (max_date - min_date).days
                    date_range = f"{days} dias"
            st.metric("📅 Período", date_range)
        
        with col4:
            data_size = len(json.dumps(data).encode('utf-8')) / 1024 / 1024  # MB
            st.metric("💾 Tamanho", f"{data_size:.1f} MB")
        
        # Preview dos dados
        with st.expander("🔍 Preview dos Dados (Primeiros 5 registros)"):
            if len(df) > 0:
                st.dataframe(df.head(), use_container_width=True)
            else:
                st.info("Nenhum dado para exibir")

# Função auxiliar para uso no app principal
def render_enhanced_data_interface() -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Renderiza interface aprimorada e retorna configuração e dados."""
    
    interface = EnhancedDataInterface()
    
    # Renderiza seletor de fonte
    config_data = interface.render_data_source_selector()
    
    # Botão para buscar dados
    if st.button("🚀 Buscar Dados", type="primary", use_container_width=True):
        with st.spinner("Buscando dados das fontes configuradas..."):
            try:
                # Executa busca assíncrona
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                data = loop.run_until_complete(interface.fetch_data_async(config_data))
                loop.close()
                
                # Armazena dados na sessão
                st.session_state['fetched_data'] = data
                st.session_state['data_config'] = config_data
                
                # Renderiza resumo
                interface.render_data_summary(data)
                
                return config_data, data
                
            except Exception as e:
                st.error(f"❌ Erro ao buscar dados: {str(e)}")
                return config_data, []
    
    # Retorna dados da sessão se existirem
    if 'fetched_data' in st.session_state:
        data = st.session_state['fetched_data']
        interface.render_data_summary(data)
        return st.session_state.get('data_config', config_data), data
    
    return config_data, []