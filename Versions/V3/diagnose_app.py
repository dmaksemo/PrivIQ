# diagnose_app.py - Diagnóstico completo do app

import streamlit as st
import sys
import os
from datetime import datetime

def main():
    st.title("🔍 Diagnóstico do PrivilegeIQ")
    
    # Informações do sistema
    st.header("💻 Informações do Sistema")
    col1, col2 = st.columns(2)
    
    with col1:
        st.info(f"**Python Version**: {sys.version}")
        st.info(f"**Streamlit Version**: {st.__version__}")
        st.info(f"**Working Directory**: {os.getcwd()}")
    
    with col2:
        st.info(f"**Date/Time**: {datetime.now()}")
        st.info(f"**Platform**: {sys.platform}")
    
    # Teste de importações
    st.header("📦 Status das Importações")
    
    modules_to_test = [
        ("data_processor", "AzureLogProcessor"),
        ("azure_log_analyzer", "AzureLogAnalyzer"),
        ("governance_analyzer", "AdvancedGovernanceAnalyzer"),
        ("visualization_generator", "SecurityVisualizationGenerator"),
        ("models", "AIAnalysisResult, EnhancedAIAnalysisResult"),
        ("config", "config"),
        ("azure_data_connectors", "UnifiedDataManager"),
        ("enhanced_data_interface", "EnhancedDataInterface"),
        ("kql_templates", "KQLTemplateManager"),
        ("plotly", "plotly"),
        ("pandas", "pandas"),
        ("json", "json")
    ]
    
    success_count = 0
    total_count = len(modules_to_test)
    
    for module_name, classes in modules_to_test:
        try:
            exec(f"import {module_name}")
            st.success(f"✅ **{module_name}** - {classes}")
            success_count += 1
        except ImportError as e:
            st.error(f"❌ **{module_name}** - ERRO: {e}")
        except Exception as e:
            st.warning(f"⚠️ **{module_name}** - Aviso: {e}")
    
    # Status geral
    st.header("📊 Status Geral")
    if success_count == total_count:
        st.success(f"🎉 **Perfeito!** Todos os {total_count} módulos importados com sucesso!")
    else:
        st.warning(f"⚠️ **Atenção**: {success_count}/{total_count} módulos importados com sucesso")
    
    # Teste de configurações
    st.header("⚙️ Configurações")
    
    try:
        from config import config
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🤖 OpenAI")
            if config.is_openai_configured():
                st.success("✅ OpenAI Configurado")
                st.info(f"Endpoint: {config.openai_endpoint[:50]}...")
            else:
                st.error("❌ OpenAI Não Configurado")
        
        with col2:
            st.subheader("☁️ Azure Services")
            if config.is_log_analytics_configured():
                st.success("✅ Log Analytics Configurado")
            else:
                st.warning("⚠️ Log Analytics Não Configurado")
            
            if config.is_blob_storage_configured():
                st.success("✅ Blob Storage Configurado")
            else:
                st.warning("⚠️ Blob Storage Não Configurado")
                
    except Exception as e:
        st.error(f"❌ Erro ao verificar configurações: {e}")
    
    # Teste de Azure SDK
    st.header("☁️ Azure SDK")
    
    azure_modules = [
        "azure.identity",
        "azure.monitor.query", 
        "azure.storage.blob",
        "azure.core"
    ]
    
    azure_success = 0
    for module in azure_modules:
        try:
            exec(f"import {module}")
            st.success(f"✅ {module}")
            azure_success += 1
        except ImportError:
            st.error(f"❌ {module} - Não instalado")
        except Exception as e:
            st.warning(f"⚠️ {module} - {e}")
    
    if azure_success == len(azure_modules):
        st.success("🎉 Todos os módulos Azure SDK disponíveis!")
    else:
        st.warning(f"⚠️ Instale dependências Azure: pip install azure-identity azure-monitor-query azure-storage-blob")
    
    # Teste de conectividade (se configurado)
    st.header("🔌 Teste de Conectividade")
    
    if st.button("🧪 Testar Conectores Azure"):
        try:
            from azure_data_connectors import DataSourceConfig, DataConnectorFactory
            from config import config
            
            with st.spinner("Testando conectividade..."):
                if config.is_log_analytics_configured():
                    try:
                        la_config = DataSourceConfig(
                            source_type='log_analytics',
                            workspace_id=config.log_analytics_workspace_id,
                            tenant_id=config.log_analytics_tenant_id,
                            client_id=config.log_analytics_client_id,
                            client_secret=config.log_analytics_client_secret
                        )
                        la_connector = DataConnectorFactory.create_connector(la_config)
                        la_status = la_connector.validate_connection()
                        
                        if la_status:
                            st.success("✅ Log Analytics - Conectado")
                        else:
                            st.error("❌ Log Analytics - Falha na conexão")
                    except Exception as e:
                        st.error(f"❌ Log Analytics - Erro: {e}")
                
                if config.is_blob_storage_configured():
                    try:
                        bs_config = DataSourceConfig(
                            source_type='storage_account',
                            storage_account_name=config.storage_account_name,
                            container_name=config.storage_container_name
                        )
                        bs_connector = DataConnectorFactory.create_connector(bs_config)
                        bs_status = bs_connector.validate_connection()
                        
                        if bs_status:
                            st.success("✅ Blob Storage - Conectado")
                        else:
                            st.error("❌ Blob Storage - Falha na conexão")
                    except Exception as e:
                        st.error(f"❌ Blob Storage - Erro: {e}")
                        
        except Exception as e:
            st.error(f"❌ Erro no teste de conectividade: {e}")
    
    # Informações para depuração
    st.header("🔧 Informações para Depuração")
    
    with st.expander("📋 Variáveis de Ambiente"):
        env_vars = [
            "AZURE_LOG_ANALYTICS_WORKSPACE_ID",
            "AZURE_TENANT_ID", 
            "AZURE_CLIENT_ID",
            "AZURE_STORAGE_ACCOUNT",
            "AZURE_STORAGE_CONTAINER"
        ]
        
        for var in env_vars:
            value = os.getenv(var, "Não definida")
            if value != "Não definida":
                # Mascarar dados sensíveis
                if "SECRET" in var or "KEY" in var:
                    display_value = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else "***"
                else:
                    display_value = value
                st.success(f"✅ {var}: {display_value}")
            else:
                st.warning(f"⚠️ {var}: {value}")
    
    with st.expander("📁 Arquivos do Projeto"):
        current_dir = os.getcwd()
        files = os.listdir(current_dir)
        python_files = [f for f in files if f.endswith('.py')]
        config_files = [f for f in files if f.endswith(('.json', '.env', '.txt'))]
        
        st.write("**Arquivos Python:**")
        for file in sorted(python_files):
            st.text(f"📄 {file}")
        
        st.write("**Arquivos de Configuração:**")
        for file in sorted(config_files):
            st.text(f"⚙️ {file}")

if __name__ == "__main__":
    main()