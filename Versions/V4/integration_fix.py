# integration_fix.py - Como corrigir/integrar conectores no app principal

"""
PROBLEMA: App funcionando mas sem conectores Azure integrados
SOLUÇÃO: Modificações específicas no app.py
"""

# 1. ADICIONAR NO INÍCIO DO app.py (após imports existentes):
additional_imports = '''
# Adicionar após imports existentes no app.py
try:
    from dotenv import load_dotenv
    from azure_data_connectors import UnifiedDataManager, DataConnectorFactory, DataSourceConfig
    from enhanced_data_interface import render_enhanced_data_interface
    load_dotenv()  # Carrega .env
    AZURE_CONNECTORS_AVAILABLE = True
except ImportError as e:
    AZURE_CONNECTORS_AVAILABLE = False
    st.warning(f"⚠️ Conectores Azure não disponíveis: {e}")
'''

# 2. MODIFICAR SEÇÃO DE UPLOAD NO app.py:
def show_data_source_integration():
    return '''
# ENCONTRAR esta seção no app.py (por volta da linha 200-300):
uploaded_file = st.file_uploader(
    "📁 Selecione o arquivo de logs (JSON)", 
    type=['json'],
    help="Faça upload de um arquivo JSON contendo logs de auditoria do Azure"
)

# SUBSTITUIR POR:
st.sidebar.markdown("### 🔌 Fonte de Dados")

if AZURE_CONNECTORS_AVAILABLE:
    data_source = st.sidebar.selectbox(
        "Selecione a Fonte:",
        ["manual_upload", "azure_log_analytics", "azure_blob_storage"],
        format_func=lambda x: {
            "manual_upload": "📁 Upload Manual",
            "azure_log_analytics": "📊 Azure Log Analytics", 
            "azure_blob_storage": "💾 Azure Blob Storage"
        }[x]
    )
    
    if data_source == "manual_upload":
        uploaded_file = st.file_uploader(
            "📁 Selecione o arquivo de logs (JSON)", 
            type=['json'],
            help="Faça upload de um arquivo JSON contendo logs de auditoria do Azure"
        )
        if uploaded_file:
            logs = json.loads(uploaded_file.read())
    
    elif data_source == "azure_log_analytics":
        if st.sidebar.button("🔄 Buscar do Log Analytics"):
            with st.spinner("Buscando dados do Log Analytics..."):
                logs = fetch_from_log_analytics()
    
    elif data_source == "azure_blob_storage":
        if st.sidebar.button("🔄 Buscar do Blob Storage"):
            with st.spinner("Buscando dados do Blob Storage..."):
                logs = fetch_from_blob_storage()
else:
    # Fallback para upload manual se Azure não disponível
    uploaded_file = st.file_uploader(
        "📁 Selecione o arquivo de logs (JSON)", 
        type=['json'],
        help="Faça upload de um arquivo JSON contendo logs de auditoria do Azure"
    )
    if uploaded_file:
        logs = json.loads(uploaded_file.read())
'''

# 3. ADICIONAR FUNÇÕES AUXILIARES NO app.py:
def show_helper_functions():
    return '''
# ADICIONAR estas funções no app.py (antes da função main):

@st.cache_data(ttl=300)  # Cache por 5 minutos
def fetch_from_log_analytics(timeframe="7d"):
    """Busca dados do Azure Log Analytics"""
    try:
        import os
        manager = UnifiedDataManager()
        
        # Configurar Log Analytics
        la_config = DataSourceConfig(
            source_type='log_analytics',
            workspace_id=os.getenv('AZURE_LOG_ANALYTICS_WORKSPACE_ID'),
            tenant_id=os.getenv('AZURE_TENANT_ID'),
            client_id=os.getenv('AZURE_CLIENT_ID'),
            client_secret=os.getenv('AZURE_CLIENT_SECRET')
        )
        
        la_connector = DataConnectorFactory.create_connector(la_config)
        manager.register_connector('log_analytics', la_connector)
        
        # Buscar dados
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        data = loop.run_until_complete(
            la_connector.fetch_data({
                'analysis_type': 'comprehensive_governance',
                'timeframe': timeframe,
                'limit': 10000
            })
        )
        loop.close()
        
        st.success(f"✅ {len(data)} registros obtidos do Log Analytics")
        return data
        
    except Exception as e:
        st.error(f"❌ Erro ao buscar do Log Analytics: {str(e)}")
        return []

@st.cache_data(ttl=300)
def fetch_from_blob_storage(max_blobs=50):
    """Busca dados do Azure Blob Storage"""
    try:
        import os
        manager = UnifiedDataManager()
        
        # Configurar Blob Storage
        bs_config = DataSourceConfig(
            source_type='storage_account',
            storage_account_name=os.getenv('AZURE_STORAGE_ACCOUNT'),
            container_name=os.getenv('AZURE_STORAGE_CONTAINER', 'entraidlogs')
        )
        
        bs_connector = DataConnectorFactory.create_connector(bs_config)
        manager.register_connector('blob_storage', bs_connector)
        
        # Buscar dados
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        data = loop.run_until_complete(
            bs_connector.fetch_data({
                'max_blobs': max_blobs,
                'blob_prefix': 'entraidlogs/'
            })
        )
        loop.close()
        
        st.success(f"✅ {len(data)} registros obtidos do Blob Storage")
        return data
        
    except Exception as e:
        st.error(f"❌ Erro ao buscar do Blob Storage: {str(e)}")
        return []
'''

print("PASSOS PARA CORRIGIR/INTEGRAR:")
print("="*50)
print("\n1. ADICIONAR IMPORTS:")
print(additional_imports)
print("\n2. MODIFICAR SEÇÃO DE UPLOAD:")
print(show_data_source_integration())
print("\n3. ADICIONAR FUNÇÕES AUXILIARES:")
print(show_helper_functions())
print("\n4. VERIFICAR SE .env ESTÁ CONFIGURADO:")
print("Arquivo .env deve ter todas as credenciais Azure")
print("\n5. TESTAR:")
print("python -m streamlit run app.py --server.port 8508")