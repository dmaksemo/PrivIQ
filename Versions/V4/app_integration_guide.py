# app_integration_guide.py - Como integrar no app.py principal

"""
GUIA PRÁTICO: Como integrar os conectores Azure no seu app.py existente

PASSO A PASSO:
"""

# 1. ADICIONAR IMPORTS no início do app.py
imports_to_add = '''
# Novos imports para conectores Azure
from dotenv import load_dotenv
from azure_data_connectors import UnifiedDataManager, DataConnectorFactory, DataSourceConfig
from enhanced_data_interface import render_enhanced_data_interface
import asyncio
import os

# Carregar variáveis de ambiente
load_dotenv()
'''

# 2. SUBSTITUIR a seção de upload de arquivo
old_file_upload_section = '''
# CÓDIGO ANTIGO (substituir):
uploaded_file = st.file_uploader("Upload JSON file", type=['json'])
if uploaded_file:
    logs = json.loads(uploaded_file.read())
'''

new_data_interface_section = '''
# CÓDIGO NOVO (integração com Azure):
st.sidebar.markdown("### 🔌 Fonte de Dados")

# Interface unificada para múltiplas fontes
config_data, logs = render_enhanced_data_interface()

# OU implementação mais simples:
data_source = st.sidebar.selectbox(
    "Selecione a Fonte:",
    ["manual", "azure_log_analytics", "azure_blob_storage"]
)

if data_source == "azure_log_analytics":
    if st.sidebar.button("🔄 Buscar do Log Analytics"):
        logs = fetch_from_log_analytics()
elif data_source == "azure_blob_storage":
    if st.sidebar.button("🔄 Buscar do Blob Storage"):
        logs = fetch_from_blob_storage()
else:
    uploaded_file = st.file_uploader("Upload JSON file", type=['json'])
    if uploaded_file:
        logs = json.loads(uploaded_file.read())
'''

# 3. FUNÇÕES AUXILIARES para adicionar no app.py
helper_functions = '''
def init_azure_connectors():
    """Inicializa conectores Azure baseado no .env"""
    manager = UnifiedDataManager()
    
    # Log Analytics
    if all([os.getenv('AZURE_LOG_ANALYTICS_WORKSPACE_ID'), os.getenv('AZURE_TENANT_ID')]):
        la_config = DataSourceConfig(
            source_type='log_analytics',
            workspace_id=os.getenv('AZURE_LOG_ANALYTICS_WORKSPACE_ID'),
            tenant_id=os.getenv('AZURE_TENANT_ID'),
            client_id=os.getenv('AZURE_CLIENT_ID'),
            client_secret=os.getenv('AZURE_CLIENT_SECRET')
        )
        la_connector = DataConnectorFactory.create_connector(la_config)
        manager.register_connector('log_analytics', la_connector)
    
    # Blob Storage
    if os.getenv('AZURE_STORAGE_ACCOUNT'):
        bs_config = DataSourceConfig(
            source_type='storage_account',
            storage_account_name=os.getenv('AZURE_STORAGE_ACCOUNT'),
            container_name=os.getenv('AZURE_STORAGE_CONTAINER', 'entraidlogs'),
            connection_string=f"DefaultEndpointsProtocol=https;AccountName={os.getenv('AZURE_STORAGE_ACCOUNT')};AccountKey={os.getenv('AZURE_STORAGE_KEY')};EndpointSuffix=core.windows.net"
        )
        bs_connector = DataConnectorFactory.create_connector(bs_config)
        manager.register_connector('blob_storage', bs_connector)
    
    return manager

@st.cache_data(ttl=300)  # Cache por 5 minutos
def fetch_from_log_analytics(timeframe="7d", analysis_type="comprehensive_governance"):
    """Busca dados do Log Analytics com cache"""
    try:
        manager = init_azure_connectors()
        if 'log_analytics' in manager.connectors:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            data = loop.run_until_complete(
                manager.connectors['log_analytics'].fetch_data({
                    'analysis_type': analysis_type,
                    'timeframe': timeframe,
                    'limit': 10000
                })
            )
            loop.close()
            return data
        else:
            st.error("Log Analytics não configurado")
            return []
    except Exception as e:
        st.error(f"Erro ao buscar do Log Analytics: {str(e)}")
        return []

@st.cache_data(ttl=300)
def fetch_from_blob_storage(max_blobs=50):
    """Busca dados do Blob Storage com cache"""
    try:
        manager = init_azure_connectors()
        if 'blob_storage' in manager.connectors:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            data = loop.run_until_complete(
                manager.connectors['blob_storage'].fetch_data({
                    'max_blobs': max_blobs,
                    'blob_prefix': 'entraidlogs/'
                })
            )
            loop.close()
            return data
        else:
            st.error("Blob Storage não configurado")
            return []
    except Exception as e:
        st.error(f"Erro ao buscar do Blob Storage: {str(e)}")
        return []
'''

print("INSTRUÇÕES PARA INTEGRAÇÃO:")
print("="*50)
print("\n1. ADICIONAR IMPORTS:")
print(imports_to_add)
print("\n2. SUBSTITUIR SEÇÃO DE UPLOAD:")
print("Trocar:", old_file_upload_section)
print("Por:", new_data_interface_section)
print("\n3. ADICIONAR FUNÇÕES AUXILIARES:")
print(helper_functions)
print("\n4. INSTALAR DEPENDÊNCIA:")
print("pip install python-dotenv")