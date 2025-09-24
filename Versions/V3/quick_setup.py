# quick_setup.py - Setup rápido para testar conectores

import asyncio
import os
from dotenv import load_dotenv

# Carrega variáveis do .env
load_dotenv()

from azure_data_connectors import DataSourceConfig, DataConnectorFactory, UnifiedDataManager

async def test_connections():
    """Testa conectividade com ambas as fontes."""
    
    print("🧪 Testando Conectores Azure...")
    
    # Log Analytics a partir do .env
    la_config = DataSourceConfig(
        source_type='log_analytics',
        workspace_id=os.getenv('AZURE_LOG_ANALYTICS_WORKSPACE_ID'),
        tenant_id=os.getenv('AZURE_TENANT_ID'),
        client_id=os.getenv('AZURE_CLIENT_ID'),
        client_secret=os.getenv('AZURE_CLIENT_SECRET')
    )
    
    # Blob Storage a partir do .env
    bs_config = DataSourceConfig(
        source_type='storage_account',
        storage_account_name=os.getenv('AZURE_STORAGE_ACCOUNT'),
        container_name=os.getenv('AZURE_STORAGE_CONTAINER'),
        connection_string=None  # Usar Managed Identity ou criar connection string
    )
    
    # Criar conectores
    try:
        la_connector = DataConnectorFactory.create_connector(la_config)
        bs_connector = DataConnectorFactory.create_connector(bs_config)
        
        # Teste de conectividade
        print("📊 Testando Log Analytics...")
        la_status = la_connector.validate_connection()
        print(f"   Status: {'✅ Conectado' if la_status else '❌ Falha'}")
        
        print("💾 Testando Blob Storage...")
        bs_status = bs_connector.validate_connection()
        print(f"   Status: {'✅ Conectado' if bs_status else '❌ Falha'}")
        
        if la_status:
            # Teste de query simples
            print("🔍 Executando query de teste...")
            test_data = await la_connector.fetch_data({
                'analysis_type': 'role_assignments',
                'timeframe': '1d',
                'limit': 10
            })
            print(f"   Resultados: {len(test_data)} registros")
        
        if bs_status:
            # Teste de listagem de blobs
            print("📁 Listando blobs de teste...")
            blob_data = await bs_connector.fetch_data({
                'max_blobs': 5
            })
            print(f"   Resultados: {len(blob_data)} registros")
            
    except Exception as e:
        print(f"❌ Erro nos testes: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_connections())