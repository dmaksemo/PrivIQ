#!/usr/bin/env python3
"""
Debug das configurações do .env
"""

import os
from config import config

def main():
    print("🔍 DEBUG DAS CONFIGURAÇÕES DO .ENV")
    print("=" * 50)
    
    print("\n📊 Azure OpenAI:")
    print(f"  Endpoint: {config.openai_endpoint}")
    print(f"  API Key: {config.openai_api_key[:20]}..." if config.openai_api_key else "  API Key: (vazio)")
    print(f"  Deployment: {config.openai_deployment_name}")
    print(f"  API Version: {config.openai_api_version}")
    
    print("\n📈 Azure Log Analytics:")
    print(f"  Workspace ID: {config.log_analytics_workspace_id}")
    print(f"  Tenant ID: {config.log_analytics_tenant_id}")
    print(f"  Client ID: {config.log_analytics_client_id}")
    print(f"  Client Secret: {config.log_analytics_client_secret[:20]}..." if config.log_analytics_client_secret else "  Client Secret: (vazio)")
    
    print("\n💾 Azure Blob Storage:")
    print(f"  Storage Account: {config.storage_account_name}")
    print(f"  Storage Key: {config.storage_account_key[:20]}..." if config.storage_account_key else "  Storage Key: (vazio)")
    print(f"  Container: {config.storage_container_name}")
    
    print("\n🔍 Variáveis de Ambiente Diretas:")
    env_vars = [
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_API_KEY", 
        "AZURE_LOG_ANALYTICS_WORKSPACE_ID",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_STORAGE_ACCOUNT",
        "AZURE_STORAGE_KEY",
        "AZURE_STORAGE_CONTAINER"
    ]
    
    for var in env_vars:
        value = os.getenv(var, "(não encontrado)")
        if "KEY" in var or "SECRET" in var:
            display_value = f"{value[:20]}..." if value != "(não encontrado)" else value
        else:
            display_value = value
        print(f"  {var}: {display_value}")

if __name__ == "__main__":
    main()