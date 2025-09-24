import os
from dataclasses import dataclass
from typing import Optional




@dataclass
class AzureConfig:
    """Configuration for Azure services"""
    
    # Azure OpenAI Configuration
    openai_endpoint: str = "https://raul-mfh7lgww-northcentralus.cognitiveservices.azure.com/"
    openai_api_key: str = "BXo63B0o379tEJmw68aaT1T68VvEOe2rWVixdkHxLLa72nRyAPHbJQQJ99BIACHrzpqXJ3w3AAAAACOGsQUV"
    openai_deployment_name: str = "gpt-4.1"
    openai_api_version: str = "2024-02-15-preview"
    
    # Azure Blob Storage Configuration
    storage_account_name: str = os.getenv("AZURE_STORAGE_ACCOUNT", "")
    storage_account_key: str = os.getenv("AZURE_STORAGE_KEY", "")
    storage_container_name: str = os.getenv("AZURE_STORAGE_CONTAINER", "")
    
    # Analysis Configuration
    max_log_entries: int = 1000
    analysis_batch_size: int = 50
    
    def is_openai_configured(self) -> bool:
        """Check if OpenAI configuration is complete"""
        return bool(self.openai_endpoint and self.openai_api_key)
    
    def is_blob_storage_configured(self) -> bool:
        """Check if Blob Storage configuration is complete"""
        return bool(self.storage_account_name and self.storage_account_key)

# Global configuration instance
config = AzureConfig()

# Security analysis patterns and rules
SECURITY_PATTERNS = {
    "critical_permissions": [
        "Owner", "Contributor", "User Access Administrator",
        "Security Administrator", "Global Administrator",
        "Application Administrator", "Cloud Application Administrator"
    ],
    
    "sod_violations": [
        {"roles": ["Security Administrator", "User Access Administrator"], "violation": "Security and Access Management conflict"},
        {"roles": ["Owner", "Security Administrator"], "violation": "Resource and Security Management conflict"},
        {"roles": ["Global Administrator", "Billing Administrator"], "violation": "Administrative and Financial conflict"}
    ],
    
    "sensitive_resources": [
        "Microsoft.KeyVault", "Microsoft.Security", "Microsoft.Authorization",
        "Microsoft.AAD", "Microsoft.Storage", "Microsoft.Sql"
    ],
    
    "risk_indicators": [
        "multiple_admin_roles", "cross_tenant_access", "privileged_escalation",
        "unusual_access_patterns", "dormant_account_activation"
    ]
}