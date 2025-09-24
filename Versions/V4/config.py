# config.py

import os
from dataclasses import dataclass
from typing import Optional

# Carregar variáveis do arquivo .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Se python-dotenv não estiver instalado, continua sem erro
    pass

@dataclass
class AzureConfig:
    """Configuration for Azure services - Enhanced for PrivIQ"""
    
    # Azure OpenAI Configuration (do .env)
    openai_endpoint: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    openai_api_key: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    openai_deployment_name: str = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1")
    openai_api_version: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
    
    # Azure Blob Storage Configuration
    storage_account_name: str = os.getenv("AZURE_STORAGE_ACCOUNT", "")
    storage_account_key: str = os.getenv("AZURE_STORAGE_KEY", "")
    storage_connection_string: str = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "")
    storage_container_name: str = os.getenv("AZURE_STORAGE_CONTAINER", "entraidlogs")
    
    @property
    def storage_key(self) -> str:
        """Alias for storage_account_key for consistency"""
        return self.storage_account_key
    
    @property
    def container_name(self) -> str:
        """Alias for storage_container_name for compatibility"""
        return self.storage_container_name
    
    @property 
    def connection_string(self) -> str:
        """Alias for storage_connection_string for compatibility"""
        return self.storage_connection_string
    
    # Azure Log Analytics Configuration
    log_analytics_workspace_id: str = os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "")
    log_analytics_tenant_id: str = os.getenv("AZURE_TENANT_ID", "")
    log_analytics_client_id: str = os.getenv("AZURE_CLIENT_ID", "")
    log_analytics_client_secret: str = os.getenv("AZURE_CLIENT_SECRET", "")
    
    # Data Source Configuration
    default_timeframe: str = "30d"
    max_logs_per_query: int = 10000
    enable_data_caching: bool = True
    cache_ttl_minutes: int = 5
    
    # Analysis Configuration
    max_log_entries: int = 1000
    analysis_batch_size: int = 50
    max_logs_for_ai_analysis: int = 500
    enable_debug_logging: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    def is_openai_configured(self) -> bool:
        """Check if OpenAI configuration is complete"""
        return bool(self.openai_endpoint and self.openai_api_key)
    
    def is_blob_storage_configured(self) -> bool:
        """Check if Blob Storage configuration is complete"""
        return bool(self.storage_account_name and self.storage_account_key)
    
    def is_log_analytics_configured(self) -> bool:
        """Check if Log Analytics configuration is complete"""
        return bool(self.log_analytics_workspace_id and self.log_analytics_tenant_id)
    
    def get_openai_config(self) -> dict:
        """Retorna configurações do OpenAI como dicionário."""
        return {
            'api_key': self.openai_api_key,
            'endpoint': self.openai_endpoint,
            'deployment_name': self.openai_deployment_name,
            'api_version': self.openai_api_version
        }
    
    def validate_configuration(self) -> list:
        """Valida configurações e retorna lista de erros."""
        errors = []
        
        if not self.is_openai_configured():
            errors.append("Azure OpenAI não está configurado corretamente")
        
        if self.max_logs_for_ai_analysis < 10:
            errors.append("max_logs_for_ai_analysis deve ser pelo menos 10")
        
        if self.max_logs_for_ai_analysis > 2000:
            errors.append("max_logs_for_ai_analysis não deve exceder 2000 para evitar custos excessivos")
        
        return errors

    @property
    def privileged_roles(self) -> set:
        """Retorna conjunto de roles privilegiadas."""
        return {
            'Global Administrator',
            'Privileged Role Administrator', 
            'Security Administrator',
            'User Administrator',
            'Application Administrator',
            'Cloud Application Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'Teams Administrator',
            'Intune Administrator',
            'Conditional Access Administrator',
            'Authentication Administrator',
            'Privileged Authentication Administrator',
            'Azure AD Joined Device Local Administrator',
            'Directory Writers',
            'Directory Readers',
            # Incluindo roles do seu config original
            'Owner',
            'Contributor', 
            'User Access Administrator',
            'Billing Administrator'
        }
    
    @property
    def sod_conflict_rules(self) -> list:
        """Retorna regras de conflito SOD."""
        return [
            ('Global Administrator', 'Security Administrator'),
            ('User Administrator', 'Privileged Role Administrator'),
            ('Application Administrator', 'Cloud Application Administrator'),
            ('Exchange Administrator', 'Security Administrator'),
            ('Privileged Role Administrator', 'Authentication Administrator'),
            # Incluindo conflitos do seu config original
            ('Security Administrator', 'User Access Administrator'),
            ('Owner', 'Security Administrator'),
            ('Global Administrator', 'Billing Administrator')
        ]
    
    @property
    def risk_weights(self) -> dict:
        """Retorna pesos para cálculo de risco."""
        return {
            'direct_assignment': 10,
            'sod_violation': 25,
            'excessive_privileges': 15,
            'duplicate_groups': 5,
            'after_hours_access': 8,
            'multiple_ips': 12,
            'failed_attempts': 15,
            'multiple_admin_roles': 20,
            'cross_tenant_access': 18,
            'privileged_escalation': 30,
            'unusual_access_patterns': 12,
            'dormant_account_activation': 22
        }

# Global configuration instance
config = AzureConfig()

# Security analysis patterns and rules - Enhanced and Combined
SECURITY_PATTERNS = {
    # Roles críticas - combinando ambas as listas
    "critical_permissions": [
        "Owner", "Contributor", "User Access Administrator",
        "Security Administrator", "Global Administrator",
        "Application Administrator", "Cloud Application Administrator",
        "Privileged Role Administrator", "User Administrator",
        "Exchange Administrator", "SharePoint Administrator",
        "Teams Administrator", "Intune Administrator",
        "Conditional Access Administrator", "Authentication Administrator"
    ],
    
    # Violações SOD - expandidas
    "sod_violations": [
        {"roles": ["Security Administrator", "User Access Administrator"], "violation": "Security and Access Management conflict"},
        {"roles": ["Owner", "Security Administrator"], "violation": "Resource and Security Management conflict"},
        {"roles": ["Global Administrator", "Billing Administrator"], "violation": "Administrative and Financial conflict"},
        {"roles": ["Global Administrator", "Security Administrator"], "violation": "Global and Security Administration conflict"},
        {"roles": ["User Administrator", "Privileged Role Administrator"], "violation": "User and Privilege Management conflict"},
        {"roles": ["Application Administrator", "Cloud Application Administrator"], "violation": "Application Management conflict"},
        {"roles": ["Exchange Administrator", "Security Administrator"], "violation": "Exchange and Security conflict"},
        {"roles": ["Privileged Role Administrator", "Authentication Administrator"], "violation": "Privilege and Authentication conflict"}
    ],
    
    # Recursos sensíveis
    "sensitive_resources": [
        "Microsoft.KeyVault", "Microsoft.Security", "Microsoft.Authorization",
        "Microsoft.AAD", "Microsoft.Storage", "Microsoft.Sql",
        "Microsoft.Compute", "Microsoft.Network", "Microsoft.Resources"
    ],
    
    # Indicadores de risco - expandidos
    "risk_indicators": [
        "multiple_admin_roles", "cross_tenant_access", "privileged_escalation",
        "unusual_access_patterns", "dormant_account_activation", "direct_assignment",
        "sod_violation", "excessive_privileges", "duplicate_groups",
        "after_hours_access", "multiple_ips", "failed_attempts"
    ],
    
    # Novos - para compatibilidade com código melhorado
    'privileged_roles': config.privileged_roles,
    'sod_conflicts': config.sod_conflict_rules,
    'risk_weights': config.risk_weights
}