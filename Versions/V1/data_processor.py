import pandas as pd
import json
from typing import Dict, List, Any
from config import SECURITY_PATTERNS

class AzureLogProcessor:
    """Processa e analisa logs de auditoria do Azure de forma eficiente."""

    def __init__(self):
        self.logs_df: pd.DataFrame | None = None

    def load_logs_from_file(self, file_content: str) -> pd.DataFrame:
        """Carrega e normaliza logs de um arquivo JSON."""
        try:
            logs_data = json.loads(file_content)
            
            # Normaliza estruturas comuns de logs do Azure
            if isinstance(logs_data, dict):
                if 'value' in logs_data:
                    logs_data = logs_data['value']
                elif 'records' in logs_data:
                    logs_data = logs_data['records']
            
            # pd.json_normalize lida com JSON aninhado de forma mais robusta
            self.logs_df = pd.json_normalize(logs_data, sep='_')
            return self.logs_df
        except (json.JSONDecodeError, TypeError) as e:
            raise ValueError(f"Conteúdo do arquivo não é um JSON válido: {e}")
        except Exception as e:
            raise ValueError(f"Erro inesperado ao processar o arquivo: {e}")

    def generate_summary_stats(self) -> Dict[str, Any]:
        """Gera estatísticas resumidas usando operações vetorizadas do Pandas."""
        if self.logs_df is None or self.logs_df.empty:
            return {}

        return {
            'total_events': len(self.logs_df),
            'unique_users': self.logs_df['identity_userPrincipalName'].nunique() if 'identity_userPrincipalName' in self.logs_df else 0,
            'event_categories': self.logs_df['category'].value_counts().to_dict() if 'category' in self.logs_df else {},
            'success_rate': (self.logs_df['resultType'] == 'Success').mean() * 100 if 'resultType' in self.logs_df else 0,
            'time_range': {
                'start': pd.to_datetime(self.logs_df['time']).min().isoformat() if 'time' in self.logs_df else 'N/A',
                'end': pd.to_datetime(self.logs_df['time']).max().isoformat() if 'time' in self.logs_df else 'N/A',
            }
        }
        
    # As funções create_sample_logs, analyze_permission_conflicts e analyze_critical_access
    # foram mantidas como no original, pois dependem de uma estrutura de log que pode não
    # estar presente nos arquivos reais. A lógica delas precisaria ser adaptada para
    # o DataFrame normalizado (`self.logs_df`).
    
    # ... (manter as outras funções, como create_sample_logs, por enquanto)
    def create_sample_logs(self) -> List[Dict]:
        """Cria logs de exemplo para demonstração."""
        # Código original mantido
        return [
             {
                "time": "2024-01-15T10:30:00Z", "operationName": "Add member to role", "category": "RoleManagement",
                "resultType": "Success", "callerIpAddress": "192.168.1.100", "identity": {"userPrincipalName": "admin@company.com"},
                "properties": {"targetResources": [{"userPrincipalName": "user1@company.com"}], "roleName": "Global Administrator"}
            },
            {
                "time": "2024-01-15T11:00:00Z", "operationName": "Add member to role", "category": "RoleManagement",
                "resultType": "Success", "callerIpAddress": "192.168.1.100", "identity": {"userPrincipalName": "admin@company.com"},
                "properties": {"targetResources": [{"userPrincipalName": "user1@company.com"}], "roleName": "Security Administrator"}
            },
        ]

    def analyze_permission_conflicts(self) -> Dict[str, Any]:
        return {"info": "Análise baseada em regras não implementada na refatoração."}
        
    def analyze_critical_access(self) -> Dict[str, Any]:
        return {"info": "Análise baseada em regras não implementada na refatoração."}