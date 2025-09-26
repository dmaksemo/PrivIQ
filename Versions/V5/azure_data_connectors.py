# azure_data_connectors.py

import json
import logging
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from dataclasses import dataclass
import asyncio
import pandas as pd

# Azure SDK imports
try:
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import AzureError
except ImportError:
    logging.warning("Azure SDK not installed. Install with: pip install azure-storage-blob")

from config import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DataSourceConfig:
    """Configuração para fontes de dados Azure."""
    source_type: str  # 'storage_account', 'manual'
    connection_string: Optional[str] = None
    storage_account_name: Optional[str] = None
    container_name: Optional[str] = None
    storage_key: Optional[str] = None
    storage_connection_string: Optional[str] = None

class DataConnectorInterface(ABC):
    """Interface base para conectores de dados."""
    
    @abstractmethod
    async def fetch_data(self, query_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca dados da fonte específica."""
        pass
    
    @abstractmethod
    def validate_connection(self) -> bool:
        """Valida conectividade com a fonte de dados."""
        pass

class AzureBlobStorageConnector(DataConnectorInterface):
    """Conector para Azure Blob Storage."""
    
    def __init__(self, config: DataSourceConfig):
        self.config = config
        self.client = None
        self.container_name = config.container_name or "audit-logs"
        self._initialize_client()
    
    def _initialize_client(self):
        """Inicializa cliente do Blob Storage."""
        try:
            # Prioridade 1: Connection String específica do config (SEMPRE PRIMEIRA OPÇÃO)
            if self.config.storage_connection_string:
                self.client = BlobServiceClient.from_connection_string(
                    self.config.storage_connection_string
                )
                logger.info("Azure Blob Storage client inicializado com Connection String específica")
                return
                
            # Prioridade 2: Connection String genérica
            elif self.config.connection_string:
                self.client = BlobServiceClient.from_connection_string(
                    self.config.connection_string
                )
                logger.info("Azure Blob Storage client inicializado com Connection String genérica")
                return
                
            # Prioridade 3: Storage account key (evita problemas de multi-tenant)
            elif self.config.storage_key and self.config.storage_account_name:
                account_url = f"https://{self.config.storage_account_name}.blob.core.windows.net"
                self.client = BlobServiceClient(
                    account_url=account_url,
                    credential=self.config.storage_key
                )
                logger.info("Azure Blob Storage client inicializado com Storage Key")
                return
                
            else:
                logger.error("Nenhuma credencial válida encontrada para Blob Storage")
                raise Exception("Credenciais de Blob Storage não configuradas corretamente")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar Blob Storage client: {e}")
            raise
    
    def validate_connection(self) -> bool:
        """Testa conectividade com Blob Storage."""
        try:
            container_client = self.client.get_container_client(self.container_name)
            container_client.get_container_properties()
            return True
        except Exception as e:
            logger.error(f"Falha na validação de conexão: {e}")
            return False
    
    async def fetch_data(self, query_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca logs do Blob Storage."""
        try:
            container_client = self.client.get_container_client(self.container_name)
            
            # Lista blobs baseado em parâmetros
            blob_prefix = query_params.get('blob_prefix', '')
            filter_type = query_params.get('filter_type', 'Prefixo')
            date_filter = query_params.get('date_filter')
            
            # Ajusta estratégia de busca baseado no tipo de filtro
            if filter_type == "Nome Específico" and blob_prefix:
                # Para nome específico, verifica se o blob existe diretamente
                try:
                    blob_client = container_client.get_blob_client(blob_prefix)
                    blob_properties = blob_client.get_blob_properties()
                    blobs = [type('obj', (object,), {
                        'name': blob_prefix,
                        'last_modified': blob_properties.last_modified,
                        'size': blob_properties.size
                    })()]
                except Exception:
                    # Se não encontrar o blob específico, tenta listar com prefixo
                    blobs = container_client.list_blobs(name_starts_with=blob_prefix)
            elif filter_type == "Todos os Arquivos":
                # Lista todos os blobs
                blobs = container_client.list_blobs()
            else:
                # Busca por prefixo (comportamento padrão)
                blobs = container_client.list_blobs(name_starts_with=blob_prefix)
            
            all_logs = []
            blob_count = 0
            max_blobs = query_params.get('max_blobs', 100)
            
            for blob in blobs:
                if blob_count >= max_blobs:
                    break
                
                # Filtro por data se especificado
                if date_filter and blob.last_modified < date_filter:
                    continue
                
                try:
                    blob_client = container_client.get_blob_client(blob.name)
                    content = blob_client.download_blob().readall()
                    
                    # Parse JSON ou CSV
                    if blob.name.endswith('.json'):
                        logs = json.loads(content)
                        if isinstance(logs, list):
                            all_logs.extend(logs)
                        else:
                            all_logs.append(logs)
                    elif blob.name.endswith('.csv'):
                        # Processa CSV se necessário (implementação básica)
                        import csv
                        import io
                        csv_reader = csv.DictReader(io.StringIO(content.decode('utf-8')))
                        for row in csv_reader:
                            all_logs.append(row)
                    
                    blob_count += 1
                    logger.info(f"Processado blob: {blob.name}")
                    
                except Exception as e:
                    logger.warning(f"Erro ao processar blob {blob.name}: {e}")
                    continue
            
            logger.info(f"Recuperados {len(all_logs)} logs de {blob_count} blobs")
            return all_logs
            
        except Exception as e:
            logger.error(f"Erro ao buscar dados do Blob Storage: {e}")
            raise

class UnifiedDataManager:
    """Gerenciador unificado para múltiplas fontes de dados."""
    
    def __init__(self):
        self.connectors: Dict[str, DataConnectorInterface] = {}
        self.cache: Dict[str, Any] = {}
        self.cache_ttl = 300  # 5 minutos
    
    def register_connector(self, name: str, connector: DataConnectorInterface):
        """Registra um conector de dados."""
        self.connectors[name] = connector
        logger.info(f"Conector '{name}' registrado")
    
    async def fetch_unified_data(self, 
                               sources: List[str], 
                               query_params: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """Busca dados de múltiplas fontes de forma unificada."""
        results = {}
        
        # Executa queries em paralelo
        tasks = []
        for source in sources:
            if source in self.connectors:
                task = self._fetch_with_cache(source, query_params)
                tasks.append((source, task))
        
        # Aguarda todas as queries
        for source, task in tasks:
            try:
                data = await task
                results[source] = data
                logger.info(f"Dados obtidos de '{source}': {len(data)} registros")
            except Exception as e:
                logger.error(f"Erro ao buscar dados de '{source}': {e}")
                results[source] = []
        
        return results
    
    async def _fetch_with_cache(self, source: str, params: Dict[str, Any]) -> List[Dict]:
        """Busca dados com cache."""
        cache_key = f"{source}_{hash(str(sorted(params.items())))}"
        
        # Verifica cache
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if (datetime.now() - timestamp).seconds < self.cache_ttl:
                logger.info(f"Dados de '{source}' obtidos do cache")
                return cached_data
        
        # Busca dados
        connector = self.connectors[source]
        data = await connector.fetch_data(params)
        
        # Armazena no cache
        self.cache[cache_key] = (data, datetime.now())
        
        return data
    
    def get_available_sources(self) -> List[str]:
        """Retorna lista de fontes disponíveis."""
        return list(self.connectors.keys())
    
    def validate_all_connections(self) -> Dict[str, bool]:
        """Valida conectividade de todas as fontes."""
        results = {}
        for name, connector in self.connectors.items():
            try:
                results[name] = connector.validate_connection()
            except Exception as e:
                logger.error(f"Erro ao validar '{name}': {e}")
                results[name] = False
        return results

# Factory para criar conectores
class DataConnectorFactory:
    """Factory para criar conectores baseado em configuração."""
    
    @staticmethod
    def create_connector(config: DataSourceConfig) -> DataConnectorInterface:
        """Cria conector baseado no tipo especificado."""
        if config.source_type == 'storage_account':
            return AzureBlobStorageConnector(config)
        else:
            raise ValueError(f"Tipo de fonte não suportado: {config.source_type}")
    
    @staticmethod
    def create_from_config_file(config_path: str) -> Dict[str, DataConnectorInterface]:
        """Cria múltiplos conectores a partir de arquivo de configuração."""
        with open(config_path, 'r') as f:
            configs = json.load(f)
        
        connectors = {}
        for name, config_dict in configs.items():
            config = DataSourceConfig(**config_dict)
            connectors[name] = DataConnectorFactory.create_connector(config)
        
        return connectors

# Exemplo de uso
async def example_usage():
    """Exemplo de como usar os conectores."""
    
    # Configuração do Log Analytics
    log_analytics_config = DataSourceConfig(
        source_type='log_analytics',
        workspace_id='your-workspace-id',
        tenant_id='your-tenant-id'
    )
    
    # Configuração do Blob Storage
    storage_config = DataSourceConfig(
        source_type='storage_account',
        storage_account_name='your-storage-account',
        container_name='audit-logs'
    )
    
    # Cria conectores
    log_connector = DataConnectorFactory.create_connector(log_analytics_config)
    storage_connector = DataConnectorFactory.create_connector(storage_config)
    
    # Gerenciador unificado
    data_manager = UnifiedDataManager()
    data_manager.register_connector('log_analytics', log_connector)
    data_manager.register_connector('storage', storage_connector)
    
    # Parâmetros de consulta
    query_params = {
        'analysis_type': 'role_assignments',
        'timeframe': '7d',
        'limit': 1000
    }
    
    # Busca dados de ambas as fontes
    results = await data_manager.fetch_unified_data(
        sources=['log_analytics', 'storage'],
        query_params=query_params
    )
    
    # Processa resultados
    for source, data in results.items():
        print(f"Fonte: {source}, Registros: {len(data)}")

if __name__ == "__main__":
    asyncio.run(example_usage())