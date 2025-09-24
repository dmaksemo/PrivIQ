# 🛡️ PrivIQ - Plataforma de Governança e Compliance Azure

## Projeto Hackaton IA 2025 | PrivIQ - Plataforma de Governança e Compliance Azure

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)](https://streamlit.io)
[![Azure](https://img.shields.io/badge/Azure-Entra%20ID-0078d4.svg)](https://azure.microsoft.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**PrivIQ** é uma plataforma inteligente de análise de governança e compliance para ambientes Azure, desenvolvida para identificar riscos de segurança, violações de compliance e oportunidades de melhoria em tempo real.

## 🎯 **O que faz?**

O PrivIQ analisa logs do **Azure Entra ID** (antigo Active Directory) e **Azure Activity Logs** para:

- 🔍 **Detectar violações de governança** (SOD, privilégios excessivos, acessos suspeitos)
- 📊 **Gerar relatórios de compliance** para frameworks como SOX, NIST, ISO27001, GDPR
- 🤖 **Análise inteligente com IA** usando Azure OpenAI para insights avançados
- 📈 **Visualizar métricas de segurança** com dashboards interativos
- ⚠️ **Alertar sobre riscos críticos** em tempo real
- 📋 **Recomendar ações corretivas** específicas e práticas

## 🚀 **Principais Funcionalidades**

### 🔐 **Análise de Governança**
- **Segregação de Funções (SOD)**: Detecção de violações de segregação
- **Privilégios Excessivos**: Identificação de usuários com permissões desnecessárias
- **Atividades Suspeitas**: Detecção de padrões anômalos de acesso
- **Contas Órfãs**: Identificação de contas inativas ou abandonadas

### 📊 **Compliance e Auditoria**
- **Frameworks Suportados**: SOX, NIST, ISO27001, GDPR, HIPAA, PCI-DSS
- **Score de Compliance**: Pontuação automática de conformidade
- **Relatórios Executivos**: Resumos para gestão e auditoria
- **Trilha de Auditoria**: Rastreamento completo de alterações

### 🤖 **Inteligência Artificial**
- **Azure OpenAI Integration**: Análise semântica de logs
- **Detecção de Anomalias**: Machine learning para padrões suspeitos
- **Recomendações Inteligentes**: Sugestões personalizadas de melhoria
- **Análise Preditiva**: Identificação de riscos futuros

### 📈 **Visualização e Dashboards**
- **Dashboards Interativos**: Métricas em tempo real
- **Gráficos Dinâmicos**: Visualizações com Plotly
- **Filtros Avançados**: Análise por período, usuário, risco
- **Exportação de Dados**: Relatórios em PDF e Excel

## 🛠️ **Requisitos do Sistema**

- **Python**: 3.8 ou superior
- **Sistema Operacional**: Windows, macOS ou Linux
- **Memória RAM**: Mínimo 4GB (recomendado 8GB)
- **Espaço em Disco**: 500MB livres
- **Conectividade**: Acesso à internet para Azure APIs

### **Dependências Azure**
- **Azure Entra ID** (antigo AD) com logs habilitados
- **Azure Log Analytics Workspace** configurado
- **Azure OpenAI** (opcional, para análises com IA)
- **Azure Storage Account** (opcional, para backup de dados)

## 📦 **Instalação e Configuração**

### **Passo 1: Clone ou Baixe o Projeto**
```bash
# Se usando Git
git clone https://github.com/seu-usuario/priviq.git
cd priviq

# Ou extraia o arquivo ZIP baixado
unzip priviq.zip
cd priviq
```

### **Passo 2: Instale o Python**
- Baixe e instale Python 3.8+ de [python.org](https://python.org)
- Verifique a instalação: `python --version`

### **Passo 3: Crie um Ambiente Virtual (Recomendado)**
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

### **Passo 4: Instale as Dependências**
```bash
pip install -r requirements.txt
```

### **Passo 5: Configure as Variáveis de Ambiente**
1. Copie o arquivo de exemplo:
   ```bash
   cp .env.example .env
   ```

2. Edite o arquivo `.env` com suas configurações Azure:
   ```env
   # Azure OpenAI (obrigatório para análises com IA)
   AZURE_OPENAI_ENDPOINT=https://seu-recurso.openai.azure.com
   AZURE_OPENAI_API_KEY=sua-chave-api
   AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4
   AZURE_OPENAI_API_VERSION=2024-02-15-preview

   # Azure Log Analytics (obrigatório)
   AZURE_LOG_ANALYTICS_WORKSPACE_ID=seu-workspace-id
   AZURE_TENANT_ID=seu-tenant-id
   AZURE_CLIENT_ID=seu-client-id
   AZURE_CLIENT_SECRET=seu-client-secret

   # Azure Storage (opcional)
   AZURE_STORAGE_CONNECTION_STRING=sua-connection-string
   AZURE_STORAGE_CONTAINER_NAME=priviq-data
   ```

## 🚦 **Como Executar**

### **Método 1: Streamlit (Recomendado)**
```bash
# Ative o ambiente virtual (se não estiver ativo)
.venv\Scripts\activate  # Windows
# ou
source .venv/bin/activate  # macOS/Linux

# Execute a aplicação
streamlit run app.py
```

A aplicação abrirá automaticamente no navegador em `http://localhost:8501`

### **Método 2: Docker (Alternativo)**
```bash
# Build da imagem
docker build -t priviq .

# Execute o container
docker run -p 8501:8501 --env-file .env priviq
```

## 📋 **Configuração Azure - Passo a Passo**

### **1. Azure Log Analytics Workspace**
```bash
# Criar workspace via Azure CLI
az monitor log-analytics workspace create \
  --resource-group rg-priviq \
  --workspace-name ws-priviq-logs \
  --location eastus
```

### **2. Azure OpenAI Service**
```bash
# Criar serviço OpenAI
az cognitiveservices account create \
  --name priviq-openai \
  --resource-group rg-priviq \
  --kind OpenAI \
  --sku S0 \
  --location eastus
```

### **3. Configurar Service Principal**
```bash
# Criar service principal
az ad sp create-for-rbac --name "priviq-sp" \
  --role "Log Analytics Reader" \
  --scopes /subscriptions/{subscription-id}
```

### **4. Habilitar Logs do Entra ID**
1. Acesse **Azure Portal** → **Azure Active Directory**
2. Vá em **Monitoring** → **Diagnostic settings**
3. Clique **Add diagnostic setting**
4. Selecione todas as categorias de log
5. Configure destino para **Log Analytics workspace**

## 🎮 **Como Usar**

### **1. Tela Principal**
- Faça upload de arquivos de log JSON/CSV
- Ou conecte diretamente ao Azure Log Analytics
- Escolha o período de análise

### **2. Dashboard Executivo**
- Visualize métricas principais de governança
- Score de compliance em tempo real
- Gráficos de tendências e riscos

### **3. Análise Detalhada**
- Explore violações específicas por categoria
- Veja recomendações detalhadas da IA
- Exporte relatórios para auditoria

### **4. Configurações Avançadas**
- Ajuste parâmetros de sensibilidade
- Configure alertas personalizados
- Defina frameworks de compliance específicos

## 📊 **Tipos de Análise Disponíveis**

### **🎯 Análise Padrão**
- Processamento básico de logs
- Detecção de padrões conhecidos
- Relatórios de compliance standard

### **🔬 Análise Avançada (com IA)**
- Análise semântica profunda
- Detecção de anomalias comportamentais
- Insights preditivos e recomendações personalizadas

### **👔 Dashboard Executivo**
- Métricas consolidadas para C-Level
- KPIs de governança e compliance
- Resumo executivo de riscos

## 🔧 **Solução de Problemas**

### **Erro: "Módulos não encontrados"**
```bash
# Reinstale as dependências
pip install -r requirements.txt --force-reinstall
```

### **Erro: "Não foi possível conectar ao Azure"**
1. Verifique as credenciais no arquivo `.env`
2. Confirme que o Service Principal tem permissões
3. Teste conectividade: `az login`

### **Erro: "OpenAI API Key inválida"**
1. Verifique se a chave está correta no `.env`
2. Confirme que o deployment existe no Azure OpenAI
3. Verifique cotas e limites da API

### **Performance lenta**
1. Reduza o período de análise
2. Use filtros para focar em usuários específicos
3. Configure cache local para dados frequentes

## 🔒 **Segurança e Privacidade**

- **Dados Locais**: Todos os dados são processados localmente
- **Criptografia**: Comunicação segura com APIs Azure (HTTPS/TLS)
- **Credenciais**: Armazenamento seguro em variáveis de ambiente
- **Logs**: Não armazenamos dados sensíveis em logs da aplicação
- **Compliance**: Ferramenta desenvolvida seguindo práticas de GDPR e SOX

## 📞 **Suporte e Contribuição**

### **Reportar Problemas**
- Abra uma issue no GitHub com detalhes do erro
- Inclua logs relevantes (sem dados sensíveis)
- Descreva passos para reproduzir o problema

### **Contribuir**
1. Faça fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

## 📄 **Licença**

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🏷️ **Versão**

**v2.0** - Versão com análises avançadas de IA e múltiplos frameworks de compliance

---

**Desenvolvido com ❤️ para melhorar a governança e segurança em ambientes Azure**
