# 📦 GUIA DE INSTALAÇÃO - PrivIQ

## 🚀 Dependências Necessárias para Executar o PrivIQ

### ⚡ INSTALAÇÃO RÁPIDA

Execute este comando para instalar todas as dependências essenciais:

```bash
pip install streamlit pandas numpy plotly azure-identity azure-monitor-query azure-storage-blob azure-core openai pydantic python-dotenv
```

### 📋 INSTALAÇÃO VIA REQUIREMENTS.TXT

```bash
pip install -r requirements.txt
```

### 🔧 DEPENDÊNCIAS ESSENCIAIS

#### **Interface Web**
- `streamlit>=1.28.0` - Framework para interface web

#### **Manipulação de Dados**
- `pandas>=2.0.0` - Análise de dados
- `numpy>=1.24.0` - Computação numérica

#### **Visualização**
- `plotly>=5.15.0` - Gráficos interativos

#### **Azure SDK (CRÍTICO)**
- `azure-identity>=1.15.0` - Autenticação Azure
- `azure-monitor-query>=1.3.0` - Log Analytics
- `azure-storage-blob>=12.19.0` - Blob Storage
- `azure-core>=1.29.0` - Funcionalidades core Azure

#### **Inteligência Artificial**
- `openai>=1.12.0` - Azure OpenAI

#### **Configuração**
- `pydantic>=2.0.0` - Validação de dados
- `python-dotenv>=1.0.0` - Variáveis de ambiente

### 🐍 VERSÃO DO PYTHON

**Requerido:** Python 3.8 ou superior
**Recomendado:** Python 3.11 ou 3.12

### 💻 INSTALAÇÃO EM AMBIENTE VIRTUAL

```bash
# Criar ambiente virtual
python -m venv venv

# Ativar ambiente virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

### 🔧 VERIFICAÇÃO DA INSTALAÇÃO

Execute este comando para verificar se todas as bibliotecas foram instaladas:

```bash
python -c "
import streamlit
import pandas
import plotly
import azure.identity
import azure.monitor.query
import azure.storage.blob
import openai
import pydantic
import dotenv
print('✅ Todas as dependências instaladas com sucesso!')
"
```

### ⚠️ SOLUÇÃO DE PROBLEMAS

#### **Erro: Azure SDK não encontrado**
```bash
pip install --upgrade azure-identity azure-monitor-query azure-storage-blob
```

#### **Erro: OpenAI não encontrado**
```bash
pip install --upgrade openai
```

#### **Erro: Streamlit não encontrado**
```bash
pip install --upgrade streamlit
```

### 🚦 INICIAR A APLICAÇÃO

Após instalar todas as dependências:

```bash
streamlit run app.py
```

### 📋 BIBLIOTECAS PADRÃO (Não precisam ser instaladas)

Estas bibliotecas fazem parte do Python padrão:
- `json`, `os`, `sys`, `datetime`
- `asyncio`, `collections`, `typing`
- `abc`, `dataclasses`, `enum`
- `logging`

### 🎯 RESUMO FINAL

**COMANDO ÚNICO DE INSTALAÇÃO:**
```bash
pip install streamlit pandas numpy plotly azure-identity azure-monitor-query azure-storage-blob azure-core openai pydantic python-dotenv
```

**INICIAR APLICAÇÃO:**
```bash
streamlit run app.py
```

🎉 **Pronto! O PrivIQ estará rodando em http://localhost:8501**