# visualization_generator.py

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

# Importa nossos novos modelos de dados
from models import AIAnalysisResult, Finding

class SecurityVisualizationGenerator:
    """Gera visualizações interativas a partir dos resultados da análise de IA."""

    def __init__(self):
        self.color_scheme = {
            "Critical": "#721c24",
            "High": "#dc3545",
            "Medium": "#ffc107",
            "Low": "#28a745",
        }

    def _create_empty_fig(self, title: str) -> go.Figure:
        """Cria uma figura vazia com uma mensagem informativa."""
        fig = go.Figure()
        fig.add_annotation(
            text="Dados insuficientes para gerar o gráfico",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=16, color="grey")
        )
        fig.update_layout(title_text=title, xaxis_visible=False, yaxis_visible=False)
        return fig

    def create_risk_distribution_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria um gráfico de pizza com a distribuição de riscos."""
        if not analysis_result.findings:
            return self._create_empty_fig("Distribuição de Riscos")

        df = pd.DataFrame([finding.model_dump() for finding in analysis_result.findings])
        risk_counts = df['risk_level'].value_counts()
        
        fig = px.pie(
            names=risk_counts.index,
            values=risk_counts.values,
            title="Distribuição de Riscos por Nível",
            color=risk_counts.index,
            color_discrete_map=self.color_scheme
        )
        fig.update_traces(textinfo='percent+label', pull=[0.05] * len(risk_counts))
        return fig

    def create_risk_gauge_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria um medidor (gauge) para o score de risco geral."""
        score = analysis_result.risk_assessment.score
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            title={'text': "Score de Risco Geral"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "#31333F"},
                'steps': [
                    {'range': [0, 40], 'color': 'lightgreen'},
                    {'range': [40, 70], 'color': 'yellow'},
                    {'range': [70, 100], 'color': 'red'},
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        return fig

    def create_findings_by_type_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria um gráfico de barras mostrando os tipos de achados mais comuns."""
        if not analysis_result.findings:
            return self._create_empty_fig("Contagem de Achados por Título")

        df = pd.DataFrame([finding.model_dump() for finding in analysis_result.findings])
        finding_counts = df['title'].value_counts().nlargest(10) # Pega os 10 mais comuns
        
        fig = px.bar(
            x=finding_counts.values,
            y=finding_counts.index,
            orientation='h',
            title="Top 10 Tipos de Achados de Segurança",
            labels={'x': 'Quantidade', 'y': 'Tipo de Achado'},
            text=finding_counts.values
        )
        fig.update_layout(yaxis={'categoryorder':'total ascending'})
        return fig