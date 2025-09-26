# visualization_generator.py

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from plotly.subplots import make_subplots
import numpy as np
from typing import Dict, Any, List, Optional
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json

from models import (AIAnalysisResult, Finding, EnhancedAIAnalysisResult, 
                   DetailedFinding, GovernanceViolationType, RiskLevel, ComplianceFramework)

class SecurityVisualizationGenerator:
    """Gera visualizações interativas especializadas em governança e Conformidade."""
    
    def __init__(self):
        self.color_scheme = {
            "Critical": "#7C0000",  # Vermelho escuro
            "High": "#FF4234",      # Crimson
            "Medium": "#D3940C",    # Orange
            "Low": "#228B22",       # Forest Green
            "Info": "#4682B4"       # Steel Blue
        }
        
        self.governance_colors = {
            "Violação_SOD": "#7C0000",
            "Atribuição_Direta": "#1E3CE4",
            "Privilégios_Excessivos": "#E6760E",
            "Grupos_Duplicados": "#DFB912",
            "Acesso_Suspeito": "#DC1482",
            "Contas_Órfãs": "#9932CC",
            "Escalação_de_Privilégios": "#2290B2",
            "Violação_de_Conformidade": "#4C6409"
        }
        
        self.compliance_colors = {
            "SOX": "#7C0000",
            "NIST": "#E6760E", 
            "ISO27001": "#DFB912",
            "GDPR": "#1A659E",
            "HIPAA": "#4C6409",
            "PCI_DSS": "#9932CC"
        }

    def _create_empty_fig(self, title: str, subtitle: str = "") -> go.Figure:
        """Cria uma figura vazia com mensagem informativa."""
        fig = go.Figure()
        fig.add_annotation(
            text="📊 Dados insuficientes para gerar a visualização",
            xref="paper", yref="paper", x=0.5, y=0.6, showarrow=False,
            font=dict(size=18, color="#666666")
        )
        if subtitle:
            fig.add_annotation(
                text=subtitle,
                xref="paper", yref="paper", x=0.5, y=0.4, showarrow=False,
                font=dict(size=14, color="#999999")
            )
        fig.update_layout(
            title_text=title,
            xaxis_visible=False,
            yaxis_visible=False,
            plot_bgcolor='white'
        )
        return fig

    def create_enhanced_risk_gauge_chart(self, analysis_result: EnhancedAIAnalysisResult) -> go.Figure:
        """Cria medidor de risco aprimorado com métricas de governança."""
        score = analysis_result.risk_assessment.score
        governance_metrics = analysis_result.risk_assessment.governance_metrics
        
        # Define cor baseada no score
        if score >= 80:
            bar_color = "#7C0000"
            risk_text = "CRÍTICO"
        elif score >= 60:
            bar_color = "#FF4500"  
            risk_text = "ALTO"
        elif score >= 40:
            bar_color = "#D3940C"
            risk_text = "MÉDIO"
        else:
            bar_color = "#228B22"
            risk_text = "BAIXO"
        
        # Cria subplot com gauge e métricas
        fig = make_subplots(
            rows=2, cols=2,
            specs=[[{"type": "indicator", "colspan": 2}, None],
                   [{"type": "bar"}, {"type": "bar"}]],
            subplot_titles=["Score de Risco de Governança", 
                           "Métricas de Violações", "Distribuição por Tipo"],
            vertical_spacing=0.3
        )
        
        # Gauge principal
        fig.add_trace(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            delta={'reference': 50, 'position': "top"},
            title={
                'text': f"<span style='font-size:16px'>Nível: {risk_text}</span><br>" +
                       f"<span style='font-size:12px'>Compliance: {governance_metrics.get('compliance_score', 0):.1f}%</span>",
                'font': {'size': 14}
            },
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                'bar': {'color': bar_color, 'thickness': 0.7},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 25], 'color': "#7C0000"},
                    {'range': [25, 50], 'color': "#FF4234"},
                    {'range': [50, 75], 'color': "#D3940C"},
                    {'range': [75, 100], 'color': "#228B22"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 80
                }
            }
        ), row=1, col=1)
        
        # Métricas de violações
        violation_metrics = [
            ("Violações de SOD", governance_metrics.get('sod_violations', 0)),
            ("Atribuição Direta", governance_metrics.get('direct_assignments', 0)),
            ("Privilégios excessivos", governance_metrics.get('excessive_privilege_users', 0)),
            ("Atividades Suspeitas", governance_metrics.get('suspicious_activities', 0))
        ]
        
        fig.add_trace(go.Bar(
            x=[m[1] for m in violation_metrics],
            y=[m[0] for m in violation_metrics],
            orientation='h',
            marker_color=['#7C0000', '#FF4234', '#D3940C', '#228B22'],
            text=[f"{m[1]}" for m in violation_metrics],
            textposition='outside'
        ), row=2, col=1)
        
        # Distribuição por tipo (se há findings)
        if analysis_result.findings:
            violation_types = [f.violation_type.value.replace('_', ' ') for f in analysis_result.findings]
            type_counts = Counter(violation_types)
            
            fig.add_trace(go.Bar(
                x=list(type_counts.keys()),
                y=list(type_counts.values()),
                marker_color=[self.governance_colors.get(k.replace(' ', '_'), '#4682B4') for k in type_counts.keys()],
                text=list(type_counts.values()),
                textposition='outside'
            ), row=2, col=2)
        
        fig.update_layout(
            height=600,
            showlegend=False,
            title_text=f"Dashboard de Governança - Análise Executiva"
        )
        
        return fig

    def create_risk_gauge_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Mantém compatibilidade com modelo original."""
        score = analysis_result.risk_assessment.score
        
        if score >= 80:
            bar_color = "#7C0000"
            risk_text = "CRÍTICO"
        elif score >= 60:
            bar_color = "#FF4500"  
            risk_text = "ALTO"
        elif score >= 40:
            bar_color = "#D3940C"
            risk_text = "MÉDIO"
        else:
            bar_color = "#228B22"
            risk_text = "BAIXO"
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            delta={'reference': 50, 'position': "top"},
            title={
                'text': f"Pontuação de Criticidade de Governança<br><span style='font-size:14px'>Nível: {risk_text}</span>",
                'font': {'size': 16}
            },
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                'bar': {'color': bar_color},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 25], 'color': "#7C0000"},
                    {'range': [25, 50], 'color': "#FF4234"},
                    {'range': [50, 75], 'color': "#D3940C"},
                    {'range': [75, 100], 'color': "#228B22"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 80
                }
            }
        ))
        
        fig.update_layout(height=400)
        return fig

    def create_governance_violations_chart(self, findings: List[DetailedFinding]) -> go.Figure:
        """Cria gráfico detalhado de violações de governança."""
        if not findings:
            return self._create_empty_fig(
                "Violações de Governança por Tipo", 
                "Nenhuma violação detectada nos logs analisados"
            )
        
        # Agrupa por tipo de violação e nível de risco
        violation_data = []
        for finding in findings:
            violation_data.append({
                'type': finding.violation_type.value.replace('_', ' '),
                'risk_level': finding.risk_level.value,
                'count': 1,
                'affected_count': len(finding.affected_principals)
            })
        
        df = pd.DataFrame(violation_data)
        
        # Cria subplot com múltiplas visualizações
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=[
                "Violações por Tipo e Severidade",
                "Principais Afetados",
                "Tendência por Framework de Compliance",
                "Prioridade de Remediação"
            ],
            specs=[[{"type": "bar"}, {"type": "pie"}],
                   [{"type": "bar"}, {"type": "scatter"}]]
        )
        
        # 1. Violações por tipo e severidade
        for risk_level in ['Critical', 'High', 'Medium', 'Low']:
            level_data = df[df['risk_level'] == risk_level]
            if not level_data.empty:
                type_counts = level_data.groupby('type')['count'].sum()
                fig.add_trace(go.Bar(
                    name=risk_level,
                    x=type_counts.index,
                    y=type_counts.values,
                    marker_color=self.color_scheme[risk_level]
                ), row=1, col=1)
        
        # 2. Principais tipos afetados (pie chart)
        type_totals = df.groupby('type')['affected_count'].sum()
        fig.add_trace(go.Pie(
            labels=type_totals.index,
            values=type_totals.values,
            hole=0.4,
            marker_colors=[self.governance_colors.get(t.replace(' ', '_'), '#4682B4') for t in type_totals.index]
        ), row=1, col=2)
        
        # 3. Compliance frameworks afetados
        compliance_impact = defaultdict(int)
        for finding in findings:
            for framework in finding.compliance_impact:
                compliance_impact[framework.value] += 1
        
        if compliance_impact:
            fig.add_trace(go.Bar(
                x=list(compliance_impact.keys()),
                y=list(compliance_impact.values()),
                marker_color=[self.compliance_colors.get(f, '#4682B4') for f in compliance_impact.keys()],
                text=list(compliance_impact.values()),
                textposition='outside'
            ), row=2, col=1)
        
        # 4. Prioridade vs Impacto
        priorities = [f.remediation_priority for f in findings]
        risk_scores = [100 if f.risk_level == RiskLevel.CRITICAL else 
                      75 if f.risk_level == RiskLevel.HIGH else 
                      50 if f.risk_level == RiskLevel.MEDIUM else 25 for f in findings]
        
        fig.add_trace(go.Scatter(
            x=priorities,
            y=risk_scores,
            mode='markers',
            marker=dict(
                size=[len(f.affected_principals) * 3 + 8 for f in findings],
                color=risk_scores,
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Risk Score")
            ),
            text=[f.title[:50] + '...' for f in findings],
            hovertemplate='<b>%{text}</b><br>Priority: %{x}<br>Risk Score: %{y}<extra></extra>'
        ), row=2, col=2)
        
        fig.update_layout(
            height=800,
            title_text="Análise Detalhada de Violações de Governança",
            showlegend=True
        )
        
        return fig

    def create_compliance_framework_chart(self, findings: List[DetailedFinding]) -> go.Figure:
        """Cria visualização específica para frameworks de compliance."""
        if not findings:
            return self._create_empty_fig(
                "Impacto por Framework de Compliance",
                "Nenhum impacto em frameworks de compliance detectado"
            )
        
        # Análise por framework
        framework_analysis = defaultdict(lambda: {'violations': 0, 'critical': 0, 'high': 0, 'affected_users': set()})
        
        for finding in findings:
            for framework in finding.compliance_impact:
                framework_analysis[framework.value]['violations'] += 1
                if finding.risk_level == RiskLevel.CRITICAL:
                    framework_analysis[framework.value]['critical'] += 1
                elif finding.risk_level == RiskLevel.HIGH:
                    framework_analysis[framework.value]['high'] += 1
                framework_analysis[framework.value]['affected_users'].update(finding.affected_principals)
        
        if not framework_analysis:
            return self._create_empty_fig(
                "Impacto por Framework de Compliance",
                "Nenhum framework de compliance especificamente afetado"
            )
        
        # Cria subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=[
                "Violações Totais por Framework",
                "Severidade das Violações", 
                "Usuários Afetados por Framework",
                "Pontuação de Conformidade"
            ],
            specs=[[{"type": "bar"}, {"type": "bar"}],
                   [{"type": "bar"}, {"type": "indicator"}]]
        )
        
        frameworks = list(framework_analysis.keys())
        total_violations = [framework_analysis[f]['violations'] for f in frameworks]
        critical_violations = [framework_analysis[f]['critical'] for f in frameworks]
        high_violations = [framework_analysis[f]['high'] for f in frameworks]
        affected_users = [len(framework_analysis[f]['affected_users']) for f in frameworks]
        
        # 1. Violações totais
        fig.add_trace(go.Bar(
            x=frameworks,
            y=total_violations,
            marker_color=[self.compliance_colors.get(f, '#4682B4') for f in frameworks],
            text=total_violations,
            textposition='outside',
            name="Total"
        ), row=1, col=1)
        
        # 2. Severidade
        fig.add_trace(go.Bar(
            x=frameworks,
            y=critical_violations,
            name="Critical",
            marker_color="#7C0000"
        ), row=1, col=2)
        
        fig.add_trace(go.Bar(
            x=frameworks,
            y=high_violations,
            name="High", 
            marker_color="#FF4234"
        ), row=1, col=2)
        
        # 3. Usuários afetados
        fig.add_trace(go.Bar(
            x=frameworks,
            y=affected_users,
            marker_color=[self.compliance_colors.get(f, '#4682B4') for f in frameworks],
            text=affected_users,
            textposition='outside'
        ), row=2, col=1)
        
        # 4. Score de compliance geral
        overall_score = max(0, 100 - sum(total_violations) * 10)
        fig.add_trace(go.Indicator(
            mode="gauge+number",
            value=overall_score,
            title={'text': "Pontuação Geral<br>de Conformidade"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "#228B22" if overall_score > 80 else "#F3E462" if overall_score > 50 else "#7C0000"},
                'steps': [
                    {'range': [0, 50], 'color': "#7C0000"},
                    {'range': [50, 80], 'color': "#D3940C"},
                    {'range': [80, 100], 'color': "#228B22"}
                ]
            }
        ), row=2, col=2)
        
        fig.update_layout(
            height=700,
            title_text="Análise de Impacto em Frameworks de Conformidade",
            showlegend=True
        )
        
        return fig

    def create_user_risk_heatmap(self, findings: List[DetailedFinding]) -> go.Figure:
        """Cria heatmap de risco por usuário."""
        if not findings:
            return self._create_empty_fig(
                "Mapa de Calor - Risco por Usuário",
                "Nenhum usuário específico identificado nos achados"
            )
        
        # Coleta dados de usuários e riscos
        user_risks = defaultdict(lambda: {'violations': [], 'total_risk': 0, 'frameworks': set()})
        
        for finding in findings:
            for user in finding.affected_principals[:50]:  # Limita para performance
                risk_value = 4 if finding.risk_level == RiskLevel.CRITICAL else \
                           3 if finding.risk_level == RiskLevel.HIGH else \
                           2 if finding.risk_level == RiskLevel.MEDIUM else 1
                
                user_risks[user]['violations'].append(finding.violation_type.value)
                user_risks[user]['total_risk'] += risk_value
                user_risks[user]['frameworks'].update([f.value for f in finding.compliance_impact])
        
        if not user_risks:
            return self._create_empty_fig(
                "Mapa de Calor - Risco por Usuário",
                "Nenhum usuário específico para análise de risco"
            )
        
        # Prepara dados para heatmap
        users = list(user_risks.keys())[:20]  # Top 20 usuários
        violation_types = list(GovernanceViolationType)
        
        # Cria matriz de riscos
        risk_matrix = []
        for user in users:
            user_row = []
            for vtype in violation_types:
                count = user_risks[user]['violations'].count(vtype.value)
                user_row.append(count)
            risk_matrix.append(user_row)
        
        # Cria heatmap
        fig = go.Figure(data=go.Heatmap(
            z=risk_matrix,
            x=[vtype.value.replace('_', ' ') for vtype in violation_types],
            y=[user.split('@')[0] if '@' in user else user[:20] for user in users],
            colorscale='Reds',
            showscale=True,
            hoverongaps=False,
            hovertemplate='<b>%{y}</b><br>%{x}: %{z} violações<extra></extra>'
        ))
        
        fig.update_layout(
            title="Mapa de Calor: Violações por Usuário e Tipo",
            xaxis_title="Tipo de Violação",
            yaxis_title="Usuários (Top 20 por Risco)",
            height=600
        )
        
        return fig

    def create_timeline_analysis(self, findings: List[DetailedFinding]) -> go.Figure:
        """Cria análise temporal dos achados."""
        if not findings:
            return self._create_empty_fig(
                "Timeline de Violações Detectadas",
                "Nenhum timestamp disponível para análise temporal"
            )
        
        # Filtra findings com timestamp
        timestamped_findings = [f for f in findings if f.detection_timestamp]
        
        if not timestamped_findings:
            return self._create_empty_fig(
                "Timeline de Violações Detectadas", 
                "Nenhum timestamp de detecção disponível"
            )
        
        # Prepara dados temporais
        timeline_data = []
        for finding in timestamped_findings:
            try:
                timestamp = datetime.fromisoformat(finding.detection_timestamp.replace('Z', '+00:00'))
                timeline_data.append({
                    'timestamp': timestamp,
                    'type': finding.violation_type.value,
                    'risk_level': finding.risk_level.value,
                    'title': finding.title,
                    'affected_count': len(finding.affected_principals)
                })
            except:
                continue
        
        if not timeline_data:
            return self._create_empty_fig(
                "Timeline de Violações Detectadas",
                "Erro ao processar timestamps dos achados"
            )
        
        df = pd.DataFrame(timeline_data)
        df = df.sort_values('timestamp')
        
        # Cria gráfico temporal
        fig = go.Figure()
        
        colors = {'Critical': '#7C0000', 'High': '#FF4234', 'Medium': '#D3940C', 'Low': '#228B22'}
        
        for risk_level in df['risk_level'].unique():
            level_data = df[df['risk_level'] == risk_level]
            
            fig.add_trace(go.Scatter(
                x=level_data['timestamp'],
                y=level_data['affected_count'],
                mode='markers+lines',
                name=f'{risk_level} Risk',
                marker=dict(
                    color=colors.get(risk_level, '#4682B4'),
                    size=10,
                    symbol='circle'
                ),
                text=level_data['title'],
                hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Affected: %{y}<extra></extra>'
            ))
        
        fig.update_layout(
            title="Timeline de Detecção de Violações",
            xaxis_title="Timestamp de Detecção",
            yaxis_title="Número de Usuários/Recursos Afetados",
            height=500,
            hovermode='closest'
        )
        
        return fig

    def create_executive_dashboard(self, analysis_result: EnhancedAIAnalysisResult) -> go.Figure:
        """Cria dashboard executivo com métricas principais."""
        
        # KPIs principais
        total_findings = len(analysis_result.findings)
        critical_findings = len([f for f in analysis_result.findings if f.risk_level == RiskLevel.CRITICAL])
        high_findings = len([f for f in analysis_result.findings if f.risk_level == RiskLevel.HIGH])
        
        governance_metrics = analysis_result.risk_assessment.governance_metrics
        compliance_score = governance_metrics.get('compliance_score', 0)
        
        # Cria dashboard com subplots
        fig = make_subplots(
            rows=3, cols=3,
            subplot_titles=[
                "Pontuação de Risco", "Pontuação de Conformidade", "Total de Conclusões",
                "Questões Críticas", "Violações de SOD", "Atribuições Diretas",
                "Conclusões por Nível de Risco", "Tipos de Violação", "Próximas Ações"
            ],
            specs=[[{"type": "indicator"}, {"type": "indicator"}, {"type": "indicator"}],
                   [{"type": "indicator"}, {"type": "indicator"}, {"type": "indicator"}],
                   [{"type": "pie"}, {"type": "bar"}, {"type": "table"}]]
        )
        
        # Row 1: Main KPIs
        fig.add_trace(go.Indicator(
            mode="gauge+number",
            value=analysis_result.risk_assessment.score,
            gauge={'axis': {'range': [0, 100]}, 
                   'bar': {'color': "#7C0000" if analysis_result.risk_assessment.score >= 80 else "#D3940C"},
                   'steps': [{'range': [0, 50], 'color': "lightgray"}, {'range': [50, 100], 'color': "gray"}]},
            title={'text': "Risk Score"}
        ), row=1, col=1)
        
        fig.add_trace(go.Indicator(
            mode="gauge+number",
            value=compliance_score,
            gauge={'axis': {'range': [0, 100]}, 
                   'bar': {'color': "#228B22" if compliance_score >= 80 else "#D3940C"},
                   'steps': [{'range': [0, 50], 'color': "lightgray"}, {'range': [50, 100], 'color': "gray"}]},
            title={'text': "Compliance Score"}
        ), row=1, col=2)
        
        fig.add_trace(go.Indicator(
            mode="number+delta",
            value=total_findings,
            delta={'reference': 10, 'position': "top", 'valueformat': '.0f'},
            title={'text': "Total Findings"}
        ), row=1, col=3)
        
        # Row 2: Specific metrics
        fig.add_trace(go.Indicator(
            mode="number",
            value=critical_findings,
            title={'text': "Critical Issues"},
            number={'font': {'color': "#7C0000"}}
        ), row=2, col=1)
        
        fig.add_trace(go.Indicator(
            mode="number",
            value=governance_metrics.get('sod_violations', 0),
            title={'text': "SOD Violations"},
            number={'font': {'color': "#DC143C"}}
        ), row=2, col=2)
        
        fig.add_trace(go.Indicator(
            mode="number",
            value=governance_metrics.get('direct_assignments', 0),
            title={'text': "Atribuição Direta"},
            number={'font': {'color': "#D3940C"}}
        ), row=2, col=3)
        
        # Row 3: Details
        # Risk level distribution
        risk_counts = Counter([f.risk_level.value for f in analysis_result.findings])
        if risk_counts:
            fig.add_trace(go.Pie(
                labels=list(risk_counts.keys()),
                values=list(risk_counts.values()),
                hole=0.4,
                marker_colors=[self.color_scheme.get(k, '#4682B4') for k in risk_counts.keys()]
            ), row=3, col=1)
        
        # Violation types
        violation_counts = Counter([f.violation_type.value.replace('_', ' ') for f in analysis_result.findings])
        if violation_counts:
            fig.add_trace(go.Bar(
                x=list(violation_counts.values()),
                y=list(violation_counts.keys()),
                orientation='h',
                marker_color=[self.governance_colors.get(k.replace(' ', '_'), '#4682B4') for k in violation_counts.keys()]
            ), row=3, col=2)
        
        # Next actions table
        next_actions = analysis_result.next_actions[:5] if analysis_result.next_actions else ["No specific actions recommended"]
        fig.add_trace(go.Table(
            header=dict(values=["Priority Actions"], fill_color='lightblue'),
            cells=dict(values=[next_actions], fill_color='white', align='left')
        ), row=3, col=3)
        
        fig.update_layout(
            height=900,
            title_text="Executive Dashboard - Governança Azure",
            showlegend=False
        )
        
        return fig
        return fig

    def create_findings_by_type_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria gráfico de achados por tipo com contexto de governança."""
        if not analysis_result.findings:
            return self._create_empty_fig("Achados por Tipo de Problema")
        
        df = pd.DataFrame([finding.model_dump() for finding in analysis_result.findings])
        finding_counts = df['title'].value_counts()
        
        # Identifica tipos de problemas de governança e atribui cores
        colors = []
        for i, title in enumerate(finding_counts.index):
            # Tenta usar o violation_type se disponível
            violation_type = None
            if hasattr(analysis_result.findings[0], 'violation_type'):
                # Busca o finding correspondente
                for finding in analysis_result.findings:
                    if finding.title == title:
                        violation_type = getattr(finding, 'violation_type', None)
                        break
            
            if violation_type and violation_type in self.governance_colors:
                colors.append(self.governance_colors[violation_type])
            else:
                # Fallback para análise por título
                title_lower = title.lower()
                if 'sod' in title_lower or 'segreg' in title_lower:
                    colors.append(self.governance_colors.get('Violação de SOD', '#F50B0B'))
                elif 'direct' in title_lower or 'atribui' in title_lower:
                    colors.append(self.governance_colors.get('Atribuição Direta', '#FF4500'))
                elif 'excess' in title_lower or 'privileg' in title_lower:
                    colors.append(self.governance_colors.get('Privilégios Excessivos', '#FF8C00'))
                elif 'duplic' in title_lower or 'grupo' in title_lower:
                    colors.append(self.governance_colors.get('Grupos Duplicados', '#7C0000'))
                else:
                    colors.append(self.governance_colors.get('Accessos Suspeitos', "#A63AE4"))
        
        fig = go.Figure([
            go.Bar(
                x=finding_counts.values,
                y=finding_counts.index,
                orientation='h',
                marker=dict(
                    color=colors,
                    line=dict(color='rgba(58, 71, 80, 1.0)', width=1)
                ),
                text=finding_counts.values,
                textposition='outside',
                hovertemplate='<b>%{y}</b><br>Quantidade: %{x}<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title={
                'text': "📋 Top Problemas de Governança Identificados<br><sub>Por Tipo de Achado</sub>",
                'x': 0.5,
                'font': {'size': 16}
            },
            xaxis_title="Quantidade de Ocorrências",
            yaxis_title="Tipo de Problema",
            yaxis={'categoryorder': 'total ascending'},
            height=max(400, len(finding_counts) * 40),
            margin=dict(l=200)  # Margem esquerda maior para títulos longos
        )
        
        return fig

    def create_compliance_matrix(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria matriz de compliance mostrando áreas de risco."""
        if not analysis_result.findings:
            return self._create_empty_fig("Matriz de Compliance")
        
        # Define categorias de compliance
        compliance_areas = [
            "Segregação de Funções",
            "Gerenciamento de Funções",
            "Controle de Acesso",
            "Gerenciamento de Privilégios",
            "Monitoramento"
        ]
        
        # Define controles por área
        controls = [
            "SOD-001: Funções Conflitantes",
            "RM-001: Atribuições Diretas",
            "AC-001: Acesso Excessivo",
            "PM-001: Escalonamento de Privilégios",
            "AM-001: Atividade Suspeita"
        ]
        
        # Simula scores baseados nos achados
        df = pd.DataFrame([f.model_dump() for f in analysis_result.findings])
        
        # Calcula scores por área
        area_scores = []
        for area in compliance_areas:
            area_findings = df[df['title'].str.contains('|'.join([
                'SOD', 'Direct', 'Excess', 'Privilege', 'Suspicious'
            ]), case=False, na=False)]
            
            if len(area_findings) > 0:
                critical_count = len(area_findings[area_findings['risk_level'] == 'Critical'])
                high_count = len(area_findings[area_findings['risk_level'] == 'High']) 
                score = max(0, 100 - (critical_count * 25 + high_count * 15))
            else:
                score = 100
            area_scores.append(score)
        
        # Cria heatmap
        fig = go.Figure(data=go.Heatmap(
            z=[area_scores],
            x=compliance_areas,
            y=['Compliance Score'],
            colorscale=[[0, '#7C0000'], [0.5, '#D3940C'], [1, '#228B22']],
            text=[[f"{score}%" for score in area_scores]],
            texttemplate="%{text}",
            textfont={"size": 14},
            colorbar=dict(title="Pontuação %")
        ))
        
        fig.update_layout(
            title={
                'text': "🎯 Matriz de Conformidade por Área<br><sub>Pontuação de Conformidade (%)</sub>",
                'x': 0.5
            },
            height=300,
            xaxis_title="Áreas de Conformidade",
            yaxis_title=""
        )
        
        return fig

    def create_affected_principals_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria gráfico dos principais mais afetados."""
        if not analysis_result.findings:
            return self._create_empty_fig("Principais Afetados")
        
        # Conta quantas vezes cada principal aparece
        all_principals = []
        principal_risks = {}
        
        for finding in analysis_result.findings:
            for principal in finding.affected_principals:
                all_principals.append(principal)
                if principal not in principal_risks:
                    principal_risks[principal] = []
                principal_risks[principal].append(finding.risk_level.value)
        
        if not all_principals:
            return self._create_empty_fig("Principais Afetados", "Nenhum principal específico identificado")
        
        # Conta ocorrências
        principal_counts = pd.Series(all_principals).value_counts().head(10)
        
        # Calcula score de risco médio por principal
        risk_scores = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        avg_risk_scores = []
        
        for principal in principal_counts.index:
            risks = principal_risks[principal]
            avg_score = np.mean([risk_scores[risk] for risk in risks])
            avg_risk_scores.append(avg_score)
        
        # Define cores baseadas no risco médio
        colors = []
        for score in avg_risk_scores:
            if score >= 3.5:
                colors.append("#7C0000")
            elif score >= 2.5:
                colors.append('#FF4500')
            elif score >= 1.5:
                colors.append('#D3940C')
            else:
                colors.append('#228B22')
        
        fig = go.Figure([
            go.Bar(
                x=principal_counts.index,
                y=principal_counts.values,
                marker=dict(color=colors),
                text=principal_counts.values,
                textposition='outside'
            )
        ])
        
        fig.update_layout(
            title={
                'text': "👥 Top 10 Principais Mais Afetados<br><sub>Por Quantidade de Problemas</sub>",
                'x': 0.5
            },
            xaxis_title="Usuários/Grupos/SPNs",
            yaxis_title="Número de Problemas",
            xaxis_tickangle=-45,
            height=500
        )
        
        return fig

    def create_timeline_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria linha do tempo de descoberta de problemas."""
        # Como não temos timestamps reais, simulamos baseado na criticidade
        if not analysis_result.findings:
            return self._create_empty_fig("Timeline de Descobertas")
        
        # Simula timestamps baseados na ordem e criticidade
        import datetime
        base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
        
        timeline_data = []
        for i, finding in enumerate(analysis_result.findings):
            timestamp = base_time + datetime.timedelta(minutes=i*5)
            timeline_data.append({
                'time': timestamp,
                'title': finding.title,
                'risk': finding.risk_level.value,
                'affected_count': len(finding.affected_principals)
            })
        
        df = pd.DataFrame(timeline_data)
        
        fig = go.Figure()
        
        # Adiciona pontos por nível de risco
        for risk_level, color in self.color_scheme.items():
            risk_data = df[df['risk'] == risk_level]
            if not risk_data.empty:
                fig.add_trace(go.Scatter(
                    x=risk_data['time'],
                    y=risk_data['affected_count'],
                    mode='markers+text',
                    marker=dict(
                        size=15,
                        color=color,
                        symbol='diamond' if risk_level == 'Critical' else 'circle'
                    ),
                    text=risk_data['title'],
                    textposition="top center",
                    name=f"{risk_level} Risk",
                    hovertemplate='<b>%{text}</b><br>Horário: %{x}<br>Afetados: %{y}<extra></extra>'
                ))
        
        fig.update_layout(
            title={
                'text': "⏱️ Timeline de Descoberta de Problemas<br><sub>Cronologia dos Achados</sub>",
                'x': 0.5
            },
            xaxis_title="Horário de Descoberta",
            yaxis_title="Número de Principais Afetados",
            height=400,
            hovermode='closest'
        )
        
        return fig

    def create_governance_dashboard(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria um dashboard executivo de governança."""
        if not analysis_result.findings:
            return self._create_empty_fig(
                "Dashboard de Governança", 
                "Nenhum problema de governança identificado"
            )

        # Cria subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=(
                'Distribuição de Riscos', 'Pontuação de Conformidade',
                'Problemas por Categoria', 'Timeline de Criticidade'
            ),
            specs=[[{"type": "pie"}, {"type": "indicator"}],
                   [{"type": "bar"}, {"type": "scatter"}]]
        )

        df = pd.DataFrame([finding.model_dump() for finding in analysis_result.findings])
        
        # 1. Gráfico de Pizza - Distribuição de Riscos
        risk_counts = df['risk_level'].value_counts()
        fig.add_trace(
            go.Pie(
                labels=risk_counts.index,
                values=risk_counts.values,
                marker_colors=[self.color_scheme[level] for level in risk_counts.index],
                name="Riscos"
            ),
            row=1, col=1
        )

        # 2. Gauge - Score de Compliance
        compliance_score = max(0, 100 - analysis_result.risk_assessment.score)
        fig.add_trace(
            go.Indicator(
                mode="gauge+number",
                value=compliance_score,
                title={'text': "Compliance %"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#1f77b4"},
                    'steps': [
                        {'range': [0, 50], 'color': "lightcoral"},
                        {'range': [50, 80], 'color': "lightyellow"},
                        {'range': [80, 100], 'color': "lightgreen"}
                    ]
                }
            ),
            row=1, col=2
        )

        # 3. Barra - Problemas por Categoria
        categories = df['title'].value_counts()
        fig.add_trace(
            go.Bar(
                x=categories.values,
                y=categories.index,
                orientation='h',
                marker_color='#FF6B6B',
                name="Problemas"
            ),
            row=2, col=1
        )

        # 4. Scatter - Criticidade vs Quantidade de Afetados
        affected_count = [len(f.affected_principals) for f in analysis_result.findings]
        risk_scores = [
            {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}[f.risk_level.value]
            for f in analysis_result.findings
        ]
        
        fig.add_trace(
            go.Scatter(
                x=affected_count,
                y=risk_scores,
                mode='markers',
                marker=dict(
                    size=[max(10, count*2) for count in affected_count],
                    color=[self.color_scheme[f.risk_level.value] for f in analysis_result.findings],
                    opacity=0.7
                ),
                text=[f.title for f in analysis_result.findings],
                name="Impacto"
            ),
            row=2, col=2
        )

        fig.update_layout(
            height=800,
            title_text="🛡️ Dashboard Executivo de Governança Azure",
            title_x=0.5,
            showlegend=False
        )
        
        return fig

    def create_risk_distribution_chart(self, analysis_result: AIAnalysisResult) -> go.Figure:
        """Cria gráfico de distribuição de riscos com detalhes melhorados."""
        if not analysis_result.findings:
            return self._create_empty_fig("Distribuição de Riscos por Nível")
        
        df = pd.DataFrame([finding.model_dump() for finding in analysis_result.findings])
        risk_counts = df['risk_level'].value_counts()
        
        # Calcula percentuais
        total = risk_counts.sum()
        percentages = (risk_counts / total * 100).round(1)
        
        # Cria labels com contagem e percentual
        labels = [f"{level}<br>{count} itens ({percentages[level]}%)" 
                 for level, count in risk_counts.items()]
        
        fig = go.Figure(data=[
            go.Pie(
                labels=labels,
                values=risk_counts.values,
                hole=0.4,
                marker_colors=[self.color_scheme[level] for level in risk_counts.index],
                textinfo='label+percent',
                textposition='outside',
                pull=[0.1 if level == 'Critical' else 0.05 for level in risk_counts.index]
            )
        ])
        
        fig.update_layout(
            title={
                'text': "🎯 Distribuição de Riscos de Governança<br><sub>Por Nível de Criticidade</sub>",
                'x': 0.5,
                'font': {'size': 16}
            },
            annotations=[dict(text=f'Total<br><b>{total}</b><br>Achados', 
                            x=0.5, y=0.5, font_size=14, showarrow=False)],
            height=500
        )
        
        return fig