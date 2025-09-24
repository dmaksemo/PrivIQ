import unittest
from datetime import datetime
from visualization_generator import SecurityVisualizationGenerator
from models import DetailedFinding, RiskLevel, GovernanceViolationType, ComplianceFramework, AIAnalysisResult, EnhancedAIAnalysisResult

class TestSecurityVisualizationGenerator(unittest.TestCase):
    def setUp(self):
        self.viz_generator = SecurityVisualizationGenerator()
        
    def create_mock_finding(self, risk_level=RiskLevel.HIGH, violation_type=GovernanceViolationType.SOD_VIOLATION):
        """Cria um finding mockado para testes."""
        return DetailedFinding(
            risk_level=risk_level,
            violation_type=violation_type,
            title="Test Finding",
            description="Test Description",
            recommendation="Test Recommendation",
            affected_principals=["user1@test.com", "user2@test.com"],
            evidence={"test": "evidence"},
            compliance_impact=[ComplianceFramework.SOX, ComplianceFramework.ISO27001],
            remediation_priority=1,
            business_impact="Test Impact",
            detection_timestamp=datetime.now().isoformat()
        )

    def create_mock_enhanced_result(self, num_findings=3):
        """Cria um resultado de análise mockado para testes."""
        findings = [self.create_mock_finding() for _ in range(num_findings)]
        return EnhancedAIAnalysisResult(
            risk_assessment={
                "score": 75,
                "summary": "Test Summary",
                "governance_metrics": {
                    "total_users": 100,
                    "direct_assignments": 5,
                    "sod_violations": 3,
                    "compliance_score": 80
                }
            },
            findings=findings,
            executive_summary="Test Executive Summary",
            technical_summary="Test Technical Summary",
            next_actions=["Action 1", "Action 2"],
            analysis_metadata={
                "total_logs_analyzed": 1000,
                "analysis_timestamp": datetime.now().isoformat(),
                "findings_count": num_findings
            }
        )

    def test_empty_data_handling(self):
        """Testa o comportamento com dados vazios."""
        result = self.create_mock_enhanced_result(num_findings=0)
        
        # Testa cada método principal
        charts = [
            self.viz_generator.create_compliance_framework_chart([]),
            self.viz_generator.create_governance_violations_chart([]),
            self.viz_generator.create_user_risk_heatmap([]),
            self.viz_generator.create_timeline_analysis([]),
            self.viz_generator.create_executive_dashboard(result)
        ]
        
        for chart in charts:
            self.assertIsNotNone(chart)
            self.assertTrue(hasattr(chart, 'layout'), "Chart should have a layout")
            self.assertTrue(hasattr(chart.layout, 'annotations'), "Chart should have annotations")
            
            # Verifica se há alguma anotação no gráfico
            self.assertTrue(len(chart.layout.annotations) > 0, "Chart should have at least one annotation")
            
            # Verifica se o gráfico está em estado vazio
            annotations_text = [ann.text.lower() for ann in chart.layout.annotations if hasattr(ann, 'text')]
            empty_indicators = ['insuficientes', 'vazio', 'no data', 'sem dados']
            has_empty_message = any(indicator in ' '.join(annotations_text) for indicator in empty_indicators)
            
            self.assertTrue(
                has_empty_message,
                f"Expected empty state message in annotations. Found: {annotations_text}"
            )

    def test_data_type_handling(self):
        """Testa o tratamento de diferentes tipos de dados."""
        finding = self.create_mock_finding()
        
        # Testa com diferentes tipos de valores em compliance_impact
        finding.compliance_impact = []  # Lista vazia
        chart = self.viz_generator.create_compliance_framework_chart([finding])
        self.assertIsNotNone(chart)
        
        finding.compliance_impact = None  # None
        chart = self.viz_generator.create_compliance_framework_chart([finding])
        self.assertIsNotNone(chart)
        
        finding.compliance_impact = [ComplianceFramework.SOX]  # Um único framework
        chart = self.viz_generator.create_compliance_framework_chart([finding])
        self.assertIsNotNone(chart)

    def test_error_handling(self):
        """Testa o tratamento de erros em cenários problemáticos."""
        finding = self.create_mock_finding()
        
        # Testa com timestamp inválido
        finding.detection_timestamp = "invalid_timestamp"
        chart = self.viz_generator.create_timeline_analysis([finding])
        self.assertIsNotNone(chart)
        
        # Testa com affected_principals None
        finding.affected_principals = None
        chart = self.viz_generator.create_user_risk_heatmap([finding])
        self.assertIsNotNone(chart)
        
        # Testa com valores extremos
        finding.affected_principals = ["user" + str(i) for i in range(1000)]
        chart = self.viz_generator.create_user_risk_heatmap([finding])
        self.assertIsNotNone(chart)

    def test_compliance_framework_chart(self):
        """Testa especificamente o gráfico de frameworks de compliance."""
        findings = [
            self.create_mock_finding(
                risk_level=RiskLevel.CRITICAL,
                violation_type=GovernanceViolationType.SOD_VIOLATION
            ),
            self.create_mock_finding(
                risk_level=RiskLevel.HIGH,
                violation_type=GovernanceViolationType.DIRECT_ASSIGNMENT
            )
        ]
        
        chart = self.viz_generator.create_compliance_framework_chart(findings)
        self.assertIsNotNone(chart)
        
        # Verifica se o gráfico tem os elementos esperados
        self.assertTrue(hasattr(chart, 'data'))
        self.assertTrue(len(chart.data) > 0)
        
        # Verifica configuração do layout
        self.assertIn('title', chart.layout)
        self.assertIn('xaxis', chart.layout)
        self.assertIn('yaxis', chart.layout)

    def test_data_consistency(self):
        """Testa a consistência dos dados em diferentes visualizações."""
        result = self.create_mock_enhanced_result(num_findings=5)
        
        # Gera todos os gráficos principais
        compliance_chart = self.viz_generator.create_compliance_framework_chart(result.findings)
        violations_chart = self.viz_generator.create_governance_violations_chart(result.findings)
        heatmap_chart = self.viz_generator.create_user_risk_heatmap(result.findings)
        timeline_chart = self.viz_generator.create_timeline_analysis(result.findings)
        executive_chart = self.viz_generator.create_executive_dashboard(result)
        
        # Verifica se todos os gráficos foram gerados
        charts = [compliance_chart, violations_chart, heatmap_chart, timeline_chart, executive_chart]
        for chart in charts:
            self.assertIsNotNone(chart)
            self.assertTrue(hasattr(chart, 'data'))
            self.assertTrue(hasattr(chart, 'layout'))

if __name__ == '__main__':
    unittest.main()
