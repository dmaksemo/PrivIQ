import unittest
from datetime import datetime, timedelta
from typing import List, Dict, Any
from unittest.mock import Mock, patch
from governance_analyzer import AdvancedGovernanceAnalyzer, CriticalGapAnalyzer
from models import (
    DetailedFinding, RiskLevel, GovernanceViolationType, 
    ComplianceFramework, EnhancedAIAnalysisResult
)

class TestAdvancedGovernanceAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = AdvancedGovernanceAnalyzer()
        
    def create_mock_logs(self) -> List[Dict[str, Any]]:
        """Cria logs mockados para teste."""
        current_time = datetime.now()
        return [
            {
                "time": (current_time - timedelta(hours=i)).isoformat(),
                "operation": "Add member to role",
                "user_principal_name": f"user{i}@test.com",
                "role_name": "Global Administrator",
                "target_resources": ["resource1", "resource2"],
                "ip_address": f"192.168.1.{i}",
                "result_type": "Success"
            } for i in range(10)
        ]

    def test_empty_input_handling(self):
        """Testa o comportamento com entrada vazia."""
        result = self.analyzer.perform_comprehensive_analysis([])
        self.assertIsInstance(result, EnhancedAIAnalysisResult)
        self.assertEqual(result.risk_assessment.score, 0)

    def test_invalid_data_handling(self):
        """Testa o comportamento com dados inválidos."""
        invalid_logs = [{"invalid": "data"} for _ in range(5)]
        result = self.analyzer.perform_comprehensive_analysis(invalid_logs)
        self.assertIsInstance(result, EnhancedAIAnalysisResult)
        self.assertTrue(hasattr(result, 'findings'))

    def test_critical_findings_detection(self):
        """Testa a detecção de achados críticos."""
        # Cria logs que devem gerar achados críticos
        logs = self.create_mock_logs()
        # Adiciona violações SOD
        logs.extend([{
            "time": datetime.now().isoformat(),
            "operation": "Add member to role",
            "user_principal_name": "critical_user@test.com",
            "role_name": role,
            "result_type": "Success"
        } for role in ["Global Administrator", "Security Administrator"]])

        result = self.analyzer.perform_comprehensive_analysis(logs)
        
        critical_findings = [f for f in result.findings if f.risk_level == RiskLevel.CRITICAL]
        self.assertTrue(len(critical_findings) > 0, "Deveria detectar achados críticos")

    def test_risk_score_calculation(self):
        """Testa o cálculo do score de risco."""
        logs = self.create_mock_logs()
        result = self.analyzer.perform_comprehensive_analysis(logs)
        
        self.assertIsInstance(result.risk_assessment.score, (int, float))
        self.assertTrue(0 <= result.risk_assessment.score <= 100)

    def test_compliance_framework_detection(self):
        """Testa a detecção de frameworks de compliance afetados."""
        logs = self.create_mock_logs()
        result = self.analyzer.perform_comprehensive_analysis(logs)
        
        for finding in result.findings:
            self.assertTrue(hasattr(finding, 'compliance_impact'))
            if finding.compliance_impact:
                self.assertTrue(all(isinstance(f, ComplianceFramework) 
                                  for f in finding.compliance_impact))

    def test_error_recovery(self):
        """Testa a recuperação de erros durante a análise."""
        # Simula um erro durante a análise
        with patch.object(self.analyzer, '_perform_rule_based_analysis', 
                         side_effect=Exception('Erro simulado')):
            result = self.analyzer.perform_comprehensive_analysis(self.create_mock_logs())
            self.assertIsInstance(result, EnhancedAIAnalysisResult)

    def test_large_dataset_handling(self):
        """Testa o processamento de grandes conjuntos de dados."""
        large_logs = self.create_mock_logs() * 100  # 1000 logs
        result = self.analyzer.perform_comprehensive_analysis(large_logs)
        self.assertIsInstance(result, EnhancedAIAnalysisResult)

    def test_suspicious_pattern_detection(self):
        """Testa a detecção de padrões suspeitos."""
        # Cria logs com padrões suspeitos
        logs = []
        # Múltiplos IPs para mesmo usuário
        for ip in range(10):
            logs.append({
                "time": datetime.now().isoformat(),
                "operation": "User login",
                "user_principal_name": "suspicious@test.com",
                "ip_address": f"192.168.1.{ip}",
                "result_type": "Success"
            })

        result = self.analyzer.perform_comprehensive_analysis(logs)
        suspicious_findings = [f for f in result.findings 
                             if f.violation_type == GovernanceViolationType.SUSPICIOUS_ACCESS]
        self.assertTrue(len(suspicious_findings) > 0)

    def test_consolidation_logic(self):
        """Testa a lógica de consolidação de resultados."""
        findings = [
            DetailedFinding(
                risk_level=RiskLevel.CRITICAL,
                violation_type=GovernanceViolationType.SOD_VIOLATION,
                title="Test Critical Finding",
                description="Test Description",
                recommendation="Test Recommendation",
                affected_principals=["user1@test.com"],
                evidence={"test": "evidence"},
                compliance_impact=[ComplianceFramework.SOX],
                remediation_priority=1,
                business_impact="Test Impact",
                detection_timestamp=datetime.now().isoformat()
            )
        ]
        
        result = self.analyzer._consolidate_analysis_results(findings, self.create_mock_logs())
        self.assertIsInstance(result, EnhancedAIAnalysisResult)
        self.assertTrue(hasattr(result, 'executive_summary'))
        self.assertTrue(hasattr(result, 'technical_summary'))

    def test_gap_analysis(self):
        """Testa a análise de lacunas críticas."""
        current_state = {
            "identity": {
                "mfa_status": {"enforced": False},
                "privileged_access": {"jit_enabled": False}
            },
            "compliance": {
                "audit_logs": {"enabled": True},
                "data_controls": {"classification_enabled": False}
            }
        }
        
        gaps = self.analyzer.gap_analyzer.analyze_critical_gaps(current_state)
        self.assertTrue(isinstance(gaps, dict))
        self.assertTrue('critical_findings' in gaps)
        self.assertTrue(len(gaps['critical_findings']) > 0)

    def test_metric_calculation(self):
        """Testa o cálculo de métricas de governança."""
        governance_summary = {
            'governance_issues': {
                'direct_assignments': 5,
                'sod_violations': 2,
                'duplicate_groups': 3
            },
            'unique_users': 100
        }
        
        metrics = self.analyzer._calculate_governance_metrics(governance_summary)
        self.assertIsInstance(metrics, dict)
        self.assertTrue('compliance_score' in metrics)
        self.assertTrue(isinstance(metrics['compliance_score'], (int, float)))
        self.assertTrue(0 <= metrics['compliance_score'] <= 100)

if __name__ == '__main__':
    unittest.main(verbose=True)
