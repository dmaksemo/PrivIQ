import unittest
from datetime import datetime, timedelta
from typing import List, Dict, Any
from governance_analyzer import AdvancedGovernanceAnalyzer
from models import (
    DetailedFinding, RiskLevel, GovernanceViolationType,
    ComplianceFramework, EnhancedAIAnalysisResult
)

class TestGovernanceFlows(unittest.TestCase):
    def setUp(self):
        self.analyzer = AdvancedGovernanceAnalyzer()
        self.sample_logs = self._create_sample_logs()

    def _create_sample_logs(self) -> List[Dict[str, Any]]:
        """Cria logs de teste com todos os cenários necessários."""
        current_time = datetime.now()
        logs = []

        # 1. Logs de administradores globais (para teste SOX)
        for i in range(5):
            logs.append({
                "time": (current_time - timedelta(hours=i)).isoformat(),
                "operation": "Add member to role",
                "user_principal_name": f"admin{i}@test.com",
                "role_name": "Global Administrator",
                "target_resources": ["resource1"],
                "result_type": "Success"
            })

        # 2. Logs de tentativas de login (para teste NIST)
        for i in range(3):
            logs.append({
                "time": (current_time - timedelta(minutes=i*5)).isoformat(),
                "operation": "User login",
                "user_principal_name": "user1@test.com",
                "ip_address": f"192.168.1.{i}",
                "result_type": "Success"
            })

        # 3. Logs de violações SOD
        logs.append({
            "time": current_time.isoformat(),
            "operation": "Add member to role",
            "user_principal_name": "sod_user@test.com",
            "role_name": "Security Administrator",
            "result_type": "Success"
        })
        logs.append({
            "time": current_time.isoformat(),
            "operation": "Add member to role",
            "user_principal_name": "sod_user@test.com",
            "role_name": "Global Administrator",
            "result_type": "Success"
        })

        return logs

    def test_comprehensive_analysis_flow(self):
        """Testa o fluxo completo de análise."""
        print("\nTestando fluxo de análise abrangente...")
        result = self.analyzer.perform_comprehensive_analysis(self.sample_logs)
        
        # Verifica se o resultado foi gerado corretamente
        self.assertIsInstance(result, EnhancedAIAnalysisResult)
        self.assertTrue(hasattr(result, 'findings'))
        self.assertTrue(hasattr(result, 'risk_assessment'))
        print(f"- Número de findings: {len(result.findings)}")
        print(f"- Score de risco: {result.risk_assessment.get('score', 0)}")

    def test_sod_violations_flow(self):
        """Testa o fluxo de detecção de violações SOD."""
        print("\nTestando fluxo de violações SOD...")
        findings = self.analyzer._analyze_sod_violations()
        self.assertIsInstance(findings, list)
        sod_violations = [f for f in findings if f.violation_type == GovernanceViolationType.SOD_VIOLATION]
        print(f"- Violações SOD detectadas: {len(sod_violations)}")
        for violation in sod_violations:
            print(f"  * {violation.title}")

    def test_nist_compliance_flow(self):
        """Testa o fluxo de compliance NIST."""
        print("\nTestando fluxo de compliance NIST...")
        findings = self.analyzer._check_nist_compliance()
        self.assertIsInstance(findings, list)
        nist_violations = [f for f in findings if ComplianceFramework.NIST in f.compliance_impact]
        print(f"- Violações NIST detectadas: {len(nist_violations)}")
        for violation in nist_violations:
            print(f"  * {violation.title}")

    def test_risk_calculation_flow(self):
        """Testa o fluxo de cálculo de risco."""
        print("\nTestando fluxo de cálculo de risco...")
        result = self.analyzer.perform_comprehensive_analysis(self.sample_logs)
        risk_score = result.risk_assessment.get('score', 0)
        print(f"- Score de risco calculado: {risk_score}")
        self.assertTrue(0 <= risk_score <= 100)

    def test_ai_analysis_flow(self):
        """Testa o fluxo de análise com IA."""
        print("\nTestando fluxo de análise com IA...")
        try:
            ai_result = self.analyzer._perform_ai_analysis(self.sample_logs)
            print("- Análise com IA concluída com sucesso")
            self.assertIsInstance(ai_result, EnhancedAIAnalysisResult)
        except Exception as e:
            print(f"- Erro na análise com IA: {str(e)}")
            self.fail(f"Erro no fluxo de IA: {str(e)}")

if __name__ == '__main__':
    unittest.main(verbosity=2)
