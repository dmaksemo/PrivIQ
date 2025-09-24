# kql_templates.py

"""
Templates KQL (Kusto Query Language) especializados para análise de governança Azure.
Otimizados para detectar violações, padrões suspeitos e questões de compliance.
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta

class KQLTemplateManager:
    """Gerenciador de templates KQL para diferentes cenários de análise."""
    
    def __init__(self):
        self.templates = {
            # 🛡️ ANÁLISE DE GOVERNANÇA COMPLETA
            'comprehensive_governance': {
                'name': 'Análise Completa de Governança',
                'description': 'Análise abrangente incluindo roles, sign-ins, e operações privilegiadas',
                'query': '''
// ANÁLISE COMPLETA DE GOVERNANÇA AZURE - OTIMIZADA
let timeframe = {timeframe};
let privilegedRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator", "Security Administrator",
    "User Administrator", "Application Administrator", "Cloud Application Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Teams Administrator",
    "Intune Administrator", "Conditional Access Administrator", "Authentication Administrator"
]);

// 1. ATRIBUIÇÕES DE ROLES (Últimos dados)
let RoleAssignments = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category == "RoleManagement" 
| where OperationName in ("Add role assignment", "Remove role assignment")
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| extend AssignmentType = case(
    TargetResources[0].type == "User", "Direct_Assignment",
    TargetResources[0].type == "Group", "Group_Assignment", 
    "Unknown"
)
| extend IsPrivileged = iff(RoleName in (privilegedRoles), true, false)
| project TimeGenerated, ActorUPN, TargetUPN, RoleName, OperationName, 
         AssignmentType, IsPrivileged, Result, CorrelationId
| extend EventType = "RoleAssignment";

// 2. SIGN-INS DE RISCO
let RiskySignIns = SigninLogs
| where TimeGenerated >= ago(timeframe)
| where RiskLevelDuringSignIn in ("high", "medium") or ResultType != 0
| extend RiskCategory = case(
    RiskLevelDuringSignIn == "high", "High_Risk",
    RiskLevelDuringSignIn == "medium", "Medium_Risk",
    ResultType != 0, "Failed_SignIn",
    "Low_Risk"
)
| extend LocationInfo = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, LocationInfo, 
         RiskCategory, ResultType, ResultDescription, AppDisplayName,
         DeviceDetail = DeviceDetail.displayName
| extend EventType = "SignIn";

// 3. OPERAÇÕES PRIVILEGIADAS CRÍTICAS
let PrivilegedOps = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category in ("ApplicationManagement", "DirectoryManagement", "RoleManagement", "PolicyManagement")
| where OperationName has_any ("Global Administrator", "Privileged Role", "Security", "Policy", "Application")
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResource = tostring(TargetResources[0].displayName)
| extend OperationType = case(
    Category == "RoleManagement", "Role_Management",
    Category == "ApplicationManagement", "App_Management", 
    Category == "DirectoryManagement", "Directory_Management",
    Category == "PolicyManagement", "Policy_Management",
    "Other"
)
| project TimeGenerated, ActorUPN, OperationName, OperationType, 
         TargetResource, Result, Category
| extend EventType = "PrivilegedOperation";

// 4. CONSOLIDAÇÃO E ANÁLISE
union RoleAssignments, RiskySignIns, PrivilegedOps
| extend Hour = hourofday(TimeGenerated)
| extend IsAfterHours = iff(Hour < 8 or Hour > 18, true, false)
| extend DayOfWeek = dayofweek(TimeGenerated)
| extend IsWeekend = iff(DayOfWeek == 0d or DayOfWeek == 6d, true, false)
| extend SuspiciousIndicator = case(
    IsAfterHours and EventType == "RoleAssignment", "After_Hours_Role_Assignment",
    IsWeekend and EventType == "PrivilegedOperation", "Weekend_Privileged_Operation", 
    RiskCategory == "High_Risk", "High_Risk_SignIn",
    AssignmentType == "Direct_Assignment" and IsPrivileged == true, "Direct_Privileged_Assignment",
    ""
)
| order by TimeGenerated desc
                '''
            },
            
            # 👥 ANÁLISE DE ATRIBUIÇÕES DE ROLES
            'role_assignments': {
                'name': 'Análise de Atribuições de Roles',
                'description': 'Foco em atribuições diretas, violações SOD e privilégios excessivos',
                'query': '''
// ANÁLISE DETALHADA DE ATRIBUIÇÕES DE ROLES
let timeframe = {timeframe};
let sodConflicts = dynamic([
    dynamic(["Global Administrator", "Security Administrator"]),
    dynamic(["User Administrator", "Privileged Role Administrator"]),
    dynamic(["Application Administrator", "Cloud Application Administrator"])
]);

// Busca todas as atribuições de roles
AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category == "RoleManagement"
| where OperationName in ("Add role assignment", "Remove role assignment")
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| extend PrincipalType = tostring(TargetResources[0].type)
| extend AssignmentScope = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend AssignmentType = case(
    PrincipalType == "User", "Direct_Assignment",
    PrincipalType == "Group", "Group_Assignment",
    PrincipalType == "ServicePrincipal", "SP_Assignment",
    "Unknown"
)
// Classificação de risco
| extend RiskLevel = case(
    AssignmentType == "Direct_Assignment" and RoleName contains "Administrator", "High",
    AssignmentType == "Direct_Assignment", "Medium", 
    RoleName contains "Global Administrator", "Critical",
    RoleName contains "Privileged Role Administrator", "Critical",
    "Low"
)
// Indicadores de governança
| extend GovernanceFlag = case(
    AssignmentType == "Direct_Assignment" and RoleName contains "Administrator", "DIRECT_ADMIN_ASSIGNMENT",
    OperationName == "Add role assignment" and hourofday(TimeGenerated) > 20, "AFTER_HOURS_ASSIGNMENT",
    OperationName == "Add role assignment" and dayofweek(TimeGenerated) in (0d, 6d), "WEEKEND_ASSIGNMENT",
    ""
)
| project TimeGenerated, ActorUPN, TargetUPN, RoleName, OperationName, 
         AssignmentType, RiskLevel, GovernanceFlag, Result, CorrelationId
| order by TimeGenerated desc
                '''
            },
            
            # 🔐 ANÁLISE DE SIGN-INS E COMPORTAMENTO
            'sign_in_analysis': {
                'name': 'Análise de Sign-ins e Comportamento',
                'description': 'Detecção de padrões suspeitos em autenticação e acesso',
                'query': '''
// ANÁLISE COMPORTAMENTAL DE SIGN-INS
let timeframe = {timeframe};

SigninLogs
| where TimeGenerated >= ago(timeframe)
| extend LocationKey = strcat(LocationDetails.city, "-", LocationDetails.countryOrRegion)
| extend DeviceKey = strcat(DeviceDetail.deviceId, "-", DeviceDetail.displayName)
// Análise de padrões por usuário
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(LocationKey),
    UniqueDevices = dcount(DeviceKey),
    FailedAttempts = countif(ResultType != 0),
    RiskySignIns = countif(RiskLevelDuringSignIn in ("high", "medium")),
    AfterHoursSignIns = countif(hourofday(TimeGenerated) < 8 or hourofday(TimeGenerated) > 18),
    WeekendSignIns = countif(dayofweek(TimeGenerated) in (0d, 6d)),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated),
    IPAddresses = make_set(IPAddress, 10),
    Locations = make_set(LocationKey, 5),
    Apps = make_set(AppDisplayName, 10)
    by UserPrincipalName
// Classificação de risco comportamental
| extend BehaviorRisk = case(
    UniqueIPs > 10 and SignInCount > 100, "Critical",
    UniqueLocations > 5, "High",
    FailedAttempts > 20, "High", 
    AfterHoursSignIns > 50, "Medium",
    RiskySignIns > 0, "Medium",
    "Low"
)
// Flags de anomalia
| extend AnomalyFlags = case(
    UniqueIPs > 15, "MULTIPLE_IP_ADDRESSES",
    UniqueLocations > 8, "MULTIPLE_LOCATIONS", 
    FailedAttempts > 30, "EXCESSIVE_FAILED_ATTEMPTS",
    AfterHoursSignIns > 100, "FREQUENT_AFTER_HOURS_ACCESS",
    ""
)
| extend FailureRate = round(todouble(FailedAttempts) / todouble(SignInCount) * 100, 2)
| project UserPrincipalName, SignInCount, UniqueIPs, UniqueLocations, 
         FailedAttempts, FailureRate, BehaviorRisk, AnomalyFlags,
         FirstSignIn, LastSignIn, IPAddresses, Locations, Apps
| order by BehaviorRisk desc, SignInCount desc
                '''
            },
            
            # ⚡ OPERAÇÕES PRIVILEGIADAS
            'privileged_operations': {
                'name': 'Operações Privilegiadas',
                'description': 'Monitoramento de ações administrativas críticas',
                'query': '''
// MONITORAMENTO DE OPERAÇÕES PRIVILEGIADAS
let timeframe = {timeframe};
let criticalOperations = dynamic([
    "Add role assignment", "Remove role assignment",
    "Add service principal", "Update application",
    "Add policy", "Update policy", "Delete policy",
    "Add user", "Delete user", "Update user",
    "Reset password", "Change password"
]);

AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName in (criticalOperations) or
        OperationName contains "Administrator" or
        OperationName contains "Privileged"
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend TargetResource = tostring(TargetResources[0].displayName)
// Classificação de criticidade
| extend CriticalityLevel = case(
    OperationName has_any ("Global Administrator", "Privileged Role Administrator"), "Critical",
    OperationName has_any ("Security Administrator", "Delete", "Reset password"), "High",
    OperationName has_any ("Add role", "Update policy"), "Medium",
    "Low"
)
// Indicadores de risco temporal
| extend TemporalRisk = case(
    hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) > 22, "After_Hours",
    dayofweek(TimeGenerated) in (0d, 6d), "Weekend",
    "Business_Hours"
)
// Agrupamento de atividades suspeitas
| extend SuspiciousPattern = case(
    CriticalityLevel == "Critical" and TemporalRisk != "Business_Hours", "CRITICAL_AFTER_HOURS",
    OperationName == "Add role assignment" and TargetUser == ActorUPN, "SELF_ROLE_ASSIGNMENT",
    Result == "failure" and CriticalityLevel in ("Critical", "High"), "FAILED_PRIVILEGED_OPERATION",
    ""
)
| project TimeGenerated, ActorUPN, ActorIP, OperationName, TargetUser, 
         TargetResource, CriticalityLevel, TemporalRisk, SuspiciousPattern, 
         Result, Category, CorrelationId
| order by TimeGenerated desc
                '''
            },
            
            # 🔍 DETECÇÃO DE ANOMALIAS
            'anomaly_detection': {
                'name': 'Detecção de Anomalias',
                'description': 'Identificação de padrões anômalos e comportamentos suspeitos',
                'query': '''
// DETECÇÃO AVANÇADA DE ANOMALIAS
let timeframe = {timeframe};
let baselineWindow = 30d; // Janela para estabelecer baseline

// Baseline de comportamento normal (30 dias)
let UserBaseline = SigninLogs
| where TimeGenerated between (ago(baselineWindow) .. ago(timeframe))
| summarize 
    AvgDailySignIns = avg(todouble(1)),
    TypicalHours = make_set(hourofday(TimeGenerated)),
    TypicalIPs = dcount(IPAddress),
    TypicalLocations = dcount(strcat(LocationDetails.city, LocationDetails.countryOrRegion))
    by UserPrincipalName;

// Comportamento atual
let CurrentBehavior = SigninLogs
| where TimeGenerated >= ago(timeframe)
| summarize
    CurrentSignIns = count(),
    CurrentIPs = dcount(IPAddress),
    CurrentLocations = dcount(strcat(LocationDetails.city, LocationDetails.countryOrRegion)),
    CurrentHours = make_set(hourofday(TimeGenerated)),
    RiskySignIns = countif(RiskLevelDuringSignIn in ("high", "medium")),
    FailedSignIns = countif(ResultType != 0)
    by UserPrincipalName;

// Comparação e detecção de anomalias
CurrentBehavior
| join kind=leftouter UserBaseline on UserPrincipalName
| extend IPAnomaly = case(
    isempty(TypicalIPs), false,
    CurrentIPs > (TypicalIPs * 3), true,
    false
)
| extend LocationAnomaly = case(
    isempty(TypicalLocations), false, 
    CurrentLocations > (TypicalLocations * 2), true,
    false
)
| extend VolumeAnomaly = case(
    isempty(AvgDailySignIns), false,
    CurrentSignIns > (AvgDailySignIns * 5), true,
    false
)
// Score de anomalia
| extend AnomalyScore = 
    (iff(IPAnomaly, 25, 0)) +
    (iff(LocationAnomaly, 20, 0)) + 
    (iff(VolumeAnomaly, 15, 0)) +
    (iff(RiskySignIns > 0, 20, 0)) +
    (iff(FailedSignIns > 10, 20, 0))
| extend RiskClassification = case(
    AnomalyScore >= 60, "Critical",
    AnomalyScore >= 40, "High", 
    AnomalyScore >= 20, "Medium",
    "Low"
)
| where AnomalyScore > 0
| project UserPrincipalName, AnomalyScore, RiskClassification,
         IPAnomaly, LocationAnomaly, VolumeAnomaly, 
         CurrentSignIns, CurrentIPs, CurrentLocations,
         RiskySignIns, FailedSignIns
| order by AnomalyScore desc
                '''
            },
            
            # 📊 ANÁLISE DE COMPLIANCE SOX
            'sox_compliance': {
                'name': 'Análise de Compliance SOX',
                'description': 'Verificações específicas para Sarbanes-Oxley Act',
                'query': '''
// ANÁLISE DE COMPLIANCE SOX (SARBANES-OXLEY)
let timeframe = {timeframe};
let soxCriticalRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "User Administrator", "Security Administrator", 
    "Billing Administrator", "Exchange Administrator"
]);

// 1. Violações de Segregação de Funções (SOD)
let SODViolations = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category == "RoleManagement" 
| where OperationName == "Add role assignment"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where RoleName in (soxCriticalRoles)
| summarize AssignedRoles = make_set(RoleName) by TargetUPN
| where array_length(AssignedRoles) > 1
| extend SODViolationType = case(
    AssignedRoles has_all (dynamic(["Global Administrator", "Security Administrator"])), "Admin_Security_Conflict",
    AssignedRoles has_all (dynamic(["User Administrator", "Privileged Role Administrator"])), "User_Privilege_Conflict", 
    AssignedRoles has_all (dynamic(["Billing Administrator", "Global Administrator"])), "Finance_Admin_Conflict",
    "Multiple_Admin_Roles"
)
| extend ComplianceImpact = "SOX_Violation"
| project TargetUPN, AssignedRoles, SODViolationType, ComplianceImpact;

// 2. Atribuições Diretas (Violação de Boas Práticas)
let DirectAssignments = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category == "RoleManagement"
| where OperationName == "Add role assignment"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend TargetType = tostring(TargetResources[0].type)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where TargetType == "User" and RoleName in (soxCriticalRoles)
| extend ViolationType = "Direct_Assignment"
| extend ComplianceImpact = "SOX_Best_Practice_Violation"
| project TimeGenerated, TargetUPN, RoleName, ViolationType, ComplianceImpact;

// 3. Atividades Após Horário Comercial 
let AfterHoursActivity = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category in ("RoleManagement", "ApplicationManagement", "DirectoryManagement")
| where hourofday(TimeGenerated) < 8 or hourofday(TimeGenerated) > 18
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend ViolationType = "After_Hours_Privileged_Activity"
| extend ComplianceImpact = "SOX_Monitoring_Required"
| project TimeGenerated, ActorUPN, OperationName, ViolationType, ComplianceImpact;

// Consolidação para relatório SOX
union SODViolations, DirectAssignments, AfterHoursActivity
| extend ReportCategory = "SOX_Compliance_Findings"
| extend Severity = case(
    ComplianceImpact == "SOX_Violation", "Critical",
    ComplianceImpact == "SOX_Best_Practice_Violation", "High",
    "Medium"
)
| project TimeGenerated = now(), UserPrincipalName = coalesce(TargetUPN, ActorUPN), 
         ViolationType, ComplianceImpact, Severity, ReportCategory
| order by Severity desc
                '''
            }
        }
    
    def get_template(self, template_name: str) -> Dict[str, Any]:
        """Retorna template específico."""
        return self.templates.get(template_name, {})
    
    def get_all_templates(self) -> Dict[str, Dict[str, Any]]:
        """Retorna todos os templates disponíveis."""
        return self.templates
    
    def list_templates(self) -> List[str]:
        """Lista nomes de todos os templates."""
        return list(self.templates.keys())
    
    def build_query(self, template_name: str, parameters: Dict[str, Any]) -> str:
        """Constrói query KQL com parâmetros."""
        template = self.get_template(template_name)
        if not template:
            raise ValueError(f"Template '{template_name}' não encontrado")
        
        query = template['query']
        
        # Substitui parâmetros
        for param, value in parameters.items():
            placeholder = "{" + param + "}"
            query = query.replace(placeholder, str(value))
        
        return query
    
    def get_template_info(self, template_name: str) -> Dict[str, str]:
        """Retorna informações sobre um template."""
        template = self.get_template(template_name)
        if not template:
            return {}
        
        return {
            'name': template.get('name', template_name),
            'description': template.get('description', 'Sem descrição disponível')
        }

# Templates customizados para cenários específicos
class CustomKQLTemplates:
    """Templates KQL customizados para necessidades específicas."""
    
    @staticmethod
    def get_user_risk_profile(user_upn: str, timeframe: str = "30d") -> str:
        """Query para perfil de risco de usuário específico."""
        return f'''
// PERFIL DE RISCO DETALHADO - {user_upn}
let user = "{user_upn}";
let timeframe = {timeframe};

// Análise de roles
let UserRoles = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category == "RoleManagement"
| where TargetResources[0].userPrincipalName == user
| extend RoleName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| extend Operation = OperationName
| summarize Roles = make_set(RoleName), RoleChanges = count() by Operation
| extend RiskIndicator = "Role_Analysis";

// Análise de sign-ins
let UserSignIns = SigninLogs
| where TimeGenerated >= ago(timeframe) 
| where UserPrincipalName == user
| summarize 
    TotalSignIns = count(),
    UniqueIPs = dcount(IPAddress), 
    UniqueLocations = dcount(strcat(LocationDetails.city, LocationDetails.countryOrRegion)),
    FailedAttempts = countif(ResultType != 0),
    RiskySignIns = countif(RiskLevelDuringSignIn in ("high", "medium"))
| extend RiskScore = (UniqueIPs * 2) + (FailedAttempts * 3) + (RiskySignIns * 5)
| extend RiskIndicator = "SignIn_Analysis";

// Operações privilegiadas
let UserOperations = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where InitiatedBy.user.userPrincipalName == user
| where Category in ("RoleManagement", "ApplicationManagement", "DirectoryManagement")
| summarize PrivilegedOperations = count(), Operations = make_set(OperationName)
| extend RiskIndicator = "Privileged_Operations";

union UserRoles, UserSignIns, UserOperations
| extend UserPrincipalName = user
        '''
    
    @staticmethod
    def get_governance_dashboard_query(timeframe: str = "7d") -> str:
        """Query otimizada para dashboard de governança."""
        return f'''
// DASHBOARD DE GOVERNANÇA - MÉTRICAS PRINCIPAIS
let timeframe = {timeframe};

// KPIs principais
let TotalUsers = SigninLogs
| where TimeGenerated >= ago(timeframe)
| distinct UserPrincipalName
| count;

let DirectAssignments = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category == "RoleManagement" and OperationName == "Add role assignment"
| where TargetResources[0].type == "User"
| count;

let SODViolations = AuditLogs
| where TimeGenerated >= ago(timeframe)
| where Category == "RoleManagement"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[0].newValue)
| summarize Roles = make_set(RoleName) by TargetUPN
| where array_length(Roles) > 1
| count;

let RiskySignIns = SigninLogs
| where TimeGenerated >= ago(timeframe)
| where RiskLevelDuringSignIn in ("high", "medium")
| count;

// Consolidação
print 
    Metric = "GovernanceDashboard",
    TotalUsers = TotalUsers,
    DirectAssignments = DirectAssignments, 
    SODViolations = SODViolations,
    RiskySignIns = RiskySignIns,
    TimeGenerated = now()
        '''

# Exemplo de uso
def example_usage():
    """Demonstra como usar os templates KQL."""
    
    manager = KQLTemplateManager()
    
    # Lista templates disponíveis
    print("Templates disponíveis:")
    for template in manager.list_templates():
        info = manager.get_template_info(template)
        print(f"- {template}: {info['name']}")
    
    # Constrói query específica
    parameters = {
        'timeframe': '7d',
        'user_filter': 'admin@contoso.com'
    }
    
    query = manager.build_query('role_assignments', parameters)
    print(f"\nQuery gerada:\n{query}")

if __name__ == "__main__":
    example_usage()