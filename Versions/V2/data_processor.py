# data_processor.py

import pandas as pd
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import re
from collections import defaultdict

class AzureLogProcessor:
    """Processador otimizado para logs de auditoria do Azure com foco em governança e permissões."""
    
    def __init__(self):
        self.logs_df: Optional[pd.DataFrame] = None
        self.role_assignments_df: Optional[pd.DataFrame] = None
        self.privileged_roles = {
            # Roles em inglês
            'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
            'User Administrator', 'Application Administrator', 'Cloud Application Administrator',
            'Exchange Administrator', 'SharePoint Administrator', 'Teams Administrator',
            'Intune Administrator', 'Conditional Access Administrator', 'Authentication Administrator',
            'Owner', 'Contributor', 'User Access Administrator',
            # Roles em português
            'Administrador Global', 'Administrador de Função Privilegiada', 'Admin de Segurança',
            'Administrador de Usuário', 'Administrador de Aplicativo', 'Administrador de Aplicativo de Nuvem',
            'Administrador do Exchange', 'Administrador do SharePoint', 'Administrador do Teams',
            'Administrador do Intune', 'Administrador de Acesso Condicional', 'Administrador de Autenticação',
            'Proprietário', 'Contribuidor', 'Administrador de Acesso do Usuário'
        }
        
    def load_logs_from_file(self, file_content: str) -> pd.DataFrame:
        """Carrega e normaliza logs de um arquivo JSON com tratamento robusto."""
        try:
            logs_data = json.loads(file_content)
            
            # Normaliza diferentes estruturas de logs do Azure
            if isinstance(logs_data, dict):
                if 'value' in logs_data:
                    logs_data = logs_data['value']
                elif 'records' in logs_data:
                    logs_data = logs_data['records']
                elif 'logs' in logs_data:
                    logs_data = logs_data['logs']
            
            self.logs_df = pd.json_normalize(logs_data, sep='_')
            
            # Padroniza colunas importantes
            self._standardize_columns()
            
            # Filtra logs relacionados a permissões e roles
            self._extract_role_assignments()
            
            return self.logs_df
            
        except (json.JSONDecodeError, TypeError) as e:
            raise ValueError(f"Conteúdo do arquivo não é um JSON válido: {e}")
        except Exception as e:
            raise ValueError(f"Erro inesperado ao processar o arquivo: {e}")
    
    def _standardize_columns(self):
        """Padroniza nomes de colunas para facilitar a análise."""
        if self.logs_df is None:
            return
            
        # Mapeamento de colunas comuns - suporta múltiplos formatos
        column_mappings = {
            # Formato Azure Activity Logs
            'identity_userPrincipalName': 'user_principal_name',
            'callerIpAddress': 'ip_address',
            'operationName': 'operation_name',
            'resultType': 'result_type',
            'properties_targetResources': 'target_resources',
            'properties_roleName': 'role_name',
            'properties_roleDefinitionName': 'role_definition_name',
            'activityDateTime': 'timestamp',
            'time': 'timestamp',
            # Formato Role Assignments (novo)
            'SignInName': 'user_principal_name',
            'DisplayName': 'display_name',
            'RoleDefinitionName': 'role_name',
            'RoleDefinitionId': 'role_definition_id',
            'RoleAssignmentId': 'assignment_id',
            'ObjectId': 'object_id',
            'ObjectType': 'object_type',
            'Scope': 'scope'
        }
        
        for old_name, new_name in column_mappings.items():
            if old_name in self.logs_df.columns:
                self.logs_df[new_name] = self.logs_df[old_name]
        
        # Converte timestamp para datetime
        if 'timestamp' in self.logs_df.columns:
            self.logs_df['timestamp'] = pd.to_datetime(self.logs_df['timestamp'], errors='coerce')
    
    def _extract_role_assignments(self):
        """Extrai e organiza dados de atribuições de roles."""
        if self.logs_df is None:
            return
            
        # Verifica se é formato de Role Assignments direto
        if 'RoleAssignmentId' in self.logs_df.columns or 'assignment_id' in self.logs_df.columns:
            # Formato direto de role assignments - usa todos os dados
            self.role_assignments_df = self.logs_df.copy()
            # Adiciona operação sintética para compatibilidade
            if 'operation_name' not in self.role_assignments_df.columns:
                self.role_assignments_df['operation_name'] = 'Role assignment'
        else:
            # Formato tradicional de activity logs
            role_operations = [
                'Add member to role', 'Remove member from role', 'Add role assignment',
                'Delete role assignment', 'Add app role assignment', 'Remove app role assignment'
            ]
            
            role_mask = self.logs_df['operation_name'].isin(role_operations) if 'operation_name' in self.logs_df.columns else pd.Series([False] * len(self.logs_df))
            self.role_assignments_df = self.logs_df[role_mask].copy()
    
    def analyze_direct_user_assignments(self) -> Dict[str, Any]:
        """Identifica usuários com roles atribuídas diretamente (não através de grupos)."""
        if self.role_assignments_df is None or self.role_assignments_df.empty:
            return {"direct_assignments": [], "total_count": 0}
        
        direct_assignments = []
        
        # Procura por atribuições diretas
        for _, row in self.role_assignments_df.iterrows():
            user_principal = row.get('user_principal_name', '')
            role_name = row.get('role_name', '')
            object_type = row.get('object_type', row.get('ObjectType', ''))
            
            # Verifica se tem dados válidos
            if pd.notna(user_principal) and pd.notna(role_name):
                # Verifica se é atribuição direta (não grupo)
                is_direct = True
                
                # Método 1: Verifica ObjectType se disponível
                if object_type and str(object_type).lower() == 'group':
                    is_direct = False
                # Método 2: Verifica se SignInName está vazio (indica grupo)
                elif not user_principal or str(user_principal).strip() == '':
                    is_direct = False
                # Método 3: Verifica properties (formato antigo)
                elif 'properties' in str(row):
                    props_str = str(row.get('properties', ''))
                    if 'group' in props_str.lower() or 'principalType":"Group"' in props_str:
                        is_direct = False
                
                if is_direct and user_principal.strip():
                    assignment_info = {
                        'user': user_principal,
                        'role': role_name,
                        'display_name': row.get('display_name', row.get('DisplayName', user_principal)),
                        'timestamp': row.get('timestamp', 'N/A'),
                        'operation': row.get('operation_name', 'Role assignment'),
                        'object_type': object_type,
                        'scope': row.get('scope', row.get('Scope', 'Unknown')),
                        'is_privileged': role_name in self.privileged_roles
                    }
                    direct_assignments.append(assignment_info)
        
        return {
            "direct_assignments": direct_assignments,
            "total_count": len(direct_assignments),
            "privileged_count": sum(1 for a in direct_assignments if a['is_privileged'])
        }
    
    def analyze_permission_conflicts(self) -> Dict[str, Any]:
        """Identifica conflitos de permissões e violações de SOD."""
        if self.role_assignments_df is None or self.role_assignments_df.empty:
            return {"conflicts": [], "total_conflicts": 0}
        
        conflicts = []
        user_roles = defaultdict(set)
        
        # Agrupa roles por usuário - adaptado para novo formato
        for _, row in self.role_assignments_df.iterrows():
            # Suporta tanto SignInName quanto user_principal_name
            user = row.get('user_principal_name') or row.get('SignInName', '')
            role = row.get('role_name') or row.get('RoleDefinitionName', '')
            object_type = row.get('object_type') or row.get('ObjectType', '')
            
            # Só analisa usuários (não grupos) com roles válidas
            if user and role and str(object_type).lower() != 'group' and user.strip():
                user_roles[user].add(role)
        
        # Define conflitos de SOD (Segregation of Duties)
        sod_conflicts = [
            ('Global Administrator', 'Security Administrator'),
            ('Administrador Global', 'Admin de Segurança'),
            ('User Administrator', 'Privileged Role Administrator'),
            ('Application Administrator', 'Cloud Application Administrator'),
            ('Exchange Administrator', 'Security Administrator'),
            ('Contribuidor', 'Proprietário'),  # Adiciona conflitos comuns em português
            ('Owner', 'Contributor')
        ]
        
        for user, roles in user_roles.items():
            # Verifica conflitos SOD
            for role1, role2 in sod_conflicts:
                if role1 in roles and role2 in roles:
                    conflicts.append({
                        'type': 'SOD_VIOLATION',
                        'user': user,
                        'conflicting_roles': [role1, role2],
                        'severity': 'HIGH',
                        'description': f'Usuário possui roles conflitantes que violam segregação de funções'
                    })
            
            # Verifica excesso de privilégios
            privileged_roles_count = len([r for r in roles if r in self.privileged_roles])
            if privileged_roles_count > 2:
                conflicts.append({
                    'type': 'EXCESSIVE_PRIVILEGES',
                    'user': user,
                    'roles_count': privileged_roles_count,
                    'roles': list(roles & self.privileged_roles),
                    'severity': 'MEDIUM',
                    'description': f'Usuário possui {privileged_roles_count} roles privilegiadas'
                })
        
        return {
            "conflicts": conflicts,
            "total_conflicts": len(conflicts),
            "sod_violations": len([c for c in conflicts if c['type'] == 'SOD_VIOLATION']),
            "excessive_privileges": len([c for c in conflicts if c['type'] == 'EXCESSIVE_PRIVILEGES'])
        }
    
    def analyze_duplicate_group_permissions(self) -> Dict[str, Any]:
        """Identifica grupos com permissões duplicadas ou redundantes."""
        if self.role_assignments_df is None or self.role_assignments_df.empty:
            return {"duplicates": [], "total_duplicates": 0}
        
        duplicates = []
        group_roles = defaultdict(set)
        
        # Identifica atribuições de grupos - adaptado para novo formato
        for _, row in self.role_assignments_df.iterrows():
            object_type = row.get('object_type') or row.get('ObjectType', '')
            display_name = row.get('display_name') or row.get('DisplayName', '')
            role = row.get('role_name') or row.get('RoleDefinitionName', '')
            
            # Verifica se é um grupo
            if str(object_type).lower() == 'group' and display_name and role:
                group_roles[display_name].add(role)
            elif 'properties' in str(row):
                # Fallback para formato antigo
                props_str = str(row.get('properties', ''))
                if 'principalType":"Group"' in props_str or 'group' in props_str.lower():
                    # Extrai nome do grupo das propriedades
                    group_match = re.search(r'"displayName":"([^"]+)"', props_str)
                    if group_match and role:
                        group_name = group_match.group(1)
                        group_roles[group_name].add(role)
        
        # Identifica grupos com roles duplicadas
        seen_role_sets = defaultdict(list)
        for group, roles in group_roles.items():
            role_signature = frozenset(roles)
            seen_role_sets[role_signature].append(group)
        
        for role_set, groups in seen_role_sets.items():
            if len(groups) > 1:
                duplicates.append({
                    'groups': groups,
                    'shared_roles': list(role_set),
                    'roles_count': len(role_set),
                    'severity': 'MEDIUM' if len(role_set) > 2 else 'LOW'
                })
        
        return {
            "duplicates": duplicates,
            "total_duplicates": len(duplicates),
            "affected_groups": sum(len(d['groups']) for d in duplicates)
        }
    
    def analyze_critical_access_patterns(self) -> Dict[str, Any]:
        """Analisa padrões de acesso críticos e suspeitos."""
        if self.logs_df is None or self.logs_df.empty:
            return {"critical_patterns": [], "total_patterns": 0}
        
        patterns = []
        
        # Analisa acessos fora do horário comercial
        if 'timestamp' in self.logs_df.columns:
            self.logs_df['hour'] = pd.to_datetime(self.logs_df['timestamp']).dt.hour
            after_hours = self.logs_df[
                (self.logs_df['hour'] < 7) | (self.logs_df['hour'] > 19)
            ]
            
            if not after_hours.empty:
                patterns.append({
                    'type': 'AFTER_HOURS_ACCESS',
                    'count': len(after_hours),
                    'users': after_hours['user_principal_name'].dropna().unique().tolist()[:10],
                    'severity': 'MEDIUM'
                })
        
        # Analisa múltiplos IPs por usuário
        if 'ip_address' in self.logs_df.columns and 'user_principal_name' in self.logs_df.columns:
            user_ips = self.logs_df.groupby('user_principal_name')['ip_address'].nunique()
            suspicious_users = user_ips[user_ips > 3]
            
            if not suspicious_users.empty:
                patterns.append({
                    'type': 'MULTIPLE_IP_ADDRESSES',
                    'users': [{'user': user, 'ip_count': count} 
                             for user, count in suspicious_users.items()],
                    'severity': 'HIGH'
                })
        
        # Analisa falhas de acesso consecutivas
        if 'result_type' in self.logs_df.columns:
            failed_attempts = self.logs_df[self.logs_df['result_type'] == 'Failure']
            if not failed_attempts.empty:
                user_failures = failed_attempts['user_principal_name'].value_counts()
                high_failure_users = user_failures[user_failures > 5]
                
                if not high_failure_users.empty:
                    patterns.append({
                        'type': 'EXCESSIVE_FAILED_ATTEMPTS',
                        'users': [{'user': user, 'failures': count} 
                                 for user, count in high_failure_users.items()],
                        'severity': 'HIGH'
                    })
        
        return {
            "critical_patterns": patterns,
            "total_patterns": len(patterns)
        }
    
    def analyze_orphaned_accounts(self) -> Dict[str, Any]:
        """Identifica contas órfãs ou dormentes."""
        if self.logs_df is None or self.logs_df.empty:
            return {"orphaned_accounts": [], "total_count": 0}
        
        orphaned_accounts = []
        
        # Identifica usuários com atividade muito baixa
        if 'user_principal_name' in self.logs_df.columns and 'timestamp' in self.logs_df.columns:
            user_activity = self.logs_df.groupby('user_principal_name').agg({
                'timestamp': ['count', 'max'],
                'operation_name': 'nunique'
            }).reset_index()
            
            user_activity.columns = ['user', 'activity_count', 'last_activity', 'unique_operations']
            
            # Usuários com atividade muito baixa (menos de 5 eventos)
            low_activity_users = user_activity[user_activity['activity_count'] < 5]
            
            for _, row in low_activity_users.iterrows():
                orphaned_accounts.append({
                    'user': row['user'],
                    'activity_count': row['activity_count'],
                    'last_activity': row['last_activity'].isoformat() if pd.notna(row['last_activity']) else 'N/A',
                    'unique_operations': row['unique_operations'],
                    'risk_reason': 'Low activity account - potential orphaned account'
                })
        
        return {
            "orphaned_accounts": orphaned_accounts,
            "total_count": len(orphaned_accounts)
        }
    
    def analyze_privilege_escalation_patterns(self) -> Dict[str, Any]:
        """Detecta padrões de escalação de privilégios."""
        if self.role_assignments_df is None or self.role_assignments_df.empty:
            return {"escalation_patterns": [], "total_patterns": 0}
        
        escalation_patterns = []
        
        # Ordena por usuário e timestamp
        if 'timestamp' in self.role_assignments_df.columns:
            sorted_assignments = self.role_assignments_df.sort_values(['user_principal_name', 'timestamp'])
            
            # Analisa sequências de atribuições para cada usuário
            for user in sorted_assignments['user_principal_name'].unique():
                if pd.isna(user):
                    continue
                    
                user_assignments = sorted_assignments[sorted_assignments['user_principal_name'] == user]
                
                # Verifica se há progressão para roles mais privilegiadas
                role_sequence = user_assignments['role_name'].tolist()
                
                # Detecta se usuário recebeu múltiplas roles administrativas em sequência
                admin_roles_received = [role for role in role_sequence if role in self.privileged_roles]
                
                if len(admin_roles_received) > 1:
                    # Calcula intervalo entre atribuições
                    timestamps = user_assignments['timestamp'].dropna()
                    if len(timestamps) > 1:
                        time_diff = (timestamps.iloc[-1] - timestamps.iloc[0]).total_seconds() / 3600  # horas
                        
                        if time_diff < 24:  # Múltiplas roles em menos de 24 horas
                            escalation_patterns.append({
                                'user': user,
                                'roles_sequence': role_sequence,
                                'admin_roles': admin_roles_received,
                                'time_span_hours': time_diff,
                                'severity': 'HIGH' if time_diff < 1 else 'MEDIUM',
                                'description': f'Escalação rápida de privilégios: {len(admin_roles_received)} roles administrativas em {time_diff:.1f} horas'
                            })
        
        return {
            "escalation_patterns": escalation_patterns,
            "total_patterns": len(escalation_patterns)
        }
    
    def analyze_cross_tenant_activities(self) -> Dict[str, Any]:
        """Analisa atividades cross-tenant suspeitas."""
        if self.logs_df is None or self.logs_df.empty:
            return {"cross_tenant_activities": [], "total_activities": 0}
        
        cross_tenant_activities = []
        
        # Procura por indicadores de atividade cross-tenant
        if 'properties' in self.logs_df.columns:
            cross_tenant_indicators = [
                'cross-tenant', 'external-tenant', 'guest-user', 
                'B2B', 'external-directory'
            ]
            
            for _, row in self.logs_df.iterrows():
                props_str = str(row.get('properties', '')).lower()
                
                for indicator in cross_tenant_indicators:
                    if indicator in props_str:
                        cross_tenant_activities.append({
                            'user': row.get('user_principal_name', 'Unknown'),
                            'operation': row.get('operation_name', 'Unknown'),
                            'timestamp': row.get('timestamp'),
                            'indicator': indicator,
                            'ip_address': row.get('ip_address', 'Unknown'),
                            'severity': 'MEDIUM',
                            'description': f'Atividade cross-tenant detectada: {indicator}'
                        })
                        break
        
        return {
            "cross_tenant_activities": cross_tenant_activities,
            "total_activities": len(cross_tenant_activities)
        }
    
    def analyze_service_principal_risks(self) -> Dict[str, Any]:
        """Analisa riscos relacionados a Service Principals."""
        if self.logs_df is None or self.logs_df.empty:
            return {"sp_risks": [], "total_risks": 0}
        
        sp_risks = []
        
        # Identifica atividades de Service Principals
        sp_activities = self.logs_df[
            self.logs_df['user_principal_name'].str.contains('ServicePrincipal', na=False) |
            self.logs_df['user_principal_name'].str.contains('@', na=False) == False
        ]
        
        if not sp_activities.empty:
            # Analisa Service Principals com atividade excessiva
            sp_activity_counts = sp_activities['user_principal_name'].value_counts()
            
            for sp, count in sp_activity_counts.items():
                if count > 100:  # Threshold configurável
                    sp_operations = sp_activities[sp_activities['user_principal_name'] == sp]['operation_name'].unique()
                    
                    sp_risks.append({
                        'service_principal': sp,
                        'activity_count': count,
                        'unique_operations': len(sp_operations),
                        'operations': sp_operations.tolist()[:10],  # Top 10 operações
                        'severity': 'HIGH' if count > 500 else 'MEDIUM',
                        'description': f'Service Principal com atividade excessiva: {count} operações'
                    })
        
        return {
            "sp_risks": sp_risks,
            "total_risks": len(sp_risks)
        }
    
    def generate_comprehensive_summary(self) -> Dict[str, Any]:
        """Gera um resumo abrangente de todas as análises."""
        if self.logs_df is None:
            return {}
        
        # Análises existentes
        direct_assignments = self.analyze_direct_user_assignments()
        conflicts = self.analyze_permission_conflicts()
        duplicates = self.analyze_duplicate_group_permissions()
        critical_patterns = self.analyze_critical_access_patterns()
        
        # Novas análises avançadas
        orphaned_accounts = self.analyze_orphaned_accounts()
        escalation_patterns = self.analyze_privilege_escalation_patterns()
        cross_tenant = self.analyze_cross_tenant_activities()
        sp_risks = self.analyze_service_principal_risks()
        
        return {
            'total_events': len(self.logs_df),
            'role_assignment_events': len(self.role_assignments_df) if self.role_assignments_df is not None else 0,
            'unique_users': self.logs_df['user_principal_name'].nunique() if 'user_principal_name' in self.logs_df.columns else 0,
            'time_range': {
                'start': self.logs_df['timestamp'].min().isoformat() if 'timestamp' in self.logs_df.columns and not self.logs_df['timestamp'].isna().all() else 'N/A',
                'end': self.logs_df['timestamp'].max().isoformat() if 'timestamp' in self.logs_df.columns and not self.logs_df['timestamp'].isna().all() else 'N/A'
            },
            'governance_issues': {
                'direct_assignments': direct_assignments['total_count'],
                'permission_conflicts': conflicts['total_conflicts'],
                'sod_violations': conflicts.get('sod_violations', 0),
                'duplicate_groups': duplicates['total_duplicates'],
                'critical_patterns': critical_patterns['total_patterns'],
                'orphaned_accounts': orphaned_accounts['total_count'],
                'escalation_patterns': escalation_patterns['total_patterns'],
                'cross_tenant_activities': cross_tenant['total_activities'],
                'service_principal_risks': sp_risks['total_risks']
            },
            'detailed_analysis': {
                'direct_assignments': direct_assignments,
                'conflicts': conflicts,
                'duplicates': duplicates,
                'critical_patterns': critical_patterns,
                'orphaned_accounts': orphaned_accounts,
                'escalation_patterns': escalation_patterns,
                'cross_tenant_activities': cross_tenant,
                'service_principal_risks': sp_risks
            }
        }
    
    def generate_governance_metrics(self) -> Dict[str, Any]:
        """Gera métricas específicas para dashboards de governança."""
        summary = self.generate_comprehensive_summary()
        
        # Calcula scores e KPIs
        total_issues = sum(summary.get('governance_issues', {}).values())
        total_users = summary.get('unique_users', 1)
        
        # Score de governança (0-100, onde 100 é perfeito)
        governance_score = max(0, 100 - (total_issues * 2))
        
        # Densidade de problemas (problemas por usuário)
        issue_density = total_issues / total_users if total_users > 0 else 0
        
        return {
            'governance_score': governance_score,
            'total_issues': total_issues,
            'issue_density': issue_density,
            'critical_sod_violations': summary.get('governance_issues', {}).get('sod_violations', 0),
            'high_risk_patterns': (
                summary.get('governance_issues', {}).get('escalation_patterns', 0) +
                summary.get('governance_issues', {}).get('cross_tenant_activities', 0)
            ),
            'compliance_risk_level': self._calculate_compliance_risk_level(summary),
            'recommended_actions': self._generate_recommended_actions(summary)
        }
    
    def _calculate_compliance_risk_level(self, summary: Dict[str, Any]) -> str:
        """Calcula o nível de risco de compliance baseado nos achados."""
        issues = summary.get('governance_issues', {})
        
        sod_violations = issues.get('sod_violations', 0)
        escalation_patterns = issues.get('escalation_patterns', 0)
        direct_assignments = issues.get('direct_assignments', 0)
        
        if sod_violations > 0 or escalation_patterns > 2:
            return "CRITICAL"
        elif direct_assignments > 10 or issues.get('critical_patterns', 0) > 5:
            return "HIGH"
        elif sum(issues.values()) > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommended_actions(self, summary: Dict[str, Any]) -> List[str]:
        """Gera ações recomendadas baseadas nos achados."""
        actions = []
        issues = summary.get('governance_issues', {})
        
        if issues.get('sod_violations', 0) > 0:
            actions.append("URGENTE: Remediar violações de segregação de funções")
        
        if issues.get('escalation_patterns', 0) > 0:
            actions.append("Revisar padrões de escalação de privilégios")
        
        if issues.get('direct_assignments', 0) > 5:
            actions.append("Migrar atribuições diretas para modelo baseado em grupos")
        
        if issues.get('orphaned_accounts', 0) > 0:
            actions.append("Revisar e desativar contas órfãs")
        
        if issues.get('service_principal_risks', 0) > 0:
            actions.append("Auditar Service Principals com atividade suspeita")
        
        if not actions:
            actions.append("Manter monitoramento contínuo de governança")
        
        return actions[:5]  # Máximo 5 ações
    
    def export_detailed_findings(self) -> Dict[str, Any]:
        """Exporta todos os achados em formato detalhado para relatórios."""
        summary = self.generate_comprehensive_summary()
        
        return {
            'summary': summary,
            'metrics': self.generate_governance_metrics(),
            'timestamp': pd.Timestamp.now().isoformat(),
            'analysis_scope': {
                'total_logs': len(self.logs_df) if self.logs_df is not None else 0,
                'date_range': summary.get('time_range', {}),
                'unique_users': summary.get('unique_users', 0)
            }
        }