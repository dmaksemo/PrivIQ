# test_new_format.py
"""
Teste rápido para validar o novo formato de logs.
"""

import json
import sys
import os

# Adiciona o diretório atual ao path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from data_processor import AzureLogProcessor

def test_new_format():
    """Testa o novo formato de logs."""
    sample_logs = [
        {
            "RoleAssignmentId": "4b92e023-6ca7-4087-8bfa-59aab4f5fb72",
            "Scope": "/subscriptions/1522326f-c8af-4a00-8f44-428ad65687ba",
            "DisplayName": "derlan teste",
            "SignInName": "derlan.teste@vanderlango2010hotmail.onmicrosoft.com",
            "RoleDefinitionName": "Contribuidor",
            "RoleDefinitionId": "/subscriptions/1522326f-c8af-4a00-8f44-428ad65687ba/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
            "ObjectId": "865c6564-5fa7-4023-bd93-e791e191ca2e",
            "ObjectType": "User",
            "RoleAssignmentDescription": "",
            "ConditionVersion": "",
            "Condition": ""
        },
        {
            "RoleAssignmentId": "d6b47238-c03b-40aa-8cde-ba0c51b58e59",
            "Scope": "/subscriptions/1522326f-c8af-4a00-8f44-428ad65687ba",
            "DisplayName": "grupoteste01",
            "SignInName": "",
            "RoleDefinitionName": "Admin de Segurança",
            "RoleDefinitionId": "/subscriptions/1522326f-c8af-4a00-8f44-428ad65687ba/providers/Microsoft.Authorization/roleDefinitions/fb1c8493-542b-48eb-b624-b4c8fea62acd",
            "ObjectId": "27ee59e7-954f-474d-9f2d-eedc388b6060",
            "ObjectType": "Group",
            "RoleAssignmentDescription": "",
            "ConditionVersion": "",
            "Condition": ""
        }
    ]
    
    print("🧪 Testando novo formato de logs...")
    
    processor = AzureLogProcessor()
    
    try:
        # Testa carregamento
        logs_json = json.dumps(sample_logs)
        df = processor.load_logs_from_file(logs_json)
        print(f"✅ Logs carregados: {len(df)} eventos")
        print(f"   Colunas: {list(df.columns)}")
        
        # Testa mapeamento de colunas
        if 'user_principal_name' in df.columns:
            print(f"✅ Mapeamento funcionando: user_principal_name disponível")
            print(f"   Valores: {df['user_principal_name'].tolist()}")
        
        # Testa análise de atribuições diretas
        direct_analysis = processor.analyze_direct_user_assignments()
        print(f"✅ Análise de atribuições diretas: {direct_analysis['total_count']} encontradas")
        
        # Testa análise de conflitos
        conflicts = processor.analyze_permission_conflicts()
        print(f"✅ Análise de conflitos: {conflicts['total_conflicts']} conflitos")
        
        # Testa análise de grupos
        groups = processor.analyze_duplicate_group_permissions()
        print(f"✅ Análise de grupos: {groups['total_duplicates']} duplicatas")
        
        # Testa resumo completo
        summary = processor.generate_comprehensive_summary()
        print(f"✅ Resumo gerado com {summary['total_events']} eventos")
        print(f"   Issues de governança: {summary['governance_issues']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_new_format()
    print("\n" + "="*50)
    if success:
        print("✅ TESTE CONCLUÍDO COM SUCESSO!")
        print("O sistema agora suporta o novo formato de logs.")
    else:
        print("❌ TESTE FALHOU!")
    print("="*50)