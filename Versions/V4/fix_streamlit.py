#!/usr/bin/env python3
"""
Script para corrigir warnings do Streamlit substituindo use_container_width por width
"""

def fix_streamlit_warnings():
    """Substitui use_container_width=True por width='stretch' no app.py"""
    
    # Ler o arquivo
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fazer as substituições
    content = content.replace('use_container_width=True', "width='stretch'")
    
    # Escrever o arquivo corrigido
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ Substituições realizadas com sucesso!")
    print("- use_container_width=True → width='stretch'")

if __name__ == "__main__":
    fix_streamlit_warnings()