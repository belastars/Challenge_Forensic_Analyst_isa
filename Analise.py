import os
import re
import json
import time
import pandas as pd
import requests

# =====================================================================
# CONFIGURAÇÃO DA CHAVE DE API DO GOOGLE GEMINI
# =====================================================================
# Dica de Segurança: Em produção, utilize variáveis de ambiente (.env)
os.environ["GOOGLE_API_KEY"] = "AQ.Ab8RN6K7jsR9a8JXl97NFMusLP01uHJUzoEicbBNHa0-81OClA"

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, ToolMessage

# =====================================================================
# FUNÇÃO AUXILIAR: GEOLOCALIZAÇÃO DE IPS COM CACHE
# =====================================================================

cache_paises_global = {}

def obter_pais_ip(ip: str) -> str:
    """Consulta o país de um IP utilizando cache local para evitar travamento de rede."""
    ip_str = str(ip).strip()
    if ip_str in cache_paises_global:
        return cache_paises_global[ip_str]
    
    try:
        res = requests.get(f"http://ip-api.com/json/{ip_str}?fields=country", timeout=1.5)
        if res.status_code == 200:
            pais = res.json().get("country", "Desconhecido")
            cache_paises_global[ip_str] = pais
            return pais
    except Exception:
        pass
    
    cache_paises_global[ip_str] = "Desconhecido"
    return "Desconhecido"

# =====================================================================
# 1. FERRAMENTAS (TOOLS)
# =====================================================================

@tool
def analisar_metricas_idor(arquivo_csv: str = "three_months.csv") -> str:
    """Analisar os logs no CSV focado na exploração IDOR no endpoint /invoices/search.
    Retorna estatísticas do Top 20 IPs, Top Países, Top AuthTokens, Faturas raspadas e Sites afetados.
    """
    if not os.path.exists(arquivo_csv):
        return f"Erro: Arquivo '{arquivo_csv}' não encontrado no diretório."
    
    try:
        df = pd.read_csv(arquivo_csv)
        logs_endpoint = df[df['http_uri'].str.contains('/invoices/search', na=False, case=False)].copy()
        
        if logs_endpoint.empty:
            return "Nenhuma requisição encontrada para o endpoint /invoices/search."
        
        # 1. Top 20 IPs com mais requisições
        top_ips_series = logs_endpoint['source_ip'].value_counts().head(20) if 'source_ip' in logs_endpoint.columns else pd.Series()
        top_ips = top_ips_series.to_dict()
        
        # 2. Top Países por trás desses IPs (usando a função com cache)
        top_paises = {}
        for ip in top_ips_series.index:
            pais = obter_pais_ip(str(ip))
            top_paises[pais] = top_paises.get(pais, 0) + int(top_ips_series[ip])
        
        # 3. Top 10 AuthTokens utilizados
        tokens = logs_endpoint['http_uri'].str.extract(r'(?:token|auth|bearer|authtoken)=([^&]+)', flags=re.IGNORECASE)[0].dropna()
        top_tokens = tokens.value_counts().head(10).to_dict() if not tokens.empty else {}
        
        # 4. Total de faturas / invoice_id acessados
        invoices = logs_endpoint['http_uri'].str.extract(r'(?:invoice_id|invoice|id)=([a-zA-Z0-9_-]+)', flags=re.IGNORECASE)[0].dropna()
        total_invoices = int(invoices.nunique()) if not invoices.empty else 0
        
        # 5. Sites / Hosts mais afetados
        sites = logs_endpoint['http_host'].value_counts().to_dict() if 'http_host' in logs_endpoint.columns else {}
        
        return json.dumps({
            "total_requisicoes_idor": len(logs_endpoint),
            "top_20_ips_suspeitos": top_ips,
            "top_paises_origem": top_paises,
            "top_10_authtokens_utilizados": top_tokens,
            "faturas_unicas_acessadas": total_invoices,
            "sites_afetados": sites
        }, indent=2)
    except Exception as e:
        return f"Erro durante a análise do CSV: {str(e)}"

@tool
def construir_timeline_ataque(arquivo_csv: str = "three_months.csv") -> str:
    """Mapeia a linha do tempo do ataque IDOR, identificando a data/hora de início e fim."""
    if not os.path.exists(arquivo_csv):
        return f"Erro: Arquivo '{arquivo_csv}' não encontrado."
    
    try:
        df = pd.read_csv(arquivo_csv)
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        logs_endpoint = df[df['http_uri'].str.contains('/invoices/search', na=False, case=False)].dropna(subset=['timestamp'])
        
        if logs_endpoint.empty:
            return "Nenhuma atividade registrada no endpoint vulnerável."
        
        inicio = logs_endpoint['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S')
        fim = logs_endpoint['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        
        return json.dumps({
            "inicio_ataque": inicio,
            "fim_ataque": fim
        }, indent=2)
    except Exception as e:
        return f"Erro na timeline: {str(e)}"

# =====================================================================
# 2. CONFIGURAÇÃO E EXECUÇÃO DO AGENTE
# =====================================================================

tools = [analisar_metricas_idor, construir_timeline_ataque]

tools_by_name = {
    "analisar_metricas_idor": analisar_metricas_idor,
    "construir_timeline_ataque": construir_timeline_ataque
}

# Modelo configurado com max_retries para contornar limites de cota da API
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    temperature=0.2,
    max_retries=5
)

llm_with_tools = llm.bind_tools(tools)

def rodar_agente_forense(pergunta: str):
    print(f"\n🚀 Pergunta enviada ao Agente: {pergunta}\n")
    messages = [HumanMessage(content=pergunta)]
    
    resposta_ia = llm_with_tools.invoke(messages)
    messages.append(resposta_ia)
    
    if resposta_ia.tool_calls:
        for tool_call in resposta_ia.tool_calls:
            nome_tool = tool_call["name"].lower()
            if nome_tool in tools_by_name:
                print(f"🛠️ Executando ferramenta: {nome_tool}...")
                ferramenta = tools_by_name[nome_tool]
                
                resultado_tool = ferramenta.invoke(tool_call["args"])
                
                messages.append(ToolMessage(
                    content=str(resultado_tool), 
                    tool_call_id=tool_call["id"]
                ))
        
        # Pausa de segurança para cota da API gratuita
        time.sleep(10)
        
        resposta_final = llm_with_tools.invoke(messages)
        return resposta_final.content
    else:
        return resposta_ia.content

# =====================================================================
# 3. PONTO DE ENTRADA
# =====================================================================

if __name__ == "__main__":
    pergunta_investigativa = (
        "Analise o arquivo three_months.csv e responda detalhadamente às perguntas forenses:\n"
        "1. Qual o Top 20 de IPs com mais requisições no endpoint /invoices/search?\n"
        "2. Qual o Top de países por trás desses IPs?\n"
        "3. Qual o Top 10 de authtokens utilizados?\n"
        "4. Quantas faturas (invoice_id) únicas foram consultadas?\n"
        "5. Qual foi o site/host mais afetado?\n"
        "6. Qual a linha do tempo (timeline) de início e fim do incidente?"
    )
    
    parecer_final = rodar_agente_forense(pergunta_investigativa)
    
    print("\n=======================================================")
    print("📋 PARECER FORENSE FINAL DA IA (GEMINI)")
    print("=======================================================")
    print(parecer_final)