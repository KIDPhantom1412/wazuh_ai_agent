import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv  # 引入 dotenv

# 加载 .env 文件
load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 从环境变量读取配置 ---
# 使用 os.getenv('变量名', '默认值')
WAZUH_PROTOCOL = os.getenv("VITE_WAZUH_SERVER_API_PROTOCOL", "https")
WAZUH_HOST = os.getenv("VITE_WAZUH_SERVER_API_HOST", "127.0.0.1")
WAZUH_PORT = os.getenv("VITE_WAZUH_SERVER_API_PORT", "55000")
WAZUH_URL = f"{WAZUH_PROTOCOL}://{WAZUH_HOST}:{WAZUH_PORT}"

INDEXER_HOST = os.getenv("VITE_WAZUH_SERVER_API_HOST", "127.0.0.1")
INDEXER_PORT = os.getenv("VITE_WAZUH_INDEXER_PORT", "9200")
INDEXER_URL = f"https://{INDEXER_HOST}:{INDEXER_PORT}"

USER = os.getenv("VITE_WAZUH_SERVER_API_USERNAME")
PASSWORD = os.getenv("VITE_WAZUH_SERVER_API_PASSWORD")

INDEXER_USER = os.getenv("VITE_WAZUH_INDEXER_USER")
INDEXER_PASS = os.getenv("VITE_WAZUH_INDEXER_PASSWORD")
INDEXER_AUTH = (INDEXER_USER, INDEXER_PASS)
# -----------------------

def get_wazuh_token():
    auth_url = f"{WAZUH_URL}/security/user/authenticate"
    # 注意：verify=False 是因为 Wazuh 默认使用自签名证书
    res = requests.get(auth_url, auth=(USER, PASSWORD), verify=False)
    res.raise_for_status() # 如果登录失败抛出异常
    return res.json()['data']['token']

@app.get("/api/topo")
async def get_topo():
    try:
        token = get_wazuh_token()
        headers = {'Authorization': f'Bearer {token}'}
        
        # 1. 获取 Agents
        agents_res = requests.get(f"{WAZUH_URL}/agents?limit=100", headers=headers, verify=False)
        agents = agents_res.json()['data']['affected_items']
        
        # 2. 获取告警 (近30分钟)
        time_start = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        query_body = {
            "size": 500,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 10}}},
                        {"range": {"timestamp": {"gte": time_start}}}
                    ]
                }
            }
        }
        alerts_res = requests.post(f"{INDEXER_URL}/wazuh-alerts-*/_search", json=query_body, auth=INDEXER_AUTH, verify=False)
        alerts_hits = alerts_res.json().get('hits', {}).get('hits', [])

        # 3. 聚合逻辑
        alert_map = {}
        for hit in alerts_hits:
            alert = hit['_source']
            aid = alert.get('agent', {}).get('id')
            if aid:
                level = alert['rule']['level']
                if aid not in alert_map or level > alert_map[aid]['level']:
                    alert_map[aid] = {"level": level, "description": alert['rule']['description']}

        # 4. 组装数据
        nodes = []
        for agent in agents:
            aid = agent['id']
            threat = alert_map.get(aid)
            nodes.append({
                "id": aid,
                "name": agent['name'],
                "ip": agent.get('ip', 'unknown'),
                "status": agent['status'],
                "has_threat": True if threat else False,
                "threat_info": threat['description'] if threat else "",
                "threat_level": threat['level'] if threat else 0
            })
        
        return nodes
    except Exception as e:
        print(f"Error fetching topo: {e}") # 后端打印一下具体的错误
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)