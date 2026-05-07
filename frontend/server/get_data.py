from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import urllib3
from datetime import datetime, timedelta, timezone

app = FastAPI()

# 允许跨域，方便前端调用
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置保持不变
WAZUH_URL = "https://192.168.74.130:55000"
INDEXER_URL = "https://192.168.74.130:9200"
USER = "wazuh"
PASSWORD = "OaOl0*64+.eFxzmBsBe5t8*G9xxEY5ye"
INDEXER_AUTH = ("admin", "It2bqmagNT.hxelVM9BrhnKwAZ?5Iz6S")

def get_wazuh_token():
    auth_url = f"{WAZUH_URL}/security/user/authenticate"
    res = requests.get(auth_url, auth=(USER, PASSWORD), verify=False)
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
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)