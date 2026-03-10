import json
import logging

import requests
from requests.auth import HTTPBasicAuth

from core.config import settings

logger = logging.getLogger(__name__)

protocol = settings.WAZUH_SERVER_API_PROTOCOL
host = settings.WAZUH_SERVER_API_HOST
port = settings.WAZUH_INDEXER_PORT
username = settings.WAZUH_INDEXER_USER
password = settings.WAZUH_INDEXER_PASSWORD


def count_agent_alerts(agent_id, starttime="now-24h", endtime="now"):

    logger.info("Getting the number of alerts information")

    url = f"{protocol}://{host}:{port}/wazuh-alerts-*/_count"
    payload = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.id": agent_id}},
                    {"range": {"timestamp": {"gte": starttime, "lte": endtime}}},
                ]
            }
        }
    }

    response = requests.post(
        url, auth=HTTPBasicAuth(username, password), json=payload, verify=False, timeout=10
    )

    logger.info("Get the number of alerts successfully")
    return response.json()


def agent_alerts(agent_id, x_limit=5, ruleId=-1):
    logger.info("Getting alerts information")

    url = f"{protocol}://{host}:{port}/wazuh-alerts-*/_search"
    headers = {"Content-Type": "application/json"}

    # 1. 初始化基础查询：必须匹配特定的 Agent ID
    must_conditions = [{"term": {"agent.id": agent_id}}]

    # 2. 如果提供了 ruleId，则动态追加过滤条件
    if ruleId != -1:
        must_conditions.append({"term": {"rule.id": str(ruleId)}})

    # 3. 构建完整的 DSL Payload
    payload = {
        "size": x_limit,
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        headers=headers,
        data=json.dumps(payload),
        verify=False,
    )

    logger.info(f"Get alerts response from Agent: {agent_id} successfully")
    return response.json()

def agent_archives(agent_id, keyword="", x_limit=5, payload=None):
    logger.info("Getting archives information")
    
    url = f"https://{host}:9200/wazuh-archives-*/_search"
    headers = {"Content-Type": "application/json"}

    if payload is None:
        # 1. 初始化基础查询：必须匹配特定的 Agent ID
        must_conditions = [{"term": {"agent.id": agent_id}}]

        # 追加关键词搜索功能
        if keyword and (keyword != ""):
            # 自动添加通配符以支持模糊匹配
            # 注意：如果使用通配符，不要在 query string 外面加双引号，否则会被视为短语匹配，通配符将失效
            if not keyword.startswith('*'):
                search_query = f'*{keyword}*'
                must_conditions.append({
                    "query_string": {
                        "query": f"{search_query}" # 去掉双引号
                    }
                })
            else:
                # 如果用户自己带了通配符，直接使用
                must_conditions.append({
                    "query_string": {
                        "query": f"{keyword}"
                    }
                })

        # 3. 构建完整的 DSL Payload
        payload = {
            "size": x_limit,
            "query": {"bool": {"must": must_conditions}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }

    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        headers=headers,
        data=json.dumps(payload),
        verify=False,
    )
    
    logger.info(f"Get archives  rom Agent: {agent_id} successfully")
    return response.json()

if __name__ == "__main__":
    # 测试 count_agent_alerts
    print(f"最近 1 小时告警数: {count_agent_alerts('001', 'now-1h', 'now')}")

    # 测试 agent_alerts
    # 查询ID为004的Agent中规则ID为5764的告警
    search_response = agent_alerts("004", x_limit=3, ruleId=5764)
    hits = search_response.get("hits", {}).get("hits", [])
    alerts = [hit["_source"] for hit in hits]
    print(f"\n获取到 {len(alerts)} 条告警:")
    for i, alert in enumerate(alerts):
        print("*" * 20)
        print(f"告警 #{i + 1}")
        print(f"时间戳：{alert.get('predecoder',{}).get('timestamp')}")
        print(f"规则 ID: {alert.get('rule',{}).get('id')}")
        print(f"描述: {alert.get('rule', {}).get('description')}")

    # 测试 agent_archives
    search_keyword = "whoami"
    search_response = agent_archives("005", keyword=search_keyword, x_limit=1)
    hits = search_response.get("hits", {}).get("hits", [])
    archives = [hit["_source"] for hit in hits]
    print(f"\n获取到 {len(archives)} 条归档记录:")
    for i, archive in enumerate(archives):
        print("*" * 20)
        print(f"归档记录 #{i + 1}")
        print(f"时间戳：{archive.get('timestamp')}")
        print(f"规则 ID: {archive.get('rule',{}).get('id')}")
        print(f"描述: {archive.get('rule', {}).get('description')}")