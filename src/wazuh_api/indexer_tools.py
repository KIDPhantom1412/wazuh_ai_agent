import json
import logging
import os

os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

import requests
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings

# from langchain_pinecone import PineconeVectorStore
from langchain_pinecone import Pinecone as PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec
from requests.auth import HTTPBasicAuth

from core.config import settings

logger = logging.getLogger(__name__)

protocol = settings.WAZUH_SERVER_API_PROTOCOL
host = settings.WAZUH_SERVER_API_HOST
port = settings.WAZUH_INDEXER_PORT
username = settings.WAZUH_INDEXER_USER
password = settings.WAZUH_INDEXER_PASSWORD
PINECONE_API_KEY = settings.PINECONE_API_KEY
os.environ["PINECONE_API_KEY"] = settings.PINECONE_API_KEY

LOG_FILE = r"src/rag/log1.json"
KB_FILE = r"src/rag/rag0.json"


embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Pinecone 索引配置
INDEX_NAME = "wazuh-response-index"
DIMENSION = 384  # 对应 all-MiniLM-L6-v2 的维度


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
    return response.json().get("count", 0)


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

    search_results = response.json()
    hits = search_results.get("hits", {}).get("hits", [])
    alerts = [hit["_source"] for hit in hits]

    logger.info(f"Get {len(alerts)}  alerts from Agent: {agent_id} successfully")
    return alerts


def load_knowledge_base():
    """
    加载知识库文件并转换为可嵌入的文档
    """
    logger.info("loading knowledge base……")

    with open(KB_FILE, encoding="utf-8") as f:
        kb_data = json.load(f)

    # 转换为 Document 对象
    documents = []
    for item in kb_data:
        content = f"OS: {item.get('os', 'Unknown')}\n"
        content += f"Category: {item.get('category', 'Unknown')}\n"
        content += f"Scenario: {item.get('scenario', 'Unknown')}\n"
        content += f"Tool: {item.get('tool', 'Unknown')}\n"
        content += f"Command: {item.get('command', 'Unknown')}\n"
        content += f"Description: {item.get('desc', 'Unknown')}"

        documents.append(
            Document(
                page_content=content,
                metadata={
                    "os": item.get("os", "Unknown"),
                    "category": item.get("category", "Unknown"),
                    "scenario": item.get("scenario", "Unknown"),
                    "tool": item.get("tool", "Unknown"),
                },
            )
        )

    logger.info(f"successfully load knowledge base : {len(documents)} records totally")
    return documents


def init_pinecone_index():
    """
    初始化 Pinecone 索引
    """
    logger.info("init pinecone_index")

    # 初始化 Pinecone
    pc = Pinecone(api_key=PINECONE_API_KEY)

    # 检查索引是否存在
    existing_indexes = [idx.name for idx in pc.list_indexes()]

    if INDEX_NAME in existing_indexes:
        logger.info("use existing pinecone_index")
        index = pc.Index(INDEX_NAME)
    else:
        logger.info("create new pinecone_index")
        pc.create_index(
            name=INDEX_NAME,
            dimension=DIMENSION,
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )
        index = pc.Index(INDEX_NAME)

    # 获取索引统计
    stats = index.describe_index_stats()
    logger.info(f"Index statistics: Vector count = {stats.get('total_vector_count', 0)}")

    return index


def setup_vectorstore(documents):
    """
    设置向量存储
    """
    logger.info("set up vectorstore")

    # 检查索引是否存在
    pc = Pinecone(api_key=PINECONE_API_KEY)
    existing_indexes = [idx.name for idx in pc.list_indexes()]

    if INDEX_NAME not in existing_indexes:
        init_pinecone_index()

    # 创建向量存储
    vectorstore = PineconeVectorStore.from_documents(
        documents=documents,
        embedding=embeddings,
        index_name=INDEX_NAME,
    )

    logger.info("successfully set up vectorstore")
    return vectorstore


if __name__ == "__main__":
    # 测试count_agent_alerts
    print(f"最近 1 小时告警数: {count_agent_alerts('001', 'now-1h', 'now')}")

    # 测试agent_alerts()
    # 查询ID为004的Agent中规则ID为5764的告警
    ssh_alerts = agent_alerts("004", x_limit=3, ruleId=5764)
    # for i, alert in enumerate(ssh_alerts):
    #     print('*' * 20)
    #     print(f"\n--- 告警 #{i + 1} ---")
    #     print(f"时间戳：{alert.get('predecoder',{}).get('timestamp')}")
    #     print(f"rule id: {alert.get('rule',{}).get('id')}")
    #     print(f"级别: {alert.get('rule', {}).get('level')}")
    #     print(f"描述: {alert.get('rule', {}).get('description')}")
    #     print(f"alert:{alert}\n")
    print(ssh_alerts)

    # documents = load_knowledge_base()
    # vectorstore = setup_vectorstore(documents)
