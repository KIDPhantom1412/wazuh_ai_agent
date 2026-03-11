import json
import logging
import os

from core.config import settings

os.environ["HF_ENDPOINT"] = settings.HF_ENDPOINT
os.environ["PINECONE_API_KEY"] = settings.PINECONE_API_KEY

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.documents import Document
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_pinecone import Pinecone as PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec

logger = logging.getLogger(__name__)

embeddings = HuggingFaceEmbeddings(model_name=settings.EMBEDDING_MODEL)
DIMENSION = settings.EMBEDDING_DIMENSION


def load_knowledge_base(KB_FILE):
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


def init_pinecone_index(index_name):
    """
    初始化 Pinecone 索引
    """
    logger.info(f"init pinecone_index: {index_name}")

    # 初始化 Pinecone
    pc = Pinecone(api_key=settings.PINECONE_API_KEY)

    # 检查索引是否存在
    existing_indexes = [idx.name for idx in pc.list_indexes()]

    if index_name in existing_indexes:
        logger.info("use existing pinecone_index")
        index = pc.Index(index_name)
    else:
        logger.info("create new pinecone_index")
        pc.create_index(
            name=index_name,
            dimension=DIMENSION,
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )
        index = pc.Index(index_name)

    # 获取索引统计
    stats = index.describe_index_stats()
    logger.info(f"Index statistics: Vector count = {stats.get('total_vector_count', 0)}")

    return index


def setup_vectorstore(documents, index_name):
    """
    设置向量存储
    """
    logger.info(f"set up vectorstore: {index_name}")

    # 检查索引是否存在
    pc = Pinecone(api_key=settings.PINECONE_API_KEY)
    existing_indexes = [idx.name for idx in pc.list_indexes()]

    if index_name not in existing_indexes:
        init_pinecone_index(index_name)

    # 创建向量存储
    vectorstore = PineconeVectorStore.from_documents(
        documents=documents,
        embedding=embeddings,
        index_name=index_name,
    )

    logger.info("successfully set up vectorstore")
    return vectorstore


system_prompt = """
You are a specialized Wazuh Incident Response Expert AI. Your sole purpose is to analyze security logs provided to you and recommend actionable response strategies.

### Operational Workflow:

**Step 1: Threat Evaluation**
When provided with a log, first evaluate if it indicates a genuine security threat or a "Benign Operational Activity".
- Check if the behavior aligns with normal system administrative tasks.
- **Rule Threshold:** If the Wazuh rule level is strictly less than 7 (< 7), or if the evidence strongly suggests benign intended functionality: Simply inform the user that it is an informational/benign event and NO response action is required. **DO NOT call any tools. Stop here.**

**Step 2: Knowledge Retrieval (For actual threats)**
If the log is a valid security threat (Level >= 7), you MUST call the `get_response_plan` tool. Construct your search query using key indicators from the log (e.g., Operating System, attack type, rule description).

**Step 3: Response Plan Generation**
Based strictly on the results from the knowledge base, generate a response plan. The plan MUST include the following sections:
- **Incident Analysis Summary**: A brief explanation of what happened.
- **Recommended Response Actions**: The specific mitigation steps. You MUST include specific executable commands retrieved from the knowledge base.
- **Execution Recommendations**: Advice on how to safely apply the fix (e.g., prioritizing verification over containment if dealing with critical system processes).

### Strict Constraints:
- Knowledge Base Prioritization: You MUST prioritize response strategies retrieved from the `get_response_plan` tool. However, if the retrieved results do not cover the specific attack scenario or lack sufficient detail, you may formulate a safe response plan based on your general cybersecurity expertise.
- **Dynamic Parameter Injection**: You MUST replace placeholders in the retrieved commands (such as <IP>, <USER>, <PROCESS_ID>) with the actual values extracted from the user's provided log.
- **OS Awareness**: Ensure the recommended tools and commands strictly match the target Operating System mentioned in the log.
"""


@tool
def get_response_plan(query: str) -> str:
    """
    在安全响应知识库中搜索相关信息
    用于根据攻击类型、操作系统等信息找到合适的安全响应措施
    :param query: 有关获取日志响应方案的的询问
    """
    KB_FILE = r"src/documents/rag/response_knowledgebase.json"
    index_name = "wazuh-response-index"
    documents = load_knowledge_base(KB_FILE)
    vectorstore = setup_vectorstore(documents, index_name)

    docs = vectorstore.similarity_search(query, k=3)
    results = []
    for i, doc in enumerate(docs, 1):
        results.append(f"结果 {i}:\n{doc.page_content}\n")
    return "\n".join(results)


def get_response_agent(model: BaseChatModel):
    return create_agent(
        model=model,
        tools=[get_response_plan],
        system_prompt=system_prompt,
    )


if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

    from core.config import settings

    model = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )
    response_agent = get_response_agent(model)

    # print("\n--- Q2: 获取告警 ---")
    # for chunk in indexer_agent.stream(
    #     {"messages": messages},
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")

    # messages = chunk["messages"]

    # print("\n--- Q3: 请求响应措施 ---")
    # messages.append({"role": "user", "content": "基于刚刚获取的告警日志，提供具体的安全响应措施"})
    #
    # for chunk in response_agent.stream(
    #     {"messages": messages},
    #     stream_mode="values",
    # ):
    #     latest_message = chunk["messages"][-1]
    #     if latest_message.content:
    #         print(f"Agent: {latest_message.content}")
    #     elif latest_message.tool_calls:
    #         print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")
