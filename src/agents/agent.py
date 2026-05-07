import httpx
from langchain_openai import ChatOpenAI

from agents.attack_attribution.attack_attributor import get_attack_attribution_agent
from agents.demo_agent import get_demo_agent
from agents.indexer_agent import get_indexer_agent
from core.config import settings

model = ChatOpenAI(
    model=settings.TEST_LLM_MODEL,
    api_key=settings.TEST_LLM_API_KEY,
    base_url=settings.TEST_LLM_BASE_URL,
)

# 自定义 HTTP 客户端，专门解决 chunked read 报错
custom_http_client = httpx.Client(
    timeout=httpx.Timeout(
        connect=30.0,
        read=180.0,  # 将读取超时延长至 3 分钟，给足大模型输出的时间
        write=30.0,
        pool=30.0,
    )
)

model_attribution = ChatOpenAI(
    model=settings.TEST_LLM_MODEL,
    api_key=settings.TEST_LLM_API_KEY,
    base_url=settings.TEST_LLM_BASE_URL,
    http_client=custom_http_client,
    model_kwargs={"extra_body": {"thinking": {"type": "disabled"}}},
)

demo_agent = get_demo_agent(model)
indexer_agent = get_indexer_agent(model)
attack_attributor = get_attack_attribution_agent(model_attribution)
