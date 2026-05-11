import httpx
from langchain_openai import ChatOpenAI

from agents.attack_attribution.attack_attributor import get_attack_attribution_agent
from agents.demo_agent import get_demo_agent
from agents.indexer_agent import get_indexer_agent
from agents.rule_generator.rule_generator import get_rule_generator_agent
from core.config import settings
from core.model_configs import get_model_kwargs

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

llm_attribution_params = {
    "model": settings.TEST_LLM_MODEL,
    "api_key": settings.TEST_LLM_API_KEY,
    "base_url": settings.TEST_LLM_BASE_URL,
    "http_client": custom_http_client,
}

special_kwargs = get_model_kwargs(settings.TEST_LLM_MODEL)
if special_kwargs:
    llm_attribution_params["model_kwargs"] = special_kwargs

model_attribution = ChatOpenAI(**llm_attribution_params)

demo_agent = get_demo_agent(model)
indexer_agent = get_indexer_agent(model)
rule_generator = get_rule_generator_agent(model)
attack_attributor = get_attack_attribution_agent(model_attribution)
