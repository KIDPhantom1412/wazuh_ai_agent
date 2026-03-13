from langchain_openai import ChatOpenAI

from agents.attribution_agent import get_attribution_agent
from agents.demo_agent import get_demo_agent
from agents.indexer_agent import get_indexer_agent
from agents.response_agent import get_response_agent
from core.config import settings

model = ChatOpenAI(
    model=settings.TEST_LLM_MODEL,
    api_key=settings.TEST_LLM_API_KEY,
    base_url=settings.TEST_LLM_BASE_URL,
)

demo_agent = get_demo_agent(model)
indexer_agent = get_indexer_agent(model)
response_agent = get_response_agent(model)
attribution_agent = get_attribution_agent(model, indexer_agent)
