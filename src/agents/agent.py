from langchain_openai import ChatOpenAI

from agents.demo_agent import get_demo_agent
from agents.indexer_agent import get_indexer_agent
from core.config import settings

model = ChatOpenAI(
    model=settings.TEST_LLM_MODEL,
    api_key=settings.TEST_LLM_API_KEY,
    base_url=settings.TEST_LLM_BASE_URL,
)

demo_agent = get_demo_agent(model)
indexer_agent = get_indexer_agent(model)
