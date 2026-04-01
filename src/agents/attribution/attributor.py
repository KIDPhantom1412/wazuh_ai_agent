import logging
from functools import partial

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, StateGraph

from .state import AttributionState
from .nodes import investigation_node, report_generation_node

logger = logging.getLogger(__name__)


def get_attributor_agent(model: BaseChatModel, indexer_agent):
    """
    Creates the Attributor Agent Workflow Graph
    """
    logger.info("Building the Attributor Workflow Graph...")
    
    workflow = StateGraph(AttributionState)

    workflow.add_node(
        "investigation", 
        partial(investigation_node, model=model, indexer_agent=indexer_agent)
    )
    workflow.add_node(
        "report_generation", 
        partial(report_generation_node, model=model)
    )

    workflow.set_entry_point("investigation")
    workflow.add_edge("investigation", "report_generation")
    workflow.add_edge("report_generation", END)

    app = workflow.compile()
    
    return app.with_config({"configurable": {"model": model}})