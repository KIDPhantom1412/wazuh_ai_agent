import logging
from functools import partial

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, StateGraph

# 导入所有定义好的节点
from .nodes import (
    attribution_planner_node,
    information_synthesizer_node,
    log_retrieval_node,
    mitre_expert_node,
    reporter_node,
    user_input_node,
)
from .state import AttributionState

logger = logging.getLogger(__name__)


# 定义条件路由函数


def route_planner(state: AttributionState) -> str:
    """attribution_planner_node节点的出口路由"""
    next_action = state.get("next_action")
    if not next_action:
        logger.warning(
            "Planner returned no next_action. Ending workflow to prevent infinite loops."
        )
        return END

    target = next_action.get("target")
    if target in ["Log_Retrieval_Node", "MITRE_Expert_Node", "User_Input_Node", "Reporter_Node"]:
        return target
    else:
        logger.error(f"Unknown target route: {target}. Ending workflow.")
        return END


def route_user_input(state: AttributionState) -> str:
    """user_input_node节点的出口路由"""
    requires_mitre = state.get("requires_mitre_kb")
    if requires_mitre is None:
        logger.info("Graph suspended. Waiting for human response on UI...")
        return END
    else:
        logger.info("Human response parsed. Returning control to Planner...")
        return "Attribution_Planner_Node"


# 构建图
def get_attack_attribution_agent(model: BaseChatModel):
    """
    Creates the Attack Attribution Agent Graph.
    Args:
        model: The language model to use.
    Returns:
        A compiled LangGraph runnable.
    """
    logger.info("Building Attack Attribution Graph...")

    # 初始化状态图
    graph = StateGraph(AttributionState)

    graph.add_node("Attribution_Planner_Node", partial(attribution_planner_node, model=model))
    graph.add_node("Log_Retrieval_Node", partial(log_retrieval_node, model=model))
    graph.add_node(
        "Information_Synthesizer_Node", partial(information_synthesizer_node, model=model)
    )
    graph.add_node("MITRE_Expert_Node", partial(mitre_expert_node, model=model))
    graph.add_node("Reporter_Node", partial(reporter_node, model=model))
    graph.add_node("User_Input_Node", partial(user_input_node, model=model))

    graph.set_entry_point("Attribution_Planner_Node")

    graph.add_conditional_edges(
        "Attribution_Planner_Node",
        route_planner,
        {
            "Log_Retrieval_Node": "Log_Retrieval_Node",
            "MITRE_Expert_Node": "MITRE_Expert_Node",
            "User_Input_Node": "User_Input_Node",
            "Reporter_Node": "Reporter_Node",
            END: END,
        },
    )
    graph.add_conditional_edges(
        "User_Input_Node",
        route_user_input,
        {"Attribution_Planner_Node": "Attribution_Planner_Node", END: END},
    )

    graph.add_edge("Log_Retrieval_Node", "Information_Synthesizer_Node")
    graph.add_edge("Information_Synthesizer_Node", "Attribution_Planner_Node")
    graph.add_edge("MITRE_Expert_Node", "Attribution_Planner_Node")
    graph.add_edge("Reporter_Node", END)

    app = graph.compile()

    logger.info("Attribution Graph successfully compiled!")
    return app.with_config({"configurable": {"model": model}})
