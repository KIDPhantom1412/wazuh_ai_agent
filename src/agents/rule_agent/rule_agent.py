from functools import partial

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, StateGraph

from agents.rule_agent.nodes import (
    cleanup_rule_node,
    decision_node,
    environment_perception_node,
    log_retrieval_feasibility_node,
    requirement_understanding_node,
    response_node,
    rule_generation_node,
    rule_query_node,
    rule_verification_node,
)
from agents.rule_agent.state import RuleGeneratorState


def get_rule_agent(model: BaseChatModel):
    """
    Creates the Rule Generator Agent Graph.
    Args:
        model: The language model to use.
    Returns:
        A compiled LangGraph runnable.
    """
    workflow = StateGraph(RuleGeneratorState)

    # Add nodes
    workflow.add_node("environment_perception", environment_perception_node)
    workflow.add_node("decision", partial(decision_node, model=model))
    workflow.add_node(
        "requirement_understanding", partial(requirement_understanding_node, model=model)
    )
    workflow.add_node(
        "log_retrieval_feasibility", partial(log_retrieval_feasibility_node, model=model)
    )
    workflow.add_node("rule_query", partial(rule_query_node, model=model))
    workflow.add_node("rule_generation", partial(rule_generation_node, model=model))
    workflow.add_node("rule_verification", partial(rule_verification_node, model=model))
    workflow.add_node("cleanup_rule", partial(cleanup_rule_node, model=model))
    workflow.add_node("response", partial(response_node, model=model))

    # Add edges
    # Start -> Decision (Router)
    workflow.set_entry_point("decision")

    # Environment Perception -> Requirement Understanding (S1 -> S2)
    workflow.add_edge("environment_perception", "requirement_understanding")

    # Decision Logic
    def router(state):
        decision = state.get("decision", "extract_requirements")
        if decision == "verify_rule":
            return "rule_verification"
        elif decision == "cancel_verification":
            return "response"
        elif decision == "keep_rule":
            return "response"  # Just acknowledge
        elif decision == "delete_rule":
            return "cleanup_rule"
        elif decision == "query_rule":
            return "rule_query"
        else:
            # If extracting requirements, first go to S1 (Environment Perception)
            return "environment_perception"

    workflow.add_conditional_edges(
        "decision",
        router,
        {
            "rule_verification": "rule_verification",
            "response": "response",
            "environment_perception": "environment_perception",
            "cleanup_rule": "cleanup_rule",
            "rule_query": "rule_query",
        },
    )

    # Cleanup Rule -> Response
    workflow.add_edge("cleanup_rule", "response")
    workflow.add_edge("rule_query", "response")

    # Requirement Understanding (S2)
    def check_missing_params(state):
        if state.get("missing_parameters"):
            return "response"  # Ask user
        return "log_retrieval_feasibility"

    workflow.add_conditional_edges(
        "requirement_understanding",
        check_missing_params,
        {"response": "response", "log_retrieval_feasibility": "log_retrieval_feasibility"},
    )

    # Log Retrieval & Feasibility (S3)
    def check_feasibility(state):
        if state.get("is_feasible") is False:
            return "response"  # Explain why
        return "rule_generation"

    workflow.add_conditional_edges(
        "log_retrieval_feasibility",
        check_feasibility,
        {"response": "response", "rule_generation": "rule_generation"},
    )

    # Rule Generation (S4) -> Response (Ask for verification permission)
    workflow.add_edge("rule_generation", "response")

    # Rule Verification (S5) -> Response (Report result)
    def check_verification(state):
        # If there's an error or logtest failed, we loop back to generation
        if state.get("validation_error") or (state.get("logtest_passed") is False):
            return "rule_generation"
        return "response"

    workflow.add_conditional_edges(
        "rule_verification",
        check_verification,
        {"rule_generation": "rule_generation", "response": "response"},
    )

    # Response -> END
    workflow.add_edge("response", END)

    # Compile the graph
    app = workflow.compile()

    # Bind the model to the config so nodes can access it
    return app.with_config({"configurable": {"model": model}})
