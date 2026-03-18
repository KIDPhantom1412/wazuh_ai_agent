from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class RuleGeneratorState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    environment_info: str | None
    rule_requirements: dict | None
    missing_parameters: list[str] | None
    logs: list[dict] | None
    log_analysis: str | None
    is_feasible: bool | None
    infeasibility_reason: str | None
    generated_rule: str | None
    rule_id: int | None
    rule_filename: str | None
    validation_error: str | None
    logtest_passed: bool | None
    verification_feedback: str | None
    iteration_count: int
