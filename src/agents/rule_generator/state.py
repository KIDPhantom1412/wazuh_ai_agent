from typing import Annotated

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class RuleGeneratorState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    user_input_history: list[str] | None
    environment_info: str | None
    server_timestamp: str | None
    rule_requirements: dict | None
    missing_parameters: list[str] | None
    logs_preview: list[dict] | None
    raw_logs: list[dict] | None
    log_analysis: str | None
    is_feasible: bool | None
    infeasibility_reason: str | None
    generated_rule: str | None
    verification_rule_content: str | None
    temp_json_rule_ids: list[int] | None
    rule_id: int | None
    rule_filename: str | None
    validation_error: str | None
    last_validation_error: str | None
    logtest_passed: bool | None
    verification_feedback: str | None
    iteration_count: int
