from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


def merge_kb(left: dict[str, str], right: dict[str, str]) -> dict[str, str]:
    """合并 MITRE 知识库"""
    if not left:
        left = {}
    if not right:
        return left
    new_kb = left.copy()
    new_kb.update(right)
    return new_kb


class ActionCommand(BaseModel):
    target: Literal[
        "Log_Retrieval_Node",
        "MITRE_Expert_Node",
        "User_Input_Node",
        "Reporter_Node",
        "Decision_Node",
        "Attribution_Planner_Node",
    ] = Field(description="The target node to route to.") 
    
    instruction: str = Field(
        description="The specific instruction or query to pass to the target node. YOU MUST PROVIDE THIS."
    )

# 状态定义
class AttributionState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]

    # 下一步的调查指令
    next_action: ActionCommand | None

    # 原始日志暂存
    current_raw_logs: list[dict[str, Any]] | None

    # 外部知识库
    mitre_knowledge_base: Annotated[dict[str, str], merge_kb]

    # 报告
    final_report: str | None

    # 用户自定义配置相关
    investigation_clue: str | None
    is_clue_confirmed: bool | None
    pending_question_type: str | None
    requires_mitre_kb: bool | None
