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


class DecisionActionCommand(BaseModel):
    target: Literal["User_Input_Node", "Attribution_Planner_Node", "Decision_Node"] = Field(
        description="The target node to route to from Decision_Node."
    )
    instruction: str = Field(default="", description="Optional instruction for the target node.")


class AttributionPlannerActionCommand(BaseModel):
    target: Literal["Log_Retrieval_Node", "MITRE_Expert_Node", "Reporter_Node"] = Field(
        description="The target node to route to from Attribution_Planner_Node."
    )
    instruction: str = Field(
        description="The specific instruction or query to pass to the target node. YOU MUST PROVIDE THIS."
    )


# 状态定义
class AttributionState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]

    next_action_fromDecisionNode: DecisionActionCommand | None
    next_action_fromAttributionPlannerNode: AttributionPlannerActionCommand | None

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
    ## 是否启动多主机场景
    is_multi_host: bool | None
    agent_ip_mapping: dict[str, str] | None

    ## 日志查询默认参数
    default_start_time: str = Field(
        description="调查窗口的起始时间，ISO8601格式 (北京时间/UTC+8)。"
    )
    default_end_time: str = Field(description="调查窗口的结束时间，ISO8601格式 (北京时间/UTC+8)。")
    default_agent_id: str = Field(description="提取到的被攻击 Agent ID (如 '005')。")

    # 可视化展示
    mermaid_chart: str | None
    svg_chart: str | None
