from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class AttributionState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    raw_findings: str | None
    final_report: str | None
