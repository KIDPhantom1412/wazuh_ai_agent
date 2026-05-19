import json
import logging
from typing import Any

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.config import get_config

from agents.attack_attribution.attack_attributor import get_attack_attribution_agent
from agents.rule_agent.rule_agent import get_rule_agent

logger = logging.getLogger(__name__)


def _get_thread_id() -> str:
    try:
        config = get_config()
    except RuntimeError:
        return "default"
    if not isinstance(config, dict):
        return "default"
    configurable = config.get("configurable", {})
    if isinstance(configurable, dict) and configurable.get("thread_id"):
        return str(configurable["thread_id"])
    return "default"


def _get_thread_session(
    session_cache_by_thread: dict[str, dict[str, Any]],
    thread_id: str,
) -> dict[str, Any]:
    if thread_id not in session_cache_by_thread:
        session_cache_by_thread[thread_id] = {
            "latest_plan_summary": None,
            "latest_plan_steps": [],
            "executed_steps": [],
            "specialist_state_cache": {
                "rule_agent": None,
                "attack_attribution": None,
            },
        }
    return session_cache_by_thread[thread_id]


def _normalize_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = []
        for block in content:
            if isinstance(block, dict) and "text" in block:
                text_parts.append(str(block["text"]))
            else:
                text_parts.append(str(block))
        return "".join(text_parts)
    return str(content)


def _extract_latest_ai_content(messages: list[Any] | None) -> str:
    if not messages:
        return ""
    for msg in reversed(messages):
        if getattr(msg, "type", "") == "ai":
            content = _normalize_message_content(getattr(msg, "content", ""))
            if content.strip():
                return content.strip()
    return ""


def _is_high_risk_rule_task(task: str) -> bool:
    high_risk_keywords = [
        "验证",
        "apply",
        "应用",
        "上传",
        "重启",
        "restart",
        "删除",
        "cleanup",
        "覆盖",
        "overwrite",
        "启用规则",
        "停用规则",
    ]
    lowered_task = task.lower()
    return any(keyword in task or keyword in lowered_task for keyword in high_risk_keywords)


def _has_explicit_user_authorization(task: str) -> bool:
    approval_markers = [
        "已获用户明确授权",
        "用户已明确授权",
        "用户已确认执行",
        "用户明确同意执行",
        "已获得用户授权",
    ]
    return any(marker in task for marker in approval_markers)


def _summarize_rule_state(rule_state: dict[str, Any] | None) -> str:
    if not rule_state:
        return "无进行中的规则生成工作流。"

    summary = {
        "has_generated_rule": bool(rule_state.get("generated_rule")),
        "rule_id": rule_state.get("rule_id"),
        "missing_parameters": rule_state.get("missing_parameters"),
        "is_feasible": rule_state.get("is_feasible"),
        "logtest_passed": rule_state.get("logtest_passed"),
        "validation_error": rule_state.get("validation_error"),
        "verification_feedback": rule_state.get("verification_feedback"),
        "latest_reply": _extract_latest_ai_content(rule_state.get("messages")),
    }
    return json.dumps(summary, ensure_ascii=False)


def _summarize_attack_state(attack_state: dict[str, Any] | None) -> str:
    if not attack_state:
        return "无进行中的攻击溯源工作流。"

    summary = {
        "investigation_clue": attack_state.get("investigation_clue"),
        "is_clue_confirmed": attack_state.get("is_clue_confirmed"),
        "pending_question_type": attack_state.get("pending_question_type"),
        "requires_mitre_kb": attack_state.get("requires_mitre_kb"),
        "has_final_report": bool(attack_state.get("final_report")),
        "latest_reply": _extract_latest_ai_content(attack_state.get("messages")),
    }
    return json.dumps(summary, ensure_ascii=False)


def _invoke_specialist(
    specialist_name: str,
    session_cache_by_thread: dict[str, dict[str, Any]],
    specialist_app,
    task: str,
    reset_context: bool,
) -> str:
    thread_id = _get_thread_id()
    session = _get_thread_session(session_cache_by_thread, thread_id)
    specialist_state_cache = session["specialist_state_cache"]
    current_state = None if reset_context else specialist_state_cache.get(specialist_name)
    next_state = dict(current_state or {})
    existing_messages = list(next_state.get("messages", []))

    plan_summary = session.get("latest_plan_summary")
    plan_steps = session.get("latest_plan_steps") or []
    if plan_summary:
        step_lines = "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(plan_steps))
        enriched_task = (
            f"[当前任务计划摘要]\n{plan_summary}\n\n"
            f"[计划步骤]\n{step_lines or '1. 直接执行当前子任务'}\n\n"
            f"[当前执行子任务]\n{task}"
        )
    else:
        enriched_task = task

    existing_messages.append({"role": "user", "content": enriched_task})
    next_state["messages"] = existing_messages

    result = specialist_app.invoke(next_state, {"recursion_limit": 100})
    specialist_state_cache[specialist_name] = result
    session["executed_steps"].append(
        {
            "specialist": specialist_name,
            "task": task,
            "reply": _extract_latest_ai_content(result.get("messages")),
        }
    )

    reply = _extract_latest_ai_content(result.get("messages"))
    if specialist_name == "rule_agent":
        state_summary = _summarize_rule_state(result)
    else:
        state_summary = _summarize_attack_state(result)

    return json.dumps(
        {
            "specialist": specialist_name,
            "thread_id": thread_id,
            "task": task,
            "reset_context": reset_context,
            "plan_summary": plan_summary,
            "plan_steps": plan_steps,
            "reply": reply or f"{specialist_name} 未返回可展示内容。",
            "state_summary": json.loads(state_summary),
            "executed_steps": session["executed_steps"],
        },
        ensure_ascii=False,
    )


def get_router_agent(
    router_model: BaseChatModel,
    rule_model: BaseChatModel | None = None,
    attack_model: BaseChatModel | None = None,
):
    rule_agent = get_rule_agent(rule_model or router_model)
    attack_agent = get_attack_attribution_agent(attack_model or router_model)
    session_cache_by_thread: dict[str, dict[str, Any]] = {}

    @tool
    def write_task_plan(
        plan_summary: str,
        steps: list[str],
    ) -> str:
        """为当前线程会话记录任务计划。
        当用户请求包含两个及以上动作时，你必须先调用本工具，再开始执行 specialist 工具。
        `plan_summary` 是一句话总目标，`steps` 是按顺序排列的可执行步骤列表。
        """

        thread_id = _get_thread_id()
        session = _get_thread_session(session_cache_by_thread, thread_id)
        session["latest_plan_summary"] = plan_summary
        session["latest_plan_steps"] = steps
        session["executed_steps"] = []
        return json.dumps(
            {
                "thread_id": thread_id,
                "plan_summary": plan_summary,
                "steps": steps,
                "message": "任务计划已记录，将按此计划执行。",
            },
            ensure_ascii=False,
        )

    @tool
    def delegate_rule_agent(
        task: str,
        reset_context: bool = False,
    ) -> str:
        """将单个 Wazuh 规则相关子任务委派给 `rule_agent`。
        适用于创建、修改、解释、查询、列出、验证、删除规则，以及查询规则文件、规则组和 requirement 相关规则。一次只处理一个明确子任务。
        如果用户请求包含多个规则动作，请拆分后多次调用本工具。
        当这是一个新的独立规则工作流时，将 `reset_context` 设为 true。
        """

        logger.info("Delegating task to rule_agent. reset_context=%s task=%s", reset_context, task)
        if _is_high_risk_rule_task(task) and not _has_explicit_user_authorization(task):
            return json.dumps(
                {
                    "specialist": "rule_agent",
                    "thread_id": _get_thread_id(),
                    "task": task,
                    "approval_required": True,
                    "reply": (
                        "当前子任务涉及高风险操作，可能触发规则上传、覆盖、删除或重启 Wazuh manager。"
                        "在执行前必须先取得用户明确授权。"
                    ),
                    "required_user_action": (
                        "请先向用户明确说明风险，并询问是否继续。"
                        '只有在用户明确同意后，后续工具调用才能执行，且任务文本中必须包含"已获用户明确授权"。'
                    ),
                },
                ensure_ascii=False,
            )
        return _invoke_specialist(
            specialist_name="rule_agent",
            session_cache_by_thread=session_cache_by_thread,
            specialist_app=rule_agent,
            task=task,
            reset_context=reset_context,
        )

    @tool
    def delegate_attack_attribution(
        task: str,
        reset_context: bool = False,
    ) -> str:
        """将攻击溯源或日志查询任务委派给 `attack_attribution`。
        系统会自动判断任务类型：
        - 简单日志查询（如"查询agent001最近1天的日志"）→ 直接返回原始日志
        - 攻击溯源调查（如"调查agent005的告警"）→ 启动完整调查流程
        注意：attack_attribution 内部有自主规划节点，会自行制定具体的调查策略。
        你只需将用户的原始请求原样传入 `task`，不要进一步拆解用户的需求。
        当这是一个新的独立任务时，将 `reset_context` 设为 true。
        """

        logger.info(
            "Delegating task to attack_attribution. reset_context=%s task=%s",
            reset_context,
            task,
        )
        return _invoke_specialist(
            specialist_name="attack_attribution",
            session_cache_by_thread=session_cache_by_thread,
            specialist_app=attack_agent,
            task=task,
            reset_context=reset_context,
        )

    system_prompt = """
你是 Wazuh 多智能体总控代理，采用 ReAct 风格工作：
1. 先理解用户目标。
2. 如果请求是多步骤任务，先显式生成计划摘要与步骤。
3. 再逐步调用合适工具执行。
4. 观察工具结果后决定下一步，直到任务完成。
5. 最后用中文向用户做整合回复。

══════════════════════════════════════════════════════
一、可用工具
══════════════════════════════════════════════════════
- `write_task_plan`：为当前线程会话记录任务计划摘要与步骤。多步骤请求必须先调用它。
- `delegate_rule_agent`：处理 Wazuh 规则创建、修改、解释、查询、列出、验证、删除；也处理规则文件、规则组、requirement 相关规则查询。
- `delegate_attack_attribution`：处理攻击溯源、调查、线索确认、报告生成，也支持简单日志查询
  （如关键词搜索、按文件/进程查日志）。系统内部会自动判断任务类型并选择合适的处理路径。

══════════════════════════════════════════════════════
二、通用规则
══════════════════════════════════════════════════════
【任务规划】
  - 对复合请求必须主动拆分，不要只执行其中一步。
  - 只要请求包含两个及以上动作，你必须先调用 `write_task_plan`，明确列出步骤，再开始执行。

【工具调用】
  - 同一轮中可以多次调用同一个工具，也可以先后调用不同工具。
  - 每次工具调用只传一个清晰、可执行的子任务，不要把多个动作塞进一次调用。
  - 如果问题不需要 specialist，直接回答，不要强行调工具。
  - 工具返回的是 specialist 的结果和状态摘要。你要根据这些结果继续规划，而不是机械转述。

【会话管理】
  - 工具按 `thread_id` 自动隔离会话状态。继续同一线程时复用上下文，不同线程之间不得串用。
  - 继续同一 specialist 的上下文时 `reset_context=false`；新独立任务时 `reset_context=true`。

══════════════════════════════════════════════════════
三、委托规则智能体 (delegate_rule_agent)
══════════════════════════════════════════════════════
【任务分类】
  - 只读任务（低风险，无需授权）：规则查询、列出规则、列出规则文件、查看某个规则文件、列出规则组、查询 requirement 相关规则。此类任务通常是新的独立任务，除非用户明确说"继续刚才的查询"，否则 `reset_context=true`。
  - 高风险任务（必须授权）：规则验证、应用、上传、覆盖、删除、清理、重启 Wazuh manager、启用/停用规则。

【高风险操作授权】
  对上述高风险动作，你必须先向用户说明风险并询问是否继续，获得明确同意后才能执行。
  用户同意后，传入的 `task` 文本中必须包含"已获用户明确授权"这句标记。
  如果忘记先确认，`delegate_rule_agent` 会返回 `approval_required=true`，此时必须停止并向用户征求授权。

【示例：高风险多步骤任务】
  - 用户说“先删除 id 为 100100 的规则，再去验证，最后生成说明”
  你应先说明这包含高风险动作，需要用户确认。
  - 用户确认后，你可以先调用 `write_task_plan(...)` 列出三步，
  再调用 `delegate_rule_agent(task="已获用户明确授权：删除 id 为 100100 的规则", reset_context=true)`，
  然后调用 `delegate_rule_agent(task="已获用户明确授权：验证刚才处理的规则", reset_context=false)`，
  最后调用 `delegate_rule_agent(task="基于前面执行结果生成处理说明", reset_context=false)`，
  再汇总结果。

══════════════════════════════════════════════════════
四、委托攻击溯源 (delegate_attack_attribution)
══════════════════════════════════════════════════════
【任务透传（CRITICAL — 严禁拆分用户输入）】
  attack_attribution 内部有专业的攻击溯源规划节点，会自主制定调查策略。
  当你收到日志查询、搜索或攻击溯源请求时，统一使用本工具。
  你的 `task` 必须传入用户的**完整原始输入**，一字不改、不增不减。
  对 JSON + 指令组合（如 {json日志} 对该日志进行攻击溯源），**整段原样传入**。
  严禁只传 JSON 而丢弃后面的指令，或只传指令而丢弃 JSON——这会导致下游 Planner_Node 误判任务类型。
  不要加工、拆解或细化（如添加 MITRE ID、调查步骤清单、进程追踪方向等）。
  让 specialist 自己决定怎么做。

【原始 JSON 日志透传（CRITICAL）】
  严禁对 JSON 做任何预处理，包括但不限于：提取字段重新排版、将 timestamp 中的 UTC 时间（Z 结尾）转换为北京时间、按字段分类整理、添加你的理解或注释。
  attack_attribution 内部有专门的时区处理逻辑（extract_beijing_time_from_logs），你的任何预处理都会破坏这条链路。

【输出规则】
  A. 线索确认消息透传：
     当 `state_summary` 中 `pending_question_type` 为 "CLUE" 时，说明攻击溯源等待用户确认线索。
     你必须将 `reply` 逐字原样输出给用户，严禁重新排版、总结、提取要点、Markdown 表格或分段概括。
     收到用户回复后将用户原话作为 `task` 传入，`reset_context=false`。

     CLUE 消息样例：
     ┌─────────────────────────────────────────────────
     │ 系统检测到原始日志输入。我为您提取了如下调查线索：
     │
     │ 『Agent 003 触发了 Level 12 的告警（Rule 57100: Suspicious process
     │   execution by wmic.exe）。告警显示进程 wmic.exe (PID 8840) 调用了
     │   cmd.exe (PID 9012) 执行了异常脚本，操作用户为 WORKGROUP\\admin。
     │   时间范围限定在北京时间 2026-03-10 09:15 至 09:35 之间（北京时间）。』
     │
     │ 请问该线索是否符合您的要求？（同意请回复"是"；如需修改请直接指出）
     └─────────────────────────────────────────────────
     → 正确做法：原文一字不改地发给用户。
     → 错误做法：用 Markdown 表格列出"受感染主机 / 告警规则 / 可疑进程 / MITRE 技术"。

  B. 日志查询结果透传：
     当 `reply` 中包含原始 JSON 日志数据（通常以 `[{"` 开头）时，说明这是一次日志查询结果。
     你必须将 `reply` 逐字原样输出给用户。
     严禁提取字段做成表格、按 agent/rule/level 分类汇总、转换为 Markdown、
     或输出"共查询到 N 条日志，涉及多个 agent..."等摘要。
     JSON 中有多少条、多少字段，就完整输出多少。
"""

    return create_agent(
        model=router_model,
        tools=[write_task_plan, delegate_rule_agent, delegate_attack_attribution],
        system_prompt=system_prompt,
    )
