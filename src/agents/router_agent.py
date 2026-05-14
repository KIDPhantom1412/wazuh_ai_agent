import json
import logging
from typing import Any

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.config import get_config

from agents.attack_attribution.attack_attributor import get_attack_attribution_agent
from agents.rule_generator.rule_generator import get_rule_generator_agent

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
                "rule_generator": None,
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

    result = specialist_app.invoke(next_state)
    specialist_state_cache[specialist_name] = result
    session["executed_steps"].append(
        {
            "specialist": specialist_name,
            "task": task,
            "reply": _extract_latest_ai_content(result.get("messages")),
        }
    )

    reply = _extract_latest_ai_content(result.get("messages"))
    if specialist_name == "rule_generator":
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
    rule_agent = get_rule_generator_agent(rule_model or router_model)
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
    def delegate_rule_generator(
        task: str,
        reset_context: bool = False,
    ) -> str:
        """将单个 Wazuh 规则相关子任务委派给 `rule_generator`。
        适用于创建、修改、解释、验证、删除规则。一次只处理一个明确子任务。
        如果用户请求包含多个规则动作，请拆分后多次调用本工具。
        当这是一个新的独立规则工作流时，将 `reset_context` 设为 true。
        """

        logger.info(
            "Delegating task to rule_generator. reset_context=%s task=%s", reset_context, task
        )
        if _is_high_risk_rule_task(task) and not _has_explicit_user_authorization(task):
            return json.dumps(
                {
                    "specialist": "rule_generator",
                    "thread_id": _get_thread_id(),
                    "task": task,
                    "approval_required": True,
                    "reply": (
                        "当前子任务涉及高风险操作，可能触发规则上传、覆盖、删除或重启 Wazuh manager。"
                        "在执行前必须先取得用户明确授权。"
                    ),
                    "required_user_action": (
                        "请先向用户明确说明风险，并询问是否继续。"
                        "只有在用户明确同意后，后续工具调用才能执行，且任务文本中必须包含“已获用户明确授权”。"
                    ),
                },
                ensure_ascii=False,
            )
        return _invoke_specialist(
            specialist_name="rule_generator",
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
        """将单个攻击溯源相关子任务委派给 `attack_attribution`。
        适用于线索确认、日志调查、攻击链分析、生成调查报告。一次只处理一个明确子任务。
        如果用户请求包含多个溯源动作，请拆分后多次调用本工具。
        当这是一个新的独立溯源工作流时，将 `reset_context` 设为 true。
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

你可用的 specialist 工具：
- `write_task_plan`：为当前线程会话记录任务计划摘要与步骤。多步骤请求必须先调用它。
- `delegate_rule_generator`：处理 Wazuh 规则创建、修改、解释、验证、删除。
- `delegate_attack_attribution`：处理攻击溯源、调查、线索确认、报告生成。

关键规则：
- 对复合请求必须主动拆分，不要只执行其中一步。
- 只要请求包含两个及以上动作，你必须先调用 `write_task_plan`，明确列出步骤，再开始执行。
- 同一轮中可以多次调用同一个工具，也可以先后调用不同工具。
- 每次工具调用只传一个清晰、可执行的子任务，不要把多个动作塞进一次调用。
- 工具会按 `thread_id` 自动隔离会话状态。继续同一线程的任务时复用上下文，不同线程之间不得串用上下文。
- 如果是在继续同一个 specialist 的上下文，`reset_context=false`；如果是新的独立任务，`reset_context=true`。
- 对 `rule_generator` 相关的高风险动作必须先征求用户授权，再执行。
- 高风险动作包括但不限于：规则验证、应用、上传、覆盖、删除、清理、重启 Wazuh manager、启用/停用规则。
- 如果用户只是说“帮我验证/直接应用/直接删掉”，你不能默认代为执行；必须先向用户说明风险并询问是否继续。
- 当用户明确同意后，你才能调用 `delegate_rule_generator`，并且传入的 `task` 文本里必须包含“已获用户明确授权”这句标记。
- 如果你忘了先确认，`delegate_rule_generator` 会返回 `approval_required=true`；此时你必须停止执行并向用户征求授权。
- 如果问题不需要 specialist，直接回答，不要强行调工具。
- 工具返回的是 specialist 的结果和状态摘要。你要根据这些结果继续规划，而不是机械转述。

示例：
- 用户说“先删除 id 为 100100 的规则，再去验证，最后生成说明”
  你应先说明这包含高风险动作，需要用户确认。
- 用户确认后，你可以先调用 `write_task_plan(...)` 列出三步，
  再调用 `delegate_rule_generator(task="已获用户明确授权：删除 id 为 100100 的规则", reset_context=true)`，
  然后调用 `delegate_rule_generator(task="已获用户明确授权：验证刚才处理的规则", reset_context=false)`，
  最后调用 `delegate_rule_generator(task="基于前面执行结果生成处理说明", reset_context=false)`，
  再汇总结果。
"""

    return create_agent(
        model=router_model,
        tools=[write_task_plan, delegate_rule_generator, delegate_attack_attribution],
        system_prompt=system_prompt,
    )
