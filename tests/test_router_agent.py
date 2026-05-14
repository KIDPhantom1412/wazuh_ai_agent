import os
import sys
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

# Mock wazuh_api before importing agent modules
sys.modules["wazuh_api"] = MagicMock()
sys.modules["wazuh_api.server_api"] = MagicMock()
sys.modules["wazuh_api.indexer_api"] = MagicMock()


class MockRouterReActModel(BaseChatModel):
    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        tool_messages = [msg for msg in messages if getattr(msg, "type", "") == "tool"]
        human_messages = [msg for msg in messages if getattr(msg, "type", "") == "human"]
        latest_user_input = str(human_messages[-1].content) if human_messages else ""

        if "先删除id为100100的规则，再去验证，最后生成一段处理说明" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_1",
                                        "name": "write_task_plan",
                                        "args": {
                                            "plan_summary": "处理规则 100100 的删除、验证与结果说明",
                                            "steps": [
                                                "删除规则 100100",
                                                "验证刚才处理的规则",
                                                "基于执行结果生成处理说明",
                                            ],
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if len(tool_messages) == 1:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_2",
                                        "name": "delegate_rule_generator",
                                        "args": {
                                            "task": "已获用户明确授权：删除 id 为 100100 的规则",
                                            "reset_context": True,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if len(tool_messages) == 2:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_3",
                                        "name": "delegate_rule_generator",
                                        "args": {
                                            "task": "已获用户明确授权：验证刚才处理的规则",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if len(tool_messages) == 3:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_4",
                                        "name": "delegate_rule_generator",
                                        "args": {
                                            "task": "基于前面执行结果生成处理说明",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[
                    ChatGeneration(
                        message=AIMessage(
                            content="已按计划完成规则 100100 的删除、验证，并生成处理说明。"
                        )
                    )
                ]
            )

        if "攻击溯源分析" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_1",
                                        "name": "delegate_attack_attribution",
                                        "args": {
                                            "task": "请先提炼调查线索并启动攻击溯源分析",
                                            "reset_context": True,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[
                    ChatGeneration(message=AIMessage(content="已启动攻击溯源并给出线索确认。"))
                ]
            )

        if "继续验证刚才处理的规则" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_verify",
                                        "name": "delegate_rule_generator",
                                        "args": {
                                            "task": "已获用户明确授权：验证刚才处理的规则",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="继续验证步骤已执行完毕。"))]
            )

        if "直接验证并重启manager" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_risky",
                                        "name": "delegate_rule_generator",
                                        "args": {
                                            "task": "验证刚才生成的规则并重启 Wazuh manager",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if any(
                '"approval_required": true' in str(msg.content).lower() for msg in tool_messages
            ):
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="该操作会触发高风险变更，我需要先取得你的明确授权后才能继续执行。"
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="危险操作已执行。"))]
            )

        if "继续调查" in latest_user_input:
            if any("报告已生成完毕。" in str(msg.content) for msg in tool_messages):
                return ChatResult(
                    generations=[ChatGeneration(message=AIMessage(content="报告已生成完毕。"))]
                )
            return ChatResult(
                generations=[
                    ChatGeneration(
                        message=AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "id": "call_3",
                                    "name": "delegate_attack_attribution",
                                    "args": {
                                        "task": "根据刚才的线索继续调查并生成报告",
                                        "reset_context": False,
                                    },
                                }
                            ],
                        )
                    )
                ]
            )

        return ChatResult(
            generations=[
                ChatGeneration(message=AIMessage(content="这是普通问题，直接由路由大模型回答。"))
            ]
        )

    @property
    def _llm_type(self):
        return "mock-router-react"


class FakeRuleAgent:
    def invoke(self, state):
        messages = list(state.get("messages", []))
        latest_message = messages[-1] if messages else {}
        latest_request = (
            latest_message.get("content", "")
            if isinstance(latest_message, dict)
            else getattr(latest_message, "content", "")
        )
        current_task = (
            latest_request.split("[当前执行子任务]\n", 1)[-1]
            if "[当前执行子任务]\n" in latest_request
            else latest_request
        )

        if "删除" in current_task and "100100" in current_task:
            messages.append(AIMessage(content="规则 100100 已删除。"))
            return {
                **state,
                "messages": messages,
                "deleted_rule_id": 100100,
                "verification_feedback": "规则 100100 已删除。",
            }
        if "验证" in current_task:
            deleted_rule_id = state.get("deleted_rule_id")
            messages.append(
                AIMessage(
                    content=(
                        "已基于刚才删除后的上下文完成验证。"
                        if deleted_rule_id == 100100
                        else "缺少待验证规则上下文。"
                    )
                )
            )
            return {
                **state,
                "messages": messages,
                "rule_id": deleted_rule_id,
                "logtest_passed": deleted_rule_id == 100100,
            }
        if "说明" in current_task:
            deleted_rule_id = state.get("deleted_rule_id")
            logtest_passed = state.get("logtest_passed")
            messages.append(
                AIMessage(
                    content=(
                        f"处理说明：规则 {deleted_rule_id} 已删除，随后完成验证，验证结果为通过。"
                        if deleted_rule_id == 100100 and logtest_passed
                        else "处理说明：由于缺少上下文，暂时无法生成准确说明。"
                    )
                )
            )
            return {
                **state,
                "messages": messages,
                "verification_feedback": messages[-1].content,
            }

        messages.append(AIMessage(content="规则已生成，请确认是否验证。"))
        return {
            **state,
            "messages": messages,
            "generated_rule": "<rule id='110001'/>",
            "rule_id": 110001,
            "logtest_passed": False,
        }


class FakeAttackAgent:
    def invoke(self, state):
        messages = list(state.get("messages", []))
        latest_message = messages[-1] if messages else {}
        latest_request = (
            latest_message.get("content", "")
            if isinstance(latest_message, dict)
            else getattr(latest_message, "content", "")
        )

        if state.get("pending_question_type") == "CLUE" and (
            "继续" in latest_request or "确认" in latest_request or "生成报告" in latest_request
        ):
            messages.append(AIMessage(content="报告已生成完毕。"))
            return {
                **state,
                "messages": messages,
                "investigation_clue": "检测到可疑进程链路。",
                "is_clue_confirmed": True,
                "pending_question_type": None,
                "final_report": "攻击溯源调查报告",
            }

        messages.append(AIMessage(content="已提炼攻击线索，请确认。"))
        return {
            **state,
            "messages": messages,
            "investigation_clue": "检测到可疑进程链路。",
            "is_clue_confirmed": False,
            "pending_question_type": "CLUE",
            "final_report": None,
        }


def test_router_agent_plans_and_executes_three_step_rule_chain_in_one_turn():
    from agents.router_agent import get_router_agent

    with (
        patch("agents.router_agent.get_rule_generator_agent", return_value=FakeRuleAgent()),
        patch("agents.router_agent.get_attack_attribution_agent", return_value=FakeAttackAgent()),
    ):
        app = get_router_agent(MockRouterReActModel())

        state = {
            "messages": [
                HumanMessage(
                    content="我已明确授权你执行相关变更。你先删除id为100100的规则，再去验证，最后生成一段处理说明"
                )
            ]
        }
        result = app.invoke(state)

        tool_messages = [msg for msg in result["messages"] if getattr(msg, "type", "") == "tool"]
        assert len(tool_messages) == 4
        assert (
            "已按计划完成规则 100100 的删除、验证，并生成处理说明。"
            in result["messages"][-1].content
        )
        assert "任务计划已记录" in tool_messages[0].content
        assert "规则 100100 已删除" in tool_messages[1].content
        assert "已基于刚才删除后的上下文完成验证" in tool_messages[2].content
        assert (
            "处理说明：规则 100100 已删除，随后完成验证，验证结果为通过。"
            in tool_messages[3].content
        )
        assert (
            '"steps": ["删除规则 100100", "验证刚才处理的规则", "基于执行结果生成处理说明"]'
            in tool_messages[0].content
        )


def test_router_agent_preserves_attack_specialist_state_across_turns():
    from agents.router_agent import get_router_agent

    with (
        patch("agents.router_agent.get_rule_generator_agent", return_value=FakeRuleAgent()),
        patch("agents.router_agent.get_attack_attribution_agent", return_value=FakeAttackAgent()),
    ):
        app = get_router_agent(MockRouterReActModel())

        state = {"messages": [HumanMessage(content="请帮我对这条异常进程告警做攻击溯源分析")]}
        result = app.invoke(state)

        assert "已启动攻击溯源并给出线索确认。" in result["messages"][-1].content

        result["messages"].append(HumanMessage(content="是，继续调查"))
        continued = app.invoke(result)

        tool_messages = [msg for msg in continued["messages"] if getattr(msg, "type", "") == "tool"]
        assert "报告已生成完毕。" in tool_messages[-1].content
        assert "报告已生成完毕。" in continued["messages"][-1].content


def test_router_agent_isolates_specialist_state_by_thread_id():
    from agents.router_agent import get_router_agent

    with (
        patch("agents.router_agent.get_rule_generator_agent", return_value=FakeRuleAgent()),
        patch("agents.router_agent.get_attack_attribution_agent", return_value=FakeAttackAgent()),
    ):
        app = get_router_agent(MockRouterReActModel())

        app.invoke(
            {
                "messages": [
                    HumanMessage(
                        content="我已明确授权你执行相关变更。你先删除id为100100的规则，再去验证，最后生成一段处理说明"
                    )
                ]
            },
            config={"configurable": {"thread_id": "thread-a"}},
        )

        isolated = app.invoke(
            {"messages": [HumanMessage(content="我已明确授权，请继续验证刚才处理的规则")]},
            config={"configurable": {"thread_id": "thread-b"}},
        )
        continued = app.invoke(
            {"messages": [HumanMessage(content="我已明确授权，请继续验证刚才处理的规则")]},
            config={"configurable": {"thread_id": "thread-a"}},
        )

        isolated_tools = [msg for msg in isolated["messages"] if getattr(msg, "type", "") == "tool"]
        continued_tools = [
            msg for msg in continued["messages"] if getattr(msg, "type", "") == "tool"
        ]

        assert "缺少待验证规则上下文。" in isolated_tools[-1].content
        assert "已基于刚才删除后的上下文完成验证。" in continued_tools[-1].content


def test_router_agent_requires_user_confirmation_before_high_risk_rule_actions():
    from agents.router_agent import get_router_agent

    with (
        patch("agents.router_agent.get_rule_generator_agent", return_value=FakeRuleAgent()),
        patch("agents.router_agent.get_attack_attribution_agent", return_value=FakeAttackAgent()),
    ):
        app = get_router_agent(MockRouterReActModel())
        result = app.invoke({"messages": [HumanMessage(content="帮我直接验证并重启manager")]})

        tool_messages = [msg for msg in result["messages"] if getattr(msg, "type", "") == "tool"]
        assert '"approval_required": true' in tool_messages[-1].content.lower()
        assert "先取得你的明确授权" in result["messages"][-1].content


def test_router_agent_answers_directly_when_no_specialist_is_needed():
    from agents.router_agent import get_router_agent

    with (
        patch("agents.router_agent.get_rule_generator_agent", return_value=FakeRuleAgent()),
        patch("agents.router_agent.get_attack_attribution_agent", return_value=FakeAttackAgent()),
    ):
        app = get_router_agent(MockRouterReActModel())
        result = app.invoke({"messages": [HumanMessage(content="帮我查一下今天上海天气")]})

        assert "直接由路由大模型回答" in result["messages"][-1].content
