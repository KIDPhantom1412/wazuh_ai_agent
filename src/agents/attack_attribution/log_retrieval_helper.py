import json
import logging
import re
from enum import Enum

from langchain.tools import tool

from wazuh_api.indexer_api import (
    agent_archives,
)

logger = logging.getLogger(__name__)


class QueryType(str, Enum):
    PROCESS_ID = "PROCESS_ID"
    PARENT_PROCESS_ID = "PARENT_PROCESS_ID"
    FILE_PATH = "FILE_PATH"
    IP_ADDRESS = "IP_ADDRESS"
    PORT = "PORT"
    SERVICE_NAME = "SERVICE_NAME"
    USER_ACCOUNT = "USER_ACCOUNT"
    REGISTRY_PATH = "REGISTRY_PATH"


@tool
def get_archives_by_keyword(
    agent_id: str,
    keyword: str = "",
    x_limit: int = 10,
    start_time: str = None,
    end_time: str = None,
):
    """
    从 Wazuh Indexer 的 wazuh-archives-* 获取特定 Agent 的原始归档日志，支持关键词搜索和时间过滤。

    :param agent_id: Agent 的唯一 ID (如 "001")
    :param keyword: 搜搜索的关键词 (如 "regsvr32"), 默认为""
    :param x_limit: 返回的日志条数, 默认为 10。
    :param start_time: (可选) 限定查询时间窗口的起始时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    :param end_time: (可选) 限定查询时间窗口的结束时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    """

    if start_time:
        start_time = _format_iso8601(start_time)
    if end_time:
        end_time = _format_iso8601(end_time)

    search_results = agent_archives(
        agent_id,
        keyword=keyword,
        x_limit=x_limit,
        payload=None,
        timeout=30,
        start_time=start_time,
        end_time=end_time,
    )

    hits = search_results.get("hits", {}).get("hits", [])
    archives = [simplify_log(hit["_source"]) for hit in hits]

    return json.dumps(archives, ensure_ascii=False)


def simplify_log(source):
    """
    用于提取单条日志关键内容，并保持字段路径与原始日志一致。
    仅针对 Windows EventChannel (win) 类型进行简化。
    """
    if not isinstance(source, dict):
        return source

    data = source.get("data", {})
    if not isinstance(data, dict):
        return source

    win = data.get("win", {})

    if not (isinstance(win, dict) and win):
        return source

    def _prune(obj):
        if isinstance(obj, dict):
            cleaned = {}
            for k, v in obj.items():
                pv = _prune(v)
                if pv is None or pv == "":
                    continue
                if isinstance(pv, dict) and not pv:
                    continue
                if isinstance(pv, list) and not pv:
                    continue
                cleaned[k] = pv
            return cleaned
        if isinstance(obj, list):
            cleaned_list = []
            for v in obj:
                pv = _prune(v)
                if pv is None or pv == "":
                    continue
                if isinstance(pv, dict) and not pv:
                    continue
                cleaned_list.append(pv)
            return cleaned_list
        return obj

    out = {}

    if source.get("timestamp"):
        out["timestamp"] = source.get("timestamp")
    elif source.get("@timestamp"):
        out["@timestamp"] = source.get("@timestamp")

    agent = source.get("agent", {})
    if isinstance(agent, dict) and agent.get("id"):
        out["agent"] = {"id": agent.get("id")}

    rule = source.get("rule", {})
    if isinstance(rule, dict) and rule:
        rule_out = {}
        for k in ("id", "level", "description"):
            if rule.get(k) is not None and rule.get(k) != "":
                rule_out[k] = rule.get(k)
        mitre = rule.get("mitre", {})
        if isinstance(mitre, dict) and mitre:
            mitre_out = {}
            if mitre.get("id"):
                mitre_out["id"] = mitre.get("id")
            if mitre.get("tactic"):
                mitre_out["tactic"] = mitre.get("tactic")
            if mitre_out:
                rule_out["mitre"] = mitre_out
        if rule_out:
            out["rule"] = rule_out

    win_eventdata = win.get("eventdata", {}) if isinstance(win.get("eventdata", {}), dict) else {}
    win_system = win.get("system", {}) if isinstance(win.get("system", {}), dict) else {}

    system_out = {}
    if win_system.get("eventID") is not None and win_system.get("eventID") != "":
        system_out["eventID"] = win_system.get("eventID")

    eventdata_keep = [
        # --- 1. 基础进程上下文 (Event 1, 3, 7, 11) ---
        "processId",
        "image",
        "commandLine",
        "parentProcessId",
        "parentImage",
        "parentCommandLine",
        "originalFileName",
        "integrityLevel",
        # --- 2. 用户与账号身份 (Event 1, 3, 8, 10, 7045) ---
        "user",
        "parentUser",
        "sourceUser",
        "targetUser",
        "accountName",
        "targetUserName",
        # --- 3. 网络通信记录 (Event 3, 4624) ---
        "sourceIp",
        "sourcePort",
        "destinationIp",
        "destinationPort",
        "protocol",
        "ipAddress",
        "ipPort",
        # --- 4. 文件与模块加载 (Event 7, 11) ---
        "targetFilename",
        "imageLoaded",
        "signed",
        # --- 5. 进程注入与内存访问 (Event 8, 10) ---
        "sourceProcessId",
        "sourceImage",
        "targetProcessId",
        "targetImage",
        "grantedAccess",
        "startAddress",
        "callTrace",
        # --- 6. 系统服务注册 (Event 7045) ---
        "serviceName",
        "imagePath",
        "serviceType",
        "startType",
        # --- 7. 注册表行为 (Event 12, 13, 14) ---
        "eventType",  # 动作类型：如 CreateKey, DeleteKey, SetValue, RenameKey
        "targetObject",  # 目标对象：被操作的完整注册表路径
        "details",  # 具体细节：写入注册表的具体值
    ]

    eventdata_out = {
        k: win_eventdata.get(k)
        for k in eventdata_keep
        if win_eventdata.get(k) is not None and win_eventdata.get(k) != ""
    }

    win_out = {}
    if system_out:
        win_out["system"] = system_out
    if eventdata_out:
        win_out["eventdata"] = eventdata_out
    if win_out:
        out["data"] = {"win": win_out}

    return _prune(out)


def _format_iso8601(ts_raw: str) -> str:
    """
    辅助函数：将时间字符串格式化为标准的 ISO8601 以匹配 Elasticsearch 的 timestamp
    """
    if not ts_raw:
        return None
    ts_iso = str(ts_raw).strip().strip("'\"")
    ts_iso = ts_iso.replace(" ", "T", 1) if "T" not in ts_iso and " " in ts_iso else ts_iso
    if not re.search(r"(Z|z|[+-]\d{2}:?\d{2})$", ts_iso):
        ts_iso = f"{ts_iso}Z"
    return ts_iso


def search_archives_by_eventid(
    agent_id: str,
    query_type: str,
    query_value: str,
    event_ids: list[str],
    start_time: str = None,
    end_time: str = None,
):
    must_conditions = [{"term": {"agent.id": agent_id}}]

    # 时间过滤
    time_range = {}
    if start_time:
        time_range["gte"] = _format_iso8601(start_time)
    if end_time:
        time_range["lte"] = _format_iso8601(end_time)
    if time_range:
        must_conditions.append({"range": {"timestamp": time_range}})

    # EventID 过滤
    if event_ids:
        str_event_ids = [str(eid).strip() for eid in event_ids]
        must_conditions.append({"terms": {"data.win.system.eventID": str_event_ids}})

    val_str = str(query_value).strip()
    type_conditions = []

    # 3. 动态字段映射逻辑
    if query_type == QueryType.PROCESS_ID:
        type_conditions = [
            {"term": {"data.win.eventdata.processId": val_str}},
            {"term": {"data.win.eventdata.sourceProcessId": val_str}},
            {"term": {"data.win.eventdata.targetProcessId": val_str}},
        ]
    elif query_type == QueryType.PARENT_PROCESS_ID:
        type_conditions = [
            {"term": {"data.win.eventdata.parentProcessId": val_str}},
        ]
    elif query_type == QueryType.FILE_PATH:
        # 基于 query_string 实现模糊匹配
        query_str = f"*{val_str}*"
        type_conditions = [
            {
                "query_string": {
                    "query": query_str,
                    "fields": [
                        "data.win.eventdata.image",
                        "data.win.eventdata.imageLoaded",
                        "data.win.eventdata.sourceImage",
                        "data.win.eventdata.targetImage",
                        "data.win.eventdata.targetFilename",
                        "data.win.eventdata.imagePath",
                        "data.win.eventdata.commandLine",
                    ],
                }
            }
        ]

    elif query_type == QueryType.IP_ADDRESS:
        type_conditions = [
            {"term": {"data.win.eventdata.sourceIp": val_str}},
            {"term": {"data.win.eventdata.destinationIp": val_str}},
            {"term": {"data.win.eventdata.ipAddress": val_str}},
        ]

    elif query_type == QueryType.PORT:
        type_conditions = [
            {"term": {"data.win.eventdata.sourcePort": val_str}},
            {"term": {"data.win.eventdata.destinationPort": val_str}},
            {"term": {"data.win.eventdata.ipPort": val_str}},
        ]

    elif query_type == QueryType.SERVICE_NAME:
        # 基于 query_string 实现模糊匹配
        query_str = f"*{val_str}*"
        type_conditions = [
            {"query_string": {"query": query_str, "fields": ["data.win.eventdata.serviceName"]}}
        ]

    elif query_type == QueryType.USER_ACCOUNT:
        # 基于 query_string 实现模糊匹配段
        query_str = f"*{val_str}*"
        type_conditions = [
            {
                "query_string": {
                    "query": query_str,
                    "fields": [
                        "data.win.eventdata.user",
                        "data.win.eventdata.sourceUser",
                        "data.win.eventdata.targetUser",
                        "data.win.eventdata.accountName",
                        "data.win.eventdata.targetUserName",
                    ],
                }
            }
        ]

    elif query_type == QueryType.REGISTRY_PATH:
        # 基于 query_string 实现模糊匹配
        query_str = f"*{val_str}*"
        type_conditions = [
            {"query_string": {"query": query_str, "fields": ["data.win.eventdata.targetObject"]}}
        ]

    # 将 OR (should) 逻辑挂载到主查询中
    if type_conditions:
        must_conditions.append({"bool": {"should": type_conditions, "minimum_should_match": 1}})

    payload = {
        "size": 20,
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    try:
        response = agent_archives(agent_id, payload=payload)
        hits = response.get("hits", {}).get("hits", [])
        return [simplify_log(hit["_source"]) for hit in hits] if hits else []
    except Exception as e:
        logger.error(f"Error searching lateral activities: {e}")
        return []


@tool
def get_archives_by_eventid(
    agent_id: str,
    query_type: str,
    query_value: str,
    event_ids: list[str],
    start_time: str = None,
    end_time: str = None,
):
    """
    获取多维度的高危行为日志。当需要查询父子进程关联，或需要通过特定特征（如 IP、文件名、服务名、账号）横向追踪攻击痕迹时使用。

    :param agent_id: Agent 的唯一 ID
    :param query_type: 【必填】指示查询指标的枚举类型。一次调用只能使用以下一种类型：
        - "PROCESS_ID"   : 按进程 PID 追踪。可用于按子进程 PID 追踪其父进程日志。
        - "PARENT_PROCESS_ID" : 按父进程 PID 追踪其派生的子进程日志。
        - "FILE_PATH"    : 按文件路径或文件名追踪。
        - "IP_ADDRESS"   : 按源或目的 IP 地址追踪。
        - "PORT"         : 按源或目的网络端口追踪。
        - "SERVICE_NAME" : 按注册的系统服务名称追踪。
        - "USER_ACCOUNT" : 按操作系统用户或服务账号追踪。
        - "REGISTRY_PATH" : 按注册表路径追踪。
    :param query_value: 【必填】与 query_type 对应的具体数值。样例说明：
        - 若为 PROCESS_ID 或 PARENT_PROCESS_ID: 传入pid "6536"
        - 若为 FILE_PATH: 传入文件名 "PSEXESVC.EXE", "b.jsp" 或完整路径 "C:\\Windows\\System32\\"
        - 若为 IP_ADDRESS: 传入 "192.168.1.50"
        - 若为 PORT: 传入 "2024"
        - 若为 SERVICE_NAME: 传入"WMI"
        - 若为 USER_ACCOUNT: 传入 "LocalSystem", "Administrator"
        - 若为 REGISTRY_PATH: 传入 "CurrentControlSet\\Services\\bam" 或 "Run"
    :param event_ids: 【必填】目标 EventID 列表。请严格根据调查意图在下面给出的类型中选择对应的类别：
        - ["1"]              : 进程创建行为 (Process Creation) - 用于检测异常的进程启动、父子关系违规或参数混淆。
        - ["3","4624"]       : 网络连接行为 (Network Connection) - 用于检测 C2 通信、SMB 横向移动或异常端口访问。
        - ["7"]              : 模块加载行为 (Image/DLL Loading) - 用于检测恶意 DLL 注入、劫持或可疑模块调用。
        - ["8"]              : 进程注入行为 (Process Injection) - 用于检测 CreateRemoteThread 等跨进程的高危代码注入或执行规避动作。
        - ["10"]             : 进程访问行为(Process Access) - 用于检测一个进程尝试打开另一个进程句柄以进行内存读写或状态控制的行为。
        - ["11"]             : 文件创建行为 (File Creation) - 用于检测木马落地、WebShell 释放或临时文件生成。
        - ["25"]             : 进程篡改行为 (Process Tampering) - 用于检测进程在内存中的执行镜像被恶意修改或替换的行为。
        - ["7045"]           : 系统服务安装 (Service Installation) - 用于检测权限提升、持久化驻留或通过服务实现的横向移动。
        - ["12", "13", "14"] : 注册表行为 (Registry) - 用于检测注册表修改、删除或创建等操作。
    :param start_time: (可选) 限定查询时间窗口的起始时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    :param end_time: (可选) 限定查询时间窗口的结束时间。时间需要转换为标准的 ISO8601 格式 (如 "2026-03-09T17:24:47Z")
    """
    if not event_ids:
        return json.dumps(
            {"search_feedback": "You MUST provide a list of event_ids to search for."}
        )

    results = search_archives_by_eventid(
        agent_id, query_type, query_value, event_ids, start_time, end_time
    )
    if results:
        return json.dumps(results, ensure_ascii=False, indent=2)
    else:
        return json.dumps(
            {
                "search_feedback": f"No logs found for {query_type}={query_value} with event IDs {event_ids} within the specified time."
            }
        )
