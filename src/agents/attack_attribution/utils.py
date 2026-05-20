import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wazuh_api.server_api import list_agents

logger = logging.getLogger(__name__)


def load_skill(filepath: str | Path) -> dict:
    """
    读取并解析 Markdown skill文件。
    """
    path = Path(filepath)
    if not path.exists():
        logger.error(f"Skill file not found: {path}")
        return {}

    try:
        raw_text = path.read_text(encoding="utf-8")
        match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)", raw_text, re.DOTALL)

        if not match:
            logger.error(f"Invalid format: {path} must contain YAML Front Matter (---).")
            return {}

        front_matter, content = match.group(1), match.group(2).strip()

        # 提取键值对
        metadata = {}
        for line in front_matter.split("\n"):
            if ":" in line:
                parts = line.split(":", 1)
                k = parts[0]
                v = parts[1]
                metadata[k.strip()] = v.strip()

        # 返回结构化数据
        return {
            "name": metadata.get("name", "unknown"),
            "description": metadata.get("description", ""),
            "content": content,
        }

    except Exception as e:
        logger.error(f"Failed to parse skill file {path}: {e}")
        return {}


def load_mitre(filepath: str | Path, technique_id: str) -> str:
    """
    从mitre知识库文件中提取 MITRE 技术。
    注意：如果搜索主技术（如 T1001），会自动包含其所有的子技术（如 T1001.001, T1001.002）。
    """
    path = Path(filepath)
    if not path.exists():
        logger.error(f"MITRE KnowledgeBase file not found: {path}")
        return ""

    tid = technique_id.strip().upper()

    capturing = False
    captured_text = []

    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("## T"):
                    heading_id = line[3:].strip().split()[0]

                    # if heading_id == tid or heading_id.startswith(f"{tid}."):
                    if heading_id == tid:
                        capturing = True
                        captured_text.append(line)
                    else:
                        if capturing:
                            break
                elif capturing:
                    captured_text.append(line)

        return "".join(captured_text).strip()

    except Exception as e:
        logger.error(f"Failed to read MITRE KB {path}: {e}")
        return ""


def extract_agent_ip_mapping() -> dict[str, str]:
    """
    获取 Wazuh Agent ID 与 IP 的映射字典。
    """
    ip_mapping = {}

    try:
        api_response = list_agents()
        agents = api_response.get("data", {}).get("affected_items", [])

        for agent in agents:
            agent_id = agent.get("id")
            agent_ip = agent.get("ip")

            # 过滤掉id=000的情况
            if agent_id and agent_ip and agent_id != "000":
                ip_mapping[agent_id] = agent_ip

    except Exception as e:
        logger.info(f"Exception occurred while extracting Agent IP mapping: {e}")

    return ip_mapping


BEIJING_TZ = timezone(timedelta(hours=8))


def extract_beijing_time_from_logs(text: str) -> dict | None:
    """
    扫描用户输入中的 Wazuh/ES 日志，提取 _source.timestamp 作为唯一时间来源。
    _source.timestamp 已包含时区信息（如 +0800），无需额外转换。

    Returns:
        dict with keys beijing_start, beijing_end (ISO8601 +08:00),
        beijing_display (人类可读字符串)。未找到时间戳返回 None。
    """
    timestamps = []

    try:
        parsed = json.loads(text)
        _collect_source_timestamps(parsed, timestamps)
    except json.JSONDecodeError:
        pass

    if not timestamps:
        for candidate in _iter_json_candidates(text):
            try:
                obj = json.loads(candidate)
                _collect_source_timestamps(obj, timestamps)
            except json.JSONDecodeError:
                continue

    if not timestamps:
        return None

    timestamps.sort()
    earliest = timestamps[0]
    latest = timestamps[-1]

    # 统一归一化到北京时间，以防少数 agent 时区不同
    window_start = (earliest - timedelta(minutes=10)).astimezone(BEIJING_TZ)
    window_end = (latest + timedelta(minutes=10)).astimezone(BEIJING_TZ)

    return {
        "beijing_start": window_start.isoformat(),
        "beijing_end": window_end.isoformat(),
        "beijing_display": f"{window_start.strftime('%Y-%m-%d %H:%M:%S')} 至 "
        f"{window_end.strftime('%Y-%m-%d %H:%M:%S')}（北京时间）",
    }


def _collect_source_timestamps(obj, out_list: list):
    """递归收集 _source.timestamp（已含时区信息）。"""
    if isinstance(obj, dict):
        source = obj.get("_source")
        if isinstance(source, dict):
            ts = source.get("timestamp")
            if isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts)
                    if dt not in out_list:
                        out_list.append(dt)
                except (ValueError, TypeError):
                    pass

        for v in obj.values():
            _collect_source_timestamps(v, out_list)
    elif isinstance(obj, list):
        for item in obj:
            _collect_source_timestamps(item, out_list)


def _iter_json_candidates(text: str):
    """从任意文本中提取平衡大括号的 JSON 候选片段。"""
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                yield text[start : i + 1]
                start = -1


if __name__ == "__main__":
    from pathlib import Path

    CURRENT_DIR = Path(__file__).parent
    MITRE_KB_FILE_PATH = (
        CURRENT_DIR.parent.parent
        / "documents"
        / "skill"
        / "attribution_skills"
        / "mitre_knowledgebase.md"
    )
    technique_id = "T1001"
    external_knowldege = load_mitre(MITRE_KB_FILE_PATH, technique_id)
    print(external_knowldege)

    print("Agent ID -> IP Mapping:")
    print(extract_agent_ip_mapping())
