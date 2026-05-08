import logging
import re
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
