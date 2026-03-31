import logging
import re
from pathlib import Path

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
