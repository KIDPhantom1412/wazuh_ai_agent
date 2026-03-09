import logging
import re
from pathlib import Path

from langchain.tools import tool

logger = logging.getLogger(__name__)

RULE_SYNTAX_FILE = Path(__file__).parents[3] / "documents/skill/rule_syntax.md"

_skills_cache: dict[str, str] | None = None


def _parse_rule_syntax_file() -> dict[str, str]:
    """Parse rule_syntax.md and extract content under level-3 headings.

    Returns:
        Dictionary mapping skill names (heading text) to their content.
    """
    global _skills_cache

    if _skills_cache is not None:
        return _skills_cache

    skills: dict[str, str] = {}

    try:
        if not RULE_SYNTAX_FILE.exists():
            logger.error(f"Rule syntax file not found: {RULE_SYNTAX_FILE}")
            return skills

        content = RULE_SYNTAX_FILE.read_text(encoding="utf-8")

        # Regex explanation:
        # ^###\s+(.*?)\s*\n  -> Match an H3 header (### Name)
        # (.*?)              -> Capture everything (non-greedy)
        # (?=^#{1,3}\s+|\Z)  -> Stop when we hit the next header (#, ##, or ###) or end of file
        # re.MULTILINE       -> Make ^ match start of line
        # re.DOTALL          -> Make . match newlines
        pattern = r"^###\s+(.*?)\s*\n(.*?)(?=^#{1,3}\s+|\Z)"
        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)

        for match in matches:
            heading = match.group(1).strip()
            # Remove any Markdown escaping like \_
            normalized_name = heading.replace("\\_", "_")
            body = match.group(2).strip()
            skills[normalized_name] = body

        _skills_cache = skills
        logger.info(f"Successfully parsed {len(skills)} skills from rule_syntax.md using regex")

    except Exception as e:
        logger.error(f"Error parsing rule_syntax.md: {e}")

    return skills


@tool
def load_skill(name: str) -> str:
    """Load detailed information about a Wazuh rule option/skill.

    Args:
        name: The name of the skill to load (e.g., 'match', 'regex', 'if_sid').

    Returns:
        Detailed documentation about the requested skill.
    """
    skills = _parse_rule_syntax_file()
    if name not in skills:
        return f"Skill '{name}' not found. Available skills: {', '.join(skills.keys())}"

    return skills[name]


def get_skill_descriptions() -> list[dict]:
    """Get descriptions of all available skills.

    Returns:
        List of dictionaries with 'name' and 'description' keys.
    """
    return SKILLS


SKILLS: list[dict] = [
    {
        "name": "action",
        "description": "Compares a string or regular expression representing an action with a value decoded as `action`.",
    },
    {
        "name": "category",
        "description": "Matches logs with the corresponding decoder's type.",
    },
    {
        "name": "check_diff",
        "description": "Determines when the output of a command changes.",
    },
    {
        "name": "data",
        "description": "Compares a regular expression representing data with a value decoded as `data`.",
    },
    {
        "name": "decoded_as",
        "description": "Matches with logs that have been decoded by a specific decoder.",
    },
    {
        "name": "default_match_type",
        "description": "Sets the default match type for regex-based comparisons.",
    },
    {
        "name": "description",
        "description": "Specifies the description of the rule.",
    },
    {
        "name": "different_field",
        "description": "The value of the dynamic field specified in this option must differ from those found in previous events a certain number of times.",
    },
    {
        "name": "different_url",
        "description": "The URL decoded as `url` must differ from those found in previous events a certain number of times.",
    },
    {
        "name": "different_user",
        "description": "The user decoded as `user` must differ from those found in previous events a certain number of times.",
    },
    {
        "name": "dstip",
        "description": "Compares the IP address with the IP decoded as `dstip`.",
    },
    {
        "name": "dstport",
        "description": "Compares a regular expression representing a port with a value decoded as `dstport`.",
    },
    {
        "name": "dstuser",
        "description": "Compares a regular expression representing a user with a value decoded as `dstuser`.",
    },
    {
        "name": "extra_data",
        "description": "Compares a regular expression representing data with a value decoded as `extra_data`.",
    },
    {
        "name": "field",
        "description": "Compares a field extracted by the decoder in order with a regular expression.",
    },
    {
        "name": "field_attribute",
        "description": "Specifies the name of the field extracted by the decoder.",
    },
    {
        "name": "firedtimes",
        "description": "Specifies the number of times the rule must be triggered before the alert is generated.",
    },
    {
        "name": "frequency",
        "description": "Specifies the number of times the rule must be triggered before the alert is generated.",
    },
    {
        "name": "global_frequency",
        "description": "Specifies that events of all agents will be contemplated for frequency/timeframe options.",
    },
    {
        "name": "group",
        "description": "Add additional groups to the alert.",
    },
    {
        "name": "hostname",
        "description": "Compares a regular expression representing a hostname with a value pre-decoded as `hostname`.",
    },
    {
        "name": "id",
        "description": "Compares a regular expression representing an ID with a value decoded as `id`.",
    },
    {
        "name": "id_attribute",
        "description": "Specifies the ID of the rule (1 to 999999).",
    },
    {
        "name": "if_fts",
        "description": "Makes the decoder that processed the event to take the fts line into consideration.",
    },
    {
        "name": "if_group",
        "description": "Matches if the indicated group has matched before.",
    },
    {
        "name": "if_level",
        "description": "Matches if that level has already been triggered by another rule.",
    },
    {
        "name": "if_matched_group",
        "description": "Similar to if_group but it will only match if the group has been triggered in a period of time.",
    },
    {
        "name": "if_matched_sid",
        "description": "Similar to if_sid but it will only match if the ID has been triggered in a period of time.",
    },
    {
        "name": "if_sid",
        "description": "Matches if the ID of the rule that has already been triggered is the same as the one indicated.",
    },
    {
        "name": "ignore",
        "description": "The rule will not be triggered if the value of the field matches the regular expression.",
    },
    {
        "name": "info",
        "description": "Add additional information to the alert.",
    },
    {
        "name": "level_attribute",
        "description": "Specifies the severity level of the rule (0 to 16).",
    },
    {
        "name": "list",
        "description": "Matches if the value of the field is in the specified list.",
    },
    {
        "name": "location",
        "description": "Compares a regular expression representing a location with the location where the event was generated.",
    },
    {
        "name": "match",
        "description": "Attempts to find a match in the log using sregex by default, deciding if the rule should be triggered.",
    },
    {
        "name": "max_firedtimes",
        "description": "Specifies the maximum number of times the rule can be triggered.",
    },
    {
        "name": "max_reltime",
        "description": "Specifies the maximum time between two events.",
    },
    {
        "name": "mitre",
        "description": "Add MITRE ATT&CK information to the alert.",
    },
    {
        "name": "no_full_log",
        "description": "Does not include the full log in the alert.",
    },
    {
        "name": "options",
        "description": "Sets additional options for the rule.",
    },
    {
        "name": "pci_dss",
        "description": "Add PCI DSS information to the alert.",
    },
    {
        "name": "program_name",
        "description": "Compares a regular expression representing a program name with a value decoded as `program_name`.",
    },
    {
        "name": "protocol",
        "description": "Compares a regular expression representing a protocol with a value decoded as `protocol`.",
    },
    {
        "name": "regex",
        "description": "Does the same as `match`, but with regex as default.",
    },
    {
        "name": "rule",
        "description": "Declares a new rule and its defining options.",
    },
    {
        "name": "same_field",
        "description": "The value of the dynamic field specified in this option must be the same as those found in previous events a certain number of times.",
    },
    {
        "name": "same_id",
        "description": "The ID decoded as `id` must be the same as those found in previous events a certain number of times.",
    },
    {
        "name": "same_location",
        "description": "The location where the event was generated must be the same as those found in previous events a certain number of times.",
    },
    {
        "name": "same_source_ip",
        "description": "The source IP address must be the same as those found in previous events a certain number of times.",
    },
    {
        "name": "same_user",
        "description": "The user decoded as `user` must be the same as those found in previous events a certain number of times.",
    },
    {
        "name": "script",
        "description": "Executes a script when the rule is triggered.",
    },
    {
        "name": "srcip",
        "description": "Compares the IP address with the IP decoded as `srcip`.",
    },
    {
        "name": "srcport",
        "description": "Compares a regular expression representing a port with a value decoded as `srcport`.",
    },
    {
        "name": "status",
        "description": "Compares a regular expression representing a status with a value decoded as `status`.",
    },
    {
        "name": "system_name",
        "description": "Compares a regular expression representing a system name with a value decoded as `system_name`.",
    },
    {
        "name": "time",
        "description": "Checks if the event was generated during that time range.",
    },
    {
        "name": "timeframe",
        "description": "The timeframe in seconds, intended to be used with frequency.",
    },
    {
        "name": "url",
        "description": "Compares a regular expression representing a URL with a value decoded as `url`.",
    },
    {
        "name": "user",
        "description": "Compares a regular expression representing a user with a value decoded as `user`.",
    },
    {
        "name": "var",
        "description": "Defines a variable that can be used anywhere inside the same file.",
    },
    {
        "name": "weekday",
        "description": "Checks whether the event was generated during certain weekdays.",
    },
]
