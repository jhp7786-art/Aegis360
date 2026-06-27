"""
tools/aegis_wrapper.py
======================
Wrapper class for normalizing external security tool payloads.
"""

import json
from typing import Any, Dict, List


class KnoxPayload:
    """
    Normalizes security logs and threat intelligence payload data from various
    external tools into a standardized JSON format.

    Supported external tools:
        - Tortoise Siphon
        - Piggy Loader
        - Blueprint Bastard
        - Promotion Ghost
        - Phish Fryer
        - The Bouncer
    """

    ALLOWED_TOOLS: List[str] = [
        "Tortoise Siphon",
        "Piggy Loader",
        "Blueprint Bastard",
        "Promotion Ghost",
        "Phish Fryer",
        "The Bouncer"
    ]

    def __init__(self, tool_name: str, threat_level: Any, data: Any) -> None:
        """
        Initializes the KnoxPayload instance and normalizes input data.

        Args:
            tool_name: The name of the external security tool.
            threat_level: The raw threat level or severity of the payload.
            data: The raw payload data or JSON-serializable object.

        Raises:
            ValueError: If the tool name cannot be normalized to a supported tool.
        """
        self.tool_name: str = self._normalize_tool_name(tool_name)
        self.threat_level: str = self._normalize_threat_level(threat_level)
        self.data: Any = self._normalize_data(data)

    @classmethod
    def _normalize_tool_name(cls, tool_name: str) -> str:
        """
        Validates and normalizes the tool name to its canonical title-cased representation.

        Args:
            tool_name: Raw tool name.

        Returns:
            The canonical tool name.

        Raises:
            TypeError: If tool_name is not a string.
            ValueError: If tool_name is not recognized.
        """
        if not isinstance(tool_name, str):
            raise TypeError("tool_name must be a string")

        cleaned = tool_name.strip().lower().replace("_", " ").replace("-", " ")
        cleaned = " ".join(cleaned.split())

        # Match exact normalized string
        for allowed in cls.ALLOWED_TOOLS:
            if cleaned == allowed.lower():
                return allowed

        # Match without spaces
        cleaned_no_space = cleaned.replace(" ", "")
        for allowed in cls.ALLOWED_TOOLS:
            if cleaned_no_space == allowed.lower().replace(" ", ""):
                return allowed

        raise ValueError(
            f"Invalid tool_name '{tool_name}'. Must be one of: {', '.join(cls.ALLOWED_TOOLS)}"
        )

    @staticmethod
    def _normalize_threat_level(threat_level: Any) -> str:
        """
        Normalizes various threat level formats into a standard Severity string.
        Standard levels: 'Low', 'Medium', 'High', 'Critical'.

        Args:
            threat_level: Numeric or string representation of the threat level.

        Returns:
            A normalized severity level ('Low', 'Medium', 'High', 'Critical').
        """
        if threat_level is None:
            return "Low"

        # If it's a number, map ranges
        if isinstance(threat_level, (int, float)):
            if threat_level <= 2:
                return "Low"
            elif threat_level <= 5:
                return "Medium"
            elif threat_level <= 8:
                return "High"
            else:
                return "Critical"

        # Otherwise, process as string
        level_str = str(threat_level).strip().lower()

        # Exact/prefix matches
        if level_str in ("low", "info", "informational", "l", "1", "2"):
            return "Low"
        elif level_str in ("medium", "med", "warning", "warn", "m", "3", "4", "5"):
            return "Medium"
        elif level_str in ("high", "error", "h", "6", "7", "8"):
            return "High"
        elif level_str in ("critical", "crit", "fatal", "panic", "c", "9", "10"):
            return "Critical"

        # Fallback default
        return "Medium"

    @staticmethod
    def _normalize_data(data: Any) -> Any:
        """
        Normalizes the payload data. If it is a valid JSON string, parses it
        into a native Python representation to avoid double serialization.

        Args:
            data: Raw payload data.

        Returns:
            Normalized python structure or string.
        """
        if isinstance(data, str):
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return data
        return data

    def to_json(self, indent: int = None) -> str:
        """
        Serializes the normalized payload data to a strict JSON structure.

        Args:
            indent: Optional indentation level for pretty printing.

        Returns:
            A strict JSON string containing 'ToolName', 'Severity', and 'PayloadData'.
        """
        payload: Dict[str, Any] = {
            "ToolName": self.tool_name,
            "Severity": self.threat_level,
            "PayloadData": self.data
        }
        return json.dumps(payload, indent=indent)
