"""
tools/test_aegis_wrapper.py
===========================
Unit tests for KnoxPayload class.
"""

import json
import unittest
from tools.aegis_wrapper import KnoxPayload


class TestKnoxPayload(unittest.TestCase):
    def test_tool_name_normalization(self):
        # Test exact match
        payload = KnoxPayload("Tortoise Siphon", "High", "some_data")
        self.assertEqual(payload.tool_name, "Tortoise Siphon")

        # Test case insensitivity and spaces
        payload = KnoxPayload("  tortoise_siphon  ", "High", "some_data")
        self.assertEqual(payload.tool_name, "Tortoise Siphon")

        payload = KnoxPayload("piggy-loader", "Medium", {})
        self.assertEqual(payload.tool_name, "Piggy Loader")

        payload = KnoxPayload("blueprintbastard", 2, "data")
        self.assertEqual(payload.tool_name, "Blueprint Bastard")

        payload = KnoxPayload("THE_BOUNCER", "Critical", [])
        self.assertEqual(payload.tool_name, "The Bouncer")

    def test_invalid_tool_name(self):
        with self.assertRaises(ValueError):
            KnoxPayload("Invalid Tool", "High", "data")

    def test_threat_level_normalization(self):
        # Test integer mapping
        self.assertEqual(KnoxPayload("Phish Fryer", 1, "").threat_level, "Low")
        self.assertEqual(KnoxPayload("Phish Fryer", 2, "").threat_level, "Low")
        self.assertEqual(KnoxPayload("Phish Fryer", 4, "").threat_level, "Medium")
        self.assertEqual(KnoxPayload("Phish Fryer", 5, "").threat_level, "Medium")
        self.assertEqual(KnoxPayload("Phish Fryer", 7, "").threat_level, "High")
        self.assertEqual(KnoxPayload("Phish Fryer", 8, "").threat_level, "High")
        self.assertEqual(KnoxPayload("Phish Fryer", 9, "").threat_level, "Critical")
        self.assertEqual(KnoxPayload("Phish Fryer", 10, "").threat_level, "Critical")

        # Test string mapping
        self.assertEqual(KnoxPayload("Phish Fryer", "low", "").threat_level, "Low")
        self.assertEqual(KnoxPayload("Phish Fryer", "INFO", "").threat_level, "Low")
        self.assertEqual(KnoxPayload("Phish Fryer", "warning", "").threat_level, "Medium")
        self.assertEqual(KnoxPayload("Phish Fryer", "error", "").threat_level, "High")
        self.assertEqual(KnoxPayload("Phish Fryer", "fatal", "").threat_level, "Critical")

        # Test default fallback
        self.assertEqual(KnoxPayload("Phish Fryer", "unknown_level", "").threat_level, "Medium")
        self.assertEqual(KnoxPayload("Phish Fryer", None, "").threat_level, "Low")

    def test_data_normalization(self):
        # Test dictionary data
        data_dict = {"ip": "192.168.1.1", "action": "blocked"}
        payload = KnoxPayload("The Bouncer", "High", data_dict)
        self.assertEqual(payload.data, data_dict)

        # Test JSON string data parsing
        json_str = '{"ip": "10.0.0.1", "status": "alert"}'
        payload = KnoxPayload("The Bouncer", "High", json_str)
        self.assertEqual(payload.data, {"ip": "10.0.0.1", "status": "alert"})

        # Test invalid JSON string remains string
        invalid_json = '{"ip": "10.0.0.1", invalid'
        payload = KnoxPayload("The Bouncer", "High", invalid_json)
        self.assertEqual(payload.data, invalid_json)

    def test_to_json(self):
        data = {"event": "login_attempt", "success": False}
        payload = KnoxPayload("Blueprint Bastard", 8, data)
        
        json_output = payload.to_json()
        parsed = json.loads(json_output)
        
        self.assertEqual(parsed["ToolName"], "Blueprint Bastard")
        self.assertEqual(parsed["Severity"], "High")
        self.assertEqual(parsed["PayloadData"], data)


if __name__ == "__main__":
    unittest.main()
