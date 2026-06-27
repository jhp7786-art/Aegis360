"""
backend/test_salesfort_bridge.py
================================
Unit tests for salesfort_bridge.py.
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch
import requests

# Set dummy environment variables for import and test setup
os.environ["SALESFORCE_CLIENT_ID"] = "dummy_client_id"
os.environ["SALESFORCE_PRIVATE_KEY"] = "dummy_private_key"
os.environ["SALESFORCE_USERNAME"] = "dummy_user@example.com"
os.environ["SALESFORCE_AUDIENCE"] = "https://login.salesforce.com"

from backend.salesfort_bridge import (
    generate_jwt,
    get_access_token,
    push_to_knox,
    _cached_token,
    _cached_instance_url,
)


class TestSalesforceBridge(unittest.TestCase):
    def setUp(self):
        # Reset cached tokens before each test
        import backend.salesfort_bridge
        backend.salesfort_bridge._cached_token = None
        backend.salesfort_bridge._cached_instance_url = None

    @patch("backend.salesfort_bridge.jwt.encode")
    def test_generate_jwt(self, mock_jwt_encode):
        mock_jwt_encode.return_value = "mocked_jwt_string"
        jwt_str = generate_jwt("client_id", "user@test.com", "private_key", "https://login.salesforce.com")
        
        self.assertEqual(jwt_str, "mocked_jwt_string")
        mock_jwt_encode.assert_called_once()

    @patch("backend.salesfort_bridge.generate_jwt")
    @patch("backend.salesfort_bridge.requests.post")
    def test_get_access_token_success(self, mock_post, mock_gen_jwt):
        mock_gen_jwt.return_value = "mock_jwt_assertion"
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "mock_token_123",
            "instance_url": "https://na101.salesforce.com"
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        token, instance_url = get_access_token()
        self.assertEqual(token, "mock_token_123")
        self.assertEqual(instance_url, "https://na101.salesforce.com")

        mock_post.assert_called_once_with(
            "https://login.salesforce.com/services/oauth2/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": "mock_jwt_assertion"
            },
            timeout=15
        )

    @patch("backend.salesfort_bridge.get_access_token")
    @patch("backend.salesfort_bridge.requests.post")
    def test_push_to_knox_success(self, mock_post, mock_get_token):
        mock_get_token.return_value = ("mock_token", "https://myorg.salesforce.com")
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "synced"}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        payload = {"ToolName": "The Bouncer", "Severity": "Low"}
        res = push_to_knox("/TIP/", payload)

        self.assertEqual(res, {"status": "synced"})
        mock_post.assert_called_once_with(
            "https://myorg.salesforce.com/services/apexrest/TIP/",
            data=json.dumps(payload),
            headers={
                "Authorization": "Bearer mock_token",
                "Content-Type": "application/json"
            },
            timeout=15
        )

    @patch("backend.salesfort_bridge.get_access_token")
    @patch("backend.salesfort_bridge.requests.post")
    def test_push_to_knox_unauthorized_retry(self, mock_post, mock_get_token):
        # First call to auth returns first token, second call (during retry) returns second token
        mock_get_token.side_effect = [
            ("expired_token", "https://myorg.salesforce.com"),
            ("new_token", "https://myorg.salesforce.com")
        ]

        # First request returns 401 Unauthorized, second request returns 200 OK
        mock_response_401 = MagicMock()
        mock_response_401.status_code = 401

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"status": "synced_after_retry"}
        mock_response_200.raise_for_status = MagicMock()

        mock_post.side_effect = [mock_response_401, mock_response_200]

        payload = {"ToolName": "Phish Fryer", "Severity": "High"}
        res = push_to_knox("/TIP/", payload)

        self.assertEqual(res, {"status": "synced_after_retry"})
        
        # Verify post was called twice: first with expired_token, then with new_token
        self.assertEqual(mock_post.call_count, 2)
        
        # Verify first call headers
        first_call_args = mock_post.call_args_list[0]
        self.assertEqual(first_call_args[1]["headers"]["Authorization"], "Bearer expired_token")
        
        # Verify second call headers
        second_call_args = mock_post.call_args_list[1]
        self.assertEqual(second_call_args[1]["headers"]["Authorization"], "Bearer new_token")

    @patch("backend.salesfort_bridge.get_access_token")
    @patch("backend.salesfort_bridge.requests.post")
    def test_push_to_knox_timeout(self, mock_post, mock_get_token):
        mock_get_token.return_value = ("mock_token", "https://myorg.salesforce.com")
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        with self.assertRaises(RuntimeError) as context:
            push_to_knox("/TIP/", {})

        self.assertIn("Connection to Salesforce API timed out", str(context.exception))


if __name__ == "__main__":
    unittest.main()
