"""
backend/salesfort_bridge.py
===========================
Salesforce OAuth 2.0 JWT Bearer Bridge & Knox Payload Integration.
"""

import json
import os
import time
from typing import Any, Dict, Tuple, Union
import jwt
import requests


def generate_jwt(
    client_id: str,
    username: str,
    private_key: str,
    audience: str = "https://login.salesforce.com"
) -> str:
    """
    Generates and signs a JWT assertion for the Salesforce OAuth 2.0 JWT Bearer flow (RS256).

    Args:
        client_id: The Salesforce Connected App Client ID (Consumer Key).
        username: The Salesforce username to authenticate as.
        private_key: The PEM-encoded private key content.
        audience: The Salesforce login host URL (e.g., https://login.salesforce.com).

    Returns:
        The signed and encoded JWT assertion string.
    """
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": username,
        "aud": audience,
        "exp": now + 300  # Expires in 5 minutes
    }
    # RS256 algorithm signing
    signed_jwt = jwt.encode(payload, private_key, algorithm="RS256")
    
    if isinstance(signed_jwt, bytes):
        return signed_jwt.decode("utf-8")
    return signed_jwt


def get_access_token() -> Tuple[str, str]:
    """
    Retrieves an OAuth access token and instance URL from Salesforce using the JWT Bearer flow.

    The private key and client ID are loaded securely from environment variables:
      - SALESFORCE_CLIENT_ID: Salesforce Client ID / Consumer Key.
      - SALESFORCE_PRIVATE_KEY: Raw PEM private key contents or path to a PEM file.
      - SALESFORCE_USERNAME: The Salesforce username.
      - SALESFORCE_AUDIENCE: (Optional) Target authentication host (defaults to production).

    Returns:
        A tuple of (access_token, instance_url).

    Raises:
        ValueError: If required environment configurations are missing.
        RuntimeError: If authentication request fails or returns an error.
    """
    client_id = os.environ.get("SALESFORCE_CLIENT_ID")
    private_key_env = os.environ.get("SALESFORCE_PRIVATE_KEY")
    username = os.environ.get("SALESFORCE_USERNAME")
    audience = os.environ.get("SALESFORCE_AUDIENCE", "https://login.salesforce.com")

    if not client_id or not private_key_env or not username:
        raise ValueError(
            "Missing required environment variables for Salesforce OAuth: "
            "SALESFORCE_CLIENT_ID, SALESFORCE_PRIVATE_KEY, and SALESFORCE_USERNAME must be configured."
        )

    # Resolve private key (check if it points to a file, otherwise treat as raw PEM string)
    if os.path.exists(private_key_env):
        with open(private_key_env, "r", encoding="utf-8") as key_file:
            private_key = key_file.read()
    else:
        private_key = private_key_env

    private_key = private_key.strip()

    # Generate the signed JWT assertion
    assertion = generate_jwt(client_id, username, private_key, audience)

    token_url = f"{audience.rstrip('/')}/services/oauth2/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion
    }

    try:
        response = requests.post(token_url, data=data, timeout=15)
        response.raise_for_status()
        response_data = response.json()
        return response_data["access_token"], response_data["instance_url"]
    except requests.exceptions.HTTPError as http_err:
        try:
            err_json = response.json()
            err_msg = f"Salesforce Auth Error: {err_json.get('error')} - {err_json.get('error_description')}"
        except Exception:
            err_msg = f"HTTP authentication response returned error: {http_err}"
        raise RuntimeError(err_msg) from http_err
    except requests.exceptions.Timeout as timeout_err:
        raise RuntimeError(f"Salesforce login request timed out: {timeout_err}") from timeout_err
    except requests.exceptions.RequestException as req_err:
        raise RuntimeError(f"Failed to connect to Salesforce login endpoint: {req_err}") from req_err


# Cache tokens locally to minimize repeated JWT exchanges
_cached_token: Union[str, None] = None
_cached_instance_url: Union[str, None] = None


def push_to_knox(endpoint: str, json_payload: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Pushes a KnoxPayload JSON structure to a custom Salesforce Apex REST endpoint.

    If the cached token is invalid or missing, authenticates automatically.
    Includes connection retry logic on HTTP 401 Unauthorized responses.

    Args:
        endpoint: Suffix of the custom Apex REST endpoint (e.g., '/TIP/').
        json_payload: Normalized KnoxPayload JSON string or matching dictionary.

    Returns:
        The parsed JSON dictionary returned by the Salesforce endpoint.

    Raises:
        ValueError: If the payload is invalid JSON.
        RuntimeError: On connection timeouts, invalid tokens, or networking errors.
    """
    global _cached_token, _cached_instance_url

    # Authenticate if token is not cached
    if not _cached_token or not _cached_instance_url:
        try:
            _cached_token, _cached_instance_url = get_access_token()
        except Exception as auth_err:
            raise RuntimeError(f"Salesforce authentication failed: {auth_err}") from auth_err

    # Sanitize and validate JSON payload format
    if isinstance(json_payload, str):
        try:
            json.loads(json_payload)  # Validate string is correct JSON
            data_body = json_payload
        except json.JSONDecodeError as decode_err:
            raise ValueError(f"Invalid JSON string payload: {decode_err}") from decode_err
    else:
        try:
            data_body = json.dumps(json_payload)
        except (TypeError, ValueError) as json_err:
            raise ValueError(f"Payload dictionary could not be serialized: {json_err}") from json_err

    # Format the target endpoint URL
    clean_endpoint = endpoint.strip()
    if not clean_endpoint.startswith("/"):
        clean_endpoint = "/" + clean_endpoint
    url = f"{_cached_instance_url.rstrip('/')}/services/apexrest{clean_endpoint}"

    headers = {
        "Authorization": f"Bearer {_cached_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, data=data_body, headers=headers, timeout=15)

        # Handle expired / invalid token with a single retry
        if response.status_code == 401:
            # Refresh cached token and retry
            _cached_token, _cached_instance_url = get_access_token()
            retry_headers = headers.copy()
            retry_headers["Authorization"] = f"Bearer {_cached_token}"
            url = f"{_cached_instance_url.rstrip('/')}/services/apexrest{clean_endpoint}"
            
            response = requests.post(url, data=data_body, headers=retry_headers, timeout=15)

        response.raise_for_status()

        try:
            return response.json()
        except json.JSONDecodeError:
            return {"status": "success", "raw_response": response.text}

    except requests.exceptions.Timeout as timeout_err:
        raise RuntimeError(f"Connection to Salesforce API timed out: {timeout_err}") from timeout_err
    except requests.exceptions.RequestException as req_err:
        raise RuntimeError(f"Salesforce API connection failed: {req_err}") from req_err
