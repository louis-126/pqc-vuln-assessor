"""Web model-discovery tests that never call external providers."""
from __future__ import annotations

import os
import unittest
from unittest.mock import Mock, patch

import httpx

from web.app import ANTHROPIC_MODELS_URL, app


class AnthropicModelDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index_has_provider_driven_model_dropdowns(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('id="model-select"', page)
        self.assertIn('id="reviewer-model-select"', page)
        self.assertNotIn('id="model-selection-summary"', page)
        self.assertNotIn("claude-3-7-sonnet", page)

    def test_missing_api_key_does_not_attempt_discovery(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            with patch("web.app.httpx.get") as get:
                response = self.client.get("/api/backend-check?backend=anthropic")

        payload = response.get_json()
        self.assertFalse(payload["ready"])
        self.assertEqual(payload["models"], [])
        get.assert_not_called()

    def test_models_are_loaded_live_and_newest_is_the_default(self):
        provider_response = Mock()
        provider_response.raise_for_status.return_value = None
        provider_response.json.return_value = {
            "data": [
                {
                    "id": "claude-newest",
                    "display_name": "Claude Newest",
                    "created_at": "2026-07-01T00:00:00Z",
                },
                {
                    "id": "claude-previous",
                    "display_name": "Claude Previous",
                    "created_at": "2026-01-01T00:00:00Z",
                },
            ],
        }

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-secret"}):
            with patch("web.app.httpx.get", return_value=provider_response) as get:
                response = self.client.get("/api/backend-check?backend=anthropic")

        payload = response.get_json()
        self.assertTrue(payload["ready"])
        self.assertEqual(payload["models"], ["claude-newest", "claude-previous"])
        self.assertEqual(payload["default_model"], "claude-newest")
        self.assertEqual(payload["model_options"][0]["display_name"], "Claude Newest")
        get.assert_called_once_with(
            ANTHROPIC_MODELS_URL,
            headers={
                "x-api-key": "test-secret",
                "anthropic-version": "2023-06-01",
            },
            params={"limit": 1000},
            timeout=8.0,
        )
        self.assertNotIn("test-secret", response.get_data(as_text=True))

    def test_provider_authentication_failure_blocks_backend(self):
        request = httpx.Request("GET", ANTHROPIC_MODELS_URL)
        denied = httpx.Response(401, request=request)
        provider_response = Mock()
        provider_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "unauthorized",
            request=request,
            response=denied,
        )

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "bad-secret"}):
            with patch("web.app.httpx.get", return_value=provider_response):
                response = self.client.get("/api/backend-check?backend=anthropic")

        payload = response.get_json()
        self.assertFalse(payload["ready"])
        self.assertEqual(payload["models"], [])
        self.assertIn("HTTP 401", payload["message"])
        self.assertNotIn("bad-secret", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
