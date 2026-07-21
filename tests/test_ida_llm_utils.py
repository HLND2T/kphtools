import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import ida_llm_utils


class TestRequireNonemptyText(unittest.TestCase):
    def test_require_nonempty_text_returns_stripped_text(self) -> None:
        self.assertEqual(
            "hello",
            ida_llm_utils.require_nonempty_text("  hello  ", "value"),
        )

    def test_require_nonempty_text_raises_value_error_for_blank_text(self) -> None:
        with self.assertRaises(ValueError):
            ida_llm_utils.require_nonempty_text("   ", "value")


class TestCreateOpenAiClient(unittest.TestCase):
    def test_create_openai_client_raises_when_api_key_missing(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "LLM API key required"):
            ida_llm_utils.create_openai_client(
                None,
                api_key_required_message="LLM API key required",
            )

    @patch("ida_llm_utils.AsyncOpenAI")
    def test_create_openai_client_uses_trimmed_values(self, mock_openai) -> None:
        mock_client = object()
        mock_openai.return_value = mock_client

        client = ida_llm_utils.create_openai_client(
            "  test-api-key  ",
            "  https://example.invalid/v1  ",
            api_key_required_message="unused",
        )

        self.assertIs(mock_client, client)
        mock_openai.assert_called_once_with(
            api_key="test-api-key",
            base_url="https://example.invalid/v1",
        )


class TestNormalizeOptionalValues(unittest.TestCase):
    def test_effort_defaults_to_medium_and_normalizes_explicit_value(self) -> None:
        self.assertEqual("medium", ida_llm_utils.normalize_optional_effort(None))
        self.assertEqual("medium", ida_llm_utils.normalize_optional_effort("   "))
        self.assertEqual("high", ida_llm_utils.normalize_optional_effort(" HIGH "))

    def test_effort_rejects_unknown_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "effort must be one of"):
            ida_llm_utils.normalize_optional_effort("turbo")

    def test_temperature_normalizes_numeric_string_and_blank(self) -> None:
        self.assertEqual(
            0.25,
            ida_llm_utils.normalize_optional_temperature(" 0.25 "),
        )
        self.assertIsNone(ida_llm_utils.normalize_optional_temperature("  "))

    def test_temperature_rejects_non_numeric_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "temperature must be a number"):
            ida_llm_utils.normalize_optional_temperature("cold")


class TestExtractFirstMessageText(unittest.TestCase):
    def test_extracts_string_and_multipart_content(self) -> None:
        string_response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="hello"))]
        )
        multipart_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=[
                            SimpleNamespace(text="hello "),
                            {"text": "from "},
                            SimpleNamespace(text="parts"),
                        ]
                    )
                )
            ]
        )

        self.assertEqual(
            "hello",
            ida_llm_utils.extract_first_message_text(string_response),
        )
        self.assertEqual(
            "hello from parts",
            ida_llm_utils.extract_first_message_text(multipart_response),
        )

    def test_extracts_top_level_text_attribute(self) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=SimpleNamespace(text="attribute text")
                    )
                )
            ]
        )

        self.assertEqual(
            "attribute text",
            ida_llm_utils.extract_first_message_text(response),
        )

    def test_raises_value_error_on_empty_choices(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing choices"):
            ida_llm_utils.extract_first_message_text(SimpleNamespace(choices=[]))


class TestCallLlmText(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _client_with_response(content):
        create = AsyncMock(
            return_value=SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            )
        )
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )
        return client, create

    async def test_invokes_chat_completions_with_full_conversation(self) -> None:
        client, create = self._client_with_response("done")
        messages = [
            {"id": "system-id", "role": "system", "content": "rules"},
            {"id": "user-id", "role": "user", "content": "question"},
            {"id": "assistant-id", "role": "assistant", "content": "draft"},
        ]

        text = await ida_llm_utils.call_llm_text(
            client,
            model="  gpt-5.4  ",
            messages=messages,
            effort="high",
            temperature="0.25",
        )

        self.assertEqual("done", text)
        create.assert_awaited_once_with(
            model="gpt-5.4",
            messages=[
                {"role": "system", "content": "rules"},
                {"role": "user", "content": "question"},
                {"role": "assistant", "content": "draft"},
            ],
            reasoning_effort="high",
            temperature=0.25,
        )

    async def test_defaults_effort_and_omits_temperature(self) -> None:
        client, create = self._client_with_response("done")

        await ida_llm_utils.call_llm_text(
            client,
            model="gpt-5.4",
            messages=[{"role": "user", "content": "hello"}],
        )

        create.assert_awaited_once_with(
            model="gpt-5.4",
            messages=[{"role": "user", "content": "hello"}],
            reasoning_effort="medium",
        )

    async def test_rejects_invalid_effort_before_request(self) -> None:
        client, create = self._client_with_response("done")

        with self.assertRaisesRegex(ValueError, "effort must be one of"):
            await ida_llm_utils.call_llm_text(
                client,
                model="gpt-5.4",
                messages=[{"role": "user", "content": "hello"}],
                effort="turbo",
            )

        create.assert_not_awaited()

    @patch("ida_llm_utils.create_openai_client")
    async def test_creates_async_client_when_missing(self, mock_create_client) -> None:
        client, create = self._client_with_response("done")
        mock_create_client.return_value = client

        text = await ida_llm_utils.call_llm_text(
            model="gpt-5.4",
            messages=[{"role": "user", "content": "hello"}],
            api_key="test-api-key",
            base_url="https://example.invalid/v1",
        )

        self.assertEqual("done", text)
        mock_create_client.assert_called_once_with(
            "test-api-key",
            "https://example.invalid/v1",
            api_key_required_message=(
                "api_key is required for OpenAI-compatible LLM requests"
            ),
        )
        create.assert_awaited_once()

    async def test_empty_choices_fails(self) -> None:
        create = AsyncMock(return_value=SimpleNamespace(choices=[]))
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )

        with self.assertRaisesRegex(ValueError, "missing choices"):
            await ida_llm_utils.call_llm_text(
                client,
                model="gpt-5.4",
                messages=[{"role": "user", "content": "hello"}],
            )


class _CodexHandler(BaseHTTPRequestHandler):
    content_type = "text/event-stream"
    sse_events = []
    last_path = None
    last_headers = None
    last_json_body = None
    json_bodies = []

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        type(self).last_path = self.path
        type(self).last_headers = {key.lower(): value for key, value in self.headers.items()}
        type(self).last_json_body = json.loads(body)
        type(self).json_bodies.append(type(self).last_json_body)
        self.send_response(200)
        self.send_header("Content-Type", type(self).content_type)
        self.end_headers()
        try:
            if type(self).content_type == "text/event-stream":
                for event in type(self).sse_events:
                    self.wfile.write(event.encode("utf-8"))
            else:
                self.wfile.write(b'{"ok":true}')
        except BrokenPipeError:
            return

    def log_message(self, format: str, *args) -> None:
        return


class TestCallLlmTextCodexHttp(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        _CodexHandler.content_type = "text/event-stream"
        _CodexHandler.sse_events = [
            'data: {"type":"response.output_text.delta","delta":"found_"}\n\n',
            'data: {"type":"response.output_text.delta","delta":"call"}\n\n',
            "data: [DONE]\n\n",
        ]
        _CodexHandler.last_path = None
        _CodexHandler.last_headers = None
        _CodexHandler.last_json_body = None
        _CodexHandler.json_bodies = []
        self._server = HTTPServer(("127.0.0.1", 0), _CodexHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
        )
        self._thread.start()
        self._base_url = f"http://127.0.0.1:{self._server.server_port}/v1"

    def tearDown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=1.0)

    async def _call(self, **overrides):
        kwargs = {
            "model": "gpt-5.4",
            "messages": [{"role": "user", "content": "Who are you?"}],
            "api_key": "test-api-key",
            "base_url": self._base_url,
            "fake_as": "codex",
        }
        kwargs.update(overrides)
        return await ida_llm_utils.call_llm_text(None, **kwargs)

    async def test_posts_responses_body_headers_and_template_context(self) -> None:
        result = await self._call(effort="high", temperature="0.2")

        self.assertEqual("found_call", result)
        self.assertEqual("/v1/responses", _CodexHandler.last_path)
        headers = _CodexHandler.last_headers
        self.assertEqual("text/event-stream", headers["accept"])
        self.assertEqual("codex-tui", headers["originator"])
        self.assertEqual(ida_llm_utils.CODEX_CLI_USER_AGENT, headers["user-agent"])
        self.assertEqual(headers["x-client-request-id"], headers["session-id"])
        self.assertEqual(
            headers["x-client-request-id"] + ":0",
            headers["x-codex-window-id"],
        )
        self.assertEqual("true", headers["x-openai-internal-codex-responses-lite"])
        self.assertEqual("remote_compaction_v2", headers["x-codex-beta-features"])
        body = _CodexHandler.last_json_body
        self.assertEqual(headers["x-client-request-id"], body["prompt_cache_key"])
        self.assertNotIn("<TEMPLATE_", json.dumps(body))
        self.assertEqual("gpt-5.4", body["model"])
        self.assertEqual("high", body["reasoning"]["effort"])
        self.assertEqual(0.2, body["temperature"])
        self.assertEqual("additional_tools", body["input"][0]["type"])
        self.assertEqual(
            [{"type": "input_text", "text": "Who are you?"}],
            body["input"][-1]["content"],
        )

    async def test_preserves_ids_and_cache_key_across_retries(self) -> None:
        messages = [
            {"id": "msg_initial", "role": "user", "content": "Initial prompt"},
            {"id": "msg_bad_output", "role": "assistant", "content": "bad YAML"},
            {
                "id": "msg_correction",
                "role": "user",
                "content": "Return corrected YAML",
            },
        ]
        for _ in range(2):
            await self._call(messages=messages, prompt_cache_key="stable-cache-key")

        first, second = _CodexHandler.json_bodies
        first_messages = [item for item in first["input"] if item.get("id")]
        second_messages = [item for item in second["input"] if item.get("id")]
        self.assertEqual(
            [item["id"] for item in first_messages],
            [item["id"] for item in second_messages],
        )
        self.assertEqual(
            ["msg_initial", "msg_bad_output", "msg_correction"],
            [item["id"] for item in first_messages[-3:]],
        )
        self.assertEqual("msg_bad_output", first_messages[-2]["id"])
        self.assertEqual("stable-cache-key", first["prompt_cache_key"])
        self.assertEqual("stable-cache-key", second["prompt_cache_key"])

    async def test_supports_multipart_message_content(self) -> None:
        await self._call(
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"text": "Hello "},
                        SimpleNamespace(text="world"),
                    ],
                }
            ]
        )

        self.assertEqual(
            [{"type": "input_text", "text": "Hello world"}],
            _CodexHandler.last_json_body["input"][-1]["content"],
        )

    async def test_rejects_non_sse_content_type(self) -> None:
        _CodexHandler.content_type = "application/json"
        with self.assertRaisesRegex(RuntimeError, "expected text/event-stream"):
            await self._call()

    async def test_avoids_completed_text_dup_after_deltas(self) -> None:
        _CodexHandler.sse_events = [
            'data: {"type":"response.output_text.delta","delta":"answer"}\n\n',
            'data: {"type":"response.completed","response":{"output":['
            '{"content":[{"type":"output_text","text":"answer"}]}]}}\n\n',
            "data: [DONE]\n\n",
        ]
        self.assertEqual("answer", await self._call())

    async def test_uses_completed_as_fallback_without_deltas(self) -> None:
        _CodexHandler.sse_events = [
            'data: {"type":"response.completed","response":{"output":['
            '{"content":[{"type":"output_text","text":"fallback"}]}]}}\n\n',
            "data: [DONE]\n\n",
        ]
        self.assertEqual("fallback", await self._call())

    async def test_failure_events_after_delta_include_server_message(self) -> None:
        for event_type in ("error", "response.error", "response.failed", "response.incomplete"):
            with self.subTest(event_type=event_type):
                _CodexHandler.sse_events = [
                    'data: {"type":"response.output_text.delta","delta":"partial"}\n\n',
                    f'data: {{"type":"{event_type}","error":'
                    '{"message":"server exploded"}}\n\n',
                    "data: [DONE]\n\n",
                ]
                with self.assertRaisesRegex(RuntimeError, "server exploded"):
                    await self._call()

    async def test_empty_response_text_fails(self) -> None:
        _CodexHandler.sse_events = ["data: [DONE]\n\n"]
        with self.assertRaisesRegex(RuntimeError, "empty response text"):
            await self._call()


class TestCodexTemplate(unittest.TestCase):
    def test_template_has_one_of_each_placeholder_and_kphtools_workspace(self) -> None:
        raw = Path("codex_faker.json").read_text(encoding="utf-8")
        self.assertNotIn("CS2_VibeSignatures", raw)
        self.assertIn("kphtools", raw)
        for placeholder in (
            "<TEMPLATE_MODEL_NAME>",
            "<TEMPLATE_USER_PROMPT>",
            "<TEMPLATE_PROMPT_CACHE_KEY>",
        ):
            self.assertEqual(1, raw.count(placeholder))

    def test_missing_template_fails(self) -> None:
        missing_path = Path("does-not-exist-codex-template.json")
        with patch.object(ida_llm_utils, "_CODEX_FAKER_TEMPLATE_PATH", missing_path):
            with self.assertRaisesRegex(RuntimeError, "failed to read"):
                ida_llm_utils._load_codex_faker_template()

    def test_invalid_json_and_missing_placeholder_fail(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "codex.json"
            invalid_json = (
                '<TEMPLATE_MODEL_NAME><TEMPLATE_USER_PROMPT>'
                '<TEMPLATE_PROMPT_CACHE_KEY>{'
            )
            for content, expected in (
                (invalid_json, "not valid JSON"),
                ('{"model":"<TEMPLATE_MODEL_NAME>"}', "missing placeholder"),
            ):
                with self.subTest(expected=expected):
                    path.write_text(content, encoding="utf-8")
                    with patch.object(
                        ida_llm_utils,
                        "_CODEX_FAKER_TEMPLATE_PATH",
                        path,
                    ):
                        with self.assertRaisesRegex(RuntimeError, expected):
                            ida_llm_utils._load_codex_faker_template()


if __name__ == "__main__":
    unittest.main()
