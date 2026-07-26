import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_runner


class TestOpenCodeProjectConfiguration(unittest.TestCase):
    def test_project_config_loads_shared_skill_runner_prompt(self) -> None:
        config_path = Path(".opencode/skill_runner.config.json")

        self.assertTrue(config_path.is_file(), config_path)
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual([".claude/SKILL_RUNNER.md"], config["instructions"])

    def test_project_agent_preserves_required_safety_constraints(self) -> None:
        agent_path = Path(".opencode/agents/sig-finder.md")

        self.assertTrue(agent_path.is_file(), agent_path)
        agent_text = agent_path.read_text(encoding="utf-8")
        self.assertIn("mode: primary", agent_text)
        self.assertIn("ida-pro-mcp_open_file: false", agent_text)
        self.assertIn("current binary", agent_text)
        self.assertIn("DO NOT verify or check the existence of output yaml", agent_text)


class TestOpenCodeCommandConstruction(unittest.TestCase):
    def setUp(self) -> None:
        agent_runner._MCP_PREFLIGHT_DONE = False
        agent_runner._MCP_PREFLIGHT_FAILED = False

    def test_detect_agent_kind_accepts_opencode_executable_names(self) -> None:
        self.assertEqual("opencode", agent_runner._detect_agent_kind("opencode"))
        self.assertEqual("opencode", agent_runner._detect_agent_kind("opencode.cmd"))
        self.assertEqual(
            "opencode",
            agent_runner._detect_agent_kind(r"C:\tools\opencode.cmd"),
        )
        self.assertEqual("claude", agent_runner._detect_agent_kind("claude.cmd"))
        self.assertEqual("codex", agent_runner._detect_agent_kind("codex.cmd"))
        self.assertIsNone(agent_runner._detect_agent_kind("unknown-agent"))

    def test_extract_opencode_session_id_uses_first_valid_event(self) -> None:
        output = "\n".join(
            [
                "not json",
                '{"type":"step_start","sessionID":"ses_first"}',
                '{"type":"text","sessionID":"ses_second"}',
            ]
        )

        self.assertEqual("ses_first", agent_runner._extract_opencode_session_id(output))

    def test_extract_opencode_session_id_ignores_invalid_values(self) -> None:
        output = "\n".join(
            [
                "[]",
                '{"type":"text","sessionID":""}',
                '{"type":"error","sessionID":42}',
            ]
        )

        self.assertIsNone(agent_runner._extract_opencode_session_id(output))

    def test_opencode_model_requires_provider_prefix(self) -> None:
        with self.assertRaisesRegex(ValueError, "provider/model"):
            agent_runner._agent_model_args("opencode", "gpt-5.4")

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_retries_with_reported_session_id(
        self,
        mock_run_process,
        _mock_exists,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                ["opencode", "mcp", "list"],
                0,
                "ida-pro-mcp failed\n",
                "",
            ),
            subprocess.CompletedProcess(
                ["opencode", "run"],
                1,
                '{"type":"step_start","sessionID":"ses_exact"}\n',
                "first failure",
            ),
            subprocess.CompletedProcess(
                ["opencode", "run"],
                0,
                '{"type":"text","sessionID":"ses_exact"}\n',
                "",
            ),
        ]

        result = agent_runner.run_skill(
            "find-test",
            agent="opencode",
            max_retries=2,
        )

        self.assertTrue(result)
        prompt = "Run SKILL: .claude/skills/find-test/SKILL.md"
        self.assertEqual(
            [
                "opencode",
                "run",
                "--format",
                "json",
                "--auto",
                "--agent",
                "sig-finder",
                prompt,
            ],
            mock_run_process.call_args_list[1].args[0],
        )
        self.assertEqual(
            [
                "opencode",
                "run",
                "--format",
                "json",
                "--auto",
                "--session",
                "ses_exact",
                "--agent",
                "sig-finder",
                prompt,
            ],
            mock_run_process.call_args_list[2].args[0],
        )
        self.assertIsNone(mock_run_process.call_args_list[1].kwargs["agent_input"])
        self.assertIsNone(mock_run_process.call_args_list[2].kwargs["agent_input"])

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_falls_back_to_continue_without_session_id(
        self,
        mock_run_process,
        _mock_exists,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                ["opencode.cmd", "mcp", "list"],
                0,
                "ida-pro-mcp failed\n",
                "",
            ),
            subprocess.CompletedProcess(
                ["opencode.cmd", "run"],
                1,
                "",
                "failed before first event",
            ),
            subprocess.CompletedProcess(
                ["opencode.cmd", "run"],
                0,
                '{"type":"text","sessionID":"ses_late"}\n',
                "",
            ),
        ]

        result = agent_runner.run_skill(
            "find-test",
            agent="opencode.cmd",
            max_retries=2,
        )

        self.assertTrue(result)
        retry_args = mock_run_process.call_args_list[2].args[0]
        self.assertIn("--continue", retry_args)
        self.assertNotIn("--session", retry_args)

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_sets_opencode_only_process_environment(
        self,
        mock_run_process,
        _mock_exists,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                ["opencode", "mcp", "list"],
                0,
                "ida-pro-mcp failed\n",
                "",
            ),
            subprocess.CompletedProcess(["opencode", "run"], 0, "", ""),
        ]

        self.assertTrue(
            agent_runner.run_skill(
                "find-test",
                agent="opencode",
                agent_model="openai/gpt-5.4",
                max_retries=1,
            )
        )

        run_args = mock_run_process.call_args_list[1].args[0]
        self.assertIn(["-m", "openai/gpt-5.4"], [run_args[i : i + 2] for i in range(len(run_args) - 1)])
        for process_call in mock_run_process.call_args_list:
            process_env = process_call.kwargs.get("env")
            self.assertIsNotNone(process_env)
            self.assertEqual("1", process_env["OPENCODE_DISABLE_CLAUDE_CODE_PROMPT"])
            self.assertEqual(
                ".opencode/skill_runner.config.json",
                process_env["OPENCODE_CONFIG"],
            )

    def test_invalid_opencode_model_is_rejected_before_preflight(self) -> None:
        output = io.StringIO()

        with (
            patch("agent_runner._ensure_agent_mcp_preflight") as mock_preflight,
            patch("sys.stdout", output),
        ):
            result = agent_runner.run_skill(
                "find-test",
                agent="opencode",
                agent_model="gpt-5.4",
            )

        self.assertFalse(result)
        self.assertIn("provider/model", output.getvalue())
        mock_preflight.assert_not_called()

    def test_mcp_list_server_matching_accepts_opencode_ansi_tree(self) -> None:
        self.assertTrue(
            agent_runner._mcp_list_contains_server(
                "\x1b[34m●\x1b[39m  ✓ ida-pro-mcp \x1b[90mconnected\x1b[39m\n"
            )
        )
        self.assertFalse(
            agent_runner._mcp_list_contains_server(
                "\x1b[34m●\x1b[39m  ✗ not-ida-pro-mcp \x1b[90mfailed\x1b[39m\n"
            )
        )


if __name__ == "__main__":
    unittest.main()
