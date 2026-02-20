"""E2E test verifying the preflight hook redirects Bash to the sandbox MCP tool.

This test does NOT rely on system prompts or CLAUDE.md instructions telling Claude
to use the sandbox. Instead, a PreToolUse hook (backed by the real lite-sandbox
preflight binary) denies Bash tool calls that would pass sandbox validation and
tells Claude to use mcp__lite-sandbox__bash.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    ToolResultBlock,
)
from claude_agent_sdk.types import (
    HookContext,
    HookInput,
    HookJSONOutput,
    HookMatcher,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


async def preflight_hook(
    input_data: HookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> HookJSONOutput:
    """PreToolUse hook that delegates to the lite-sandbox preflight binary.

    Pipes the hook input JSON to `lite-sandbox preflight` on stdin and returns
    the parsed JSON output.  If the binary produces no output (command would
    fail sandbox validation) an empty dict is returned, allowing the Bash call.
    """
    binary = PROJECT_ROOT / "lite-sandbox"

    hook_json = json.dumps({
        "tool_name": input_data.get("tool_name", ""),
        "tool_input": input_data.get("tool_input", {}),
        "cwd": input_data.get("cwd", ""),
    }).encode()

    proc = await asyncio.create_subprocess_exec(
        str(binary), "preflight",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate(hook_json)

    output = stdout.strip()
    if output:
        return json.loads(output)
    return {}


@pytest.fixture
def preflight_agent_options() -> ClaudeAgentOptions:
    """Agent options using the preflight hook instead of system prompt guidance.

    Key differences from the standard agent_options fixture:
    - No system_prompt telling Claude to prefer the sandbox tool
    - No can_use_tool callback denying Bash
    - Both Bash and mcp__lite-sandbox__bash are allowed
    - A PreToolUse hook backed by the real binary handles redirection
    """
    binary = PROJECT_ROOT / "lite-sandbox"
    return ClaudeAgentOptions(
        mcp_servers={
            "lite-sandbox": {
                "command": str(binary),
                "args": ["serve-mcp"],
            },
        },
        allowed_tools=["Bash", "mcp__lite-sandbox__bash"],
        hooks={
            "PreToolUse": [
                HookMatcher(
                    matcher="Bash",
                    hooks=[preflight_hook],
                ),
            ],
        },
        model="haiku",
        max_turns=5,
        cwd=str(PROJECT_ROOT),
    )


async def run_prompt(prompt: str, options: ClaudeAgentOptions) -> dict:
    """Send a prompt and collect tool calls, text, and tool results."""
    tool_calls: list[ToolUseBlock] = []
    text_blocks: list[str] = []
    tool_results: list[str] = []
    result = None

    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text_blocks.append(block.text)
                    elif isinstance(block, ToolUseBlock):
                        tool_calls.append(block)
                    elif isinstance(block, ToolResultBlock):
                        content = block.content if block.content else ""
                        if isinstance(content, list):
                            content = " ".join(
                                item.get("text", "")
                                for item in content
                                if isinstance(item, dict)
                            )
                        tool_results.append(content)
            elif isinstance(message, ResultMessage):
                result = message

    return {
        "tool_calls": tool_calls,
        "text": "\n".join(text_blocks),
        "tool_results": tool_results,
        "result": result,
    }


@pytest.mark.asyncio
async def test_preflight_redirects_to_sandbox(preflight_agent_options):
    """Without any system prompt guidance, the hook should redirect Bash to the sandbox.

    Claude will attempt to use Bash for `ls`, but the preflight hook denies it
    and tells Claude to use mcp__lite-sandbox__bash instead.  We verify that:
    1. The sandbox tool was ultimately used (not built-in Bash)
    2. The command produced valid output (go.mod visible)
    """
    response = await run_prompt(
        "List the files in the current directory. Show me the output.",
        preflight_agent_options,
    )

    tool_names = [tc.name for tc in response["tool_calls"]]

    # The sandbox MCP tool should have been used
    assert any(
        "mcp__lite-sandbox__bash" == name for name in tool_names
    ), f"Expected mcp__lite-sandbox__bash tool call, got: {tool_names}"

    # Verify the command actually ran successfully
    combined = response["text"] + " ".join(response["tool_results"])
    assert "go.mod" in combined, f"Expected go.mod in output: {combined}"
