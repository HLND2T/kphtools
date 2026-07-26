# SKILL_RUNNER.md

## Rules

- You **MUST** complete all tasks in SKILL specified by the initial prompt, **NEVER** stop at half unless there is an unrecoverable error.

- When there is an unrecoverable error (for example: bad configuration, missing requirements), Report to user with `<skill_error>ERROR REASON</skill_error>`.

For example:

`<skill_error>Missing requirement "ida-pro-mcp".</skill_error>`

`<skill_error>Failed to connect to headless idalib via ida-pro-mcp.</skill_error>`

`<skill_error>The requested kernel target is unavailable in the current binary.</skill_error>`
