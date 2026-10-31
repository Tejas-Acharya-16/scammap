@AGENTS.md

## Claude Code
- Default to Sonnet. Switch to Opus only for architecture, the threat model, or a bug that survived two attempts. Lower /effort for routine work.
- Run /usage hourly. At a limit: write the current state to STATE.md, then move the task to another tool or wait with the auto-continue option in /rate-limit-options.
- Do not set ANTHROPIC_API_KEY unless the team has decided to pay by API. With it set, Claude Code bills the API instead of the subscription.
- Parallel agents use git worktrees, for example: git worktree add ../wt-core -b agent/core
