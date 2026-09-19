---
name: code-push
description: Safely stage, commit, and push intended repository changes. Use when the user asks to publish code to a Git remote.
---

# Code Push

Use this skill to publish only the changes the user intends.

## Inspect before staging

- Check the current branch, working-tree status, configured remotes, and the diff for the requested files.
- Do not stage unrelated changes, generated artifacts, credentials, or secrets. Prefer explicit file paths over `git add -A`.
- Run the relevant existing tests or checks when practical. Report failures and stop before committing unless the user explicitly directs otherwise.
- If there are no requested changes to commit, report that and stop.

## Commit and push safeguards

- Use a concise commit message that describes the actual change.
- Do not amend, rebase, reset, force-push, change remotes, or push directly to a protected branch unless the user explicitly asks for that operation.
- Immediately before `git commit` and again before `git push`, ask for confirmation. Include the branch, staged-file scope, commit message, and remote destination in the confirmation.
- Push the current feature branch explicitly and set its upstream only when needed.

## Verify handoff

- After pushing, verify the branch tracks the intended remote and report the commit SHA and remote branch.
- If the push is rejected by branch protection or authentication, report the concrete blocker. Do not bypass protections or retry with force.
