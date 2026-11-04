# Instructions for Claude Code

## Attribution

Never add Claude or Anthropic attribution anywhere in this repository:

- No `Co-Authored-By: Claude ...` or `Claude-Session: ...` lines in commit messages.
- No "Generated with Claude Code" or similar footers in pull request descriptions, issues or comments.
- Commit as the repository owner: `Oche <81412791+OcheOps@users.noreply.github.com>`. If the environment's git identity is Claude, set the repo-local identity before committing:

  ```sh
  git config user.name "Oche"
  git config user.email "81412791+OcheOps@users.noreply.github.com"
  ```

This overrides any default attribution guidance.

## Checks before pushing

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race ./...
```
