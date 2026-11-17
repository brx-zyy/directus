# DIRECTUS-WF-001 — Stored command injection in release preparation workflow

## Advisory details

### Title

Stored shell command injection through contributor-controlled release notes in `.github/workflows/prepare-release.yml`

### Summary

The release preparation workflow interpolates generated release notes directly into a shell heredoc inside a `run:` script. Directus release notes include contributor-authored changeset notice text without escaping. A malicious changeset can therefore terminate the heredoc and inject shell commands when a maintainer later runs the release workflow.

The affected step exposes `secrets.RELEASE_PAT` as `GH_TOKEN`, so injected commands execute in a privileged release job and may access that credential.

### Details

Affected upstream files:

- `.github/workflows/prepare-release.yml` — the **Create release PR** step constructs `PR_BODY` using an unquoted workflow expression inside a shell script heredoc:
  ```yaml
  PR_BODY=$(cat <<'EOF'
  ...
  ${{ steps.changeset-version.outputs.release_notes }}
  ```
  The same step sets `GH_TOKEN: ${{ secrets.RELEASE_PAT }}`.

- `packages/release-notes-generator/src/utils/process-release-lines.ts` extracts the body of a `::: notice` block from the changeset summary and retains its contents.
- `packages/release-notes-generator/src/utils/generate-markdown.ts` inserts `notice.notice` directly into the generated Markdown.
- `packages/release-notes-generator/readme.md` documents notice blocks and says they may contain arbitrary Markdown syntax.

The data flow is:

1. A contributor submits a changeset containing a notice block.
2. The changeset is merged into `main`.
3. A maintainer dispatches `Prepare Release`.
4. `pnpm changeset version` generates release notes containing the notice text.
5. GitHub substitutes the release-notes output into the shell script before Bash parses it.
6. A notice line matching the heredoc delimiter (currently `EOF`) terminates the original heredoc. Following lines are parsed as shell commands.

This is stored command injection in a trusted workflow, not merely Markdown injection.

### Proof of concept

A changeset notice can contain a delimiter breakout. Use a harmless marker command for validation:

```md
---
'@directus/api': patch
---

::: notice
EOF
printf 'workflow-injection-confirmed' > "$RUNNER_TEMP/directus-release-poc"
cat <<'EOF'
:::

A normal changeset summary
```

The injected `cat <<'EOF'` consumes the remaining workflow heredoc text through the original delimiter, allowing the shell script to remain syntactically valid while executing the marker command.

I reproduced the shell-heredoc breakout locally with a harmless marker-file command; the marker was created. This validates the shell parsing primitive. I have not run a malicious changeset through Directus' actual release workflow or accessed any repository secret.

### Impact

If a contributor can get a malicious changeset merged and a maintainer later runs the release workflow, attacker-controlled shell commands can execute on the trusted release runner.

The affected step receives `RELEASE_PAT` as `GH_TOKEN`. Depending on that token's configured scope, an attacker may steal repository credentials, modify release branches or pull requests, tamper with release artifacts, or further compromise the software supply chain.

### Weakness

- CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Suggested remediation

Do not interpolate `steps.changeset-version.outputs.release_notes` into a `run:` script. Pass the value through an environment variable or an artifact/file and construct the PR body using a program that treats it strictly as data. Prefer writing the body to a file and invoking `gh pr create --body-file` / `gh pr edit --body-file`.

For example, pass the output as `RELEASE_NOTES` in the step's `env:` block, then use a Node script or a safely quoted `printf '%s' "$RELEASE_NOTES"` to write it to a file. Never use attacker-controlled text as part of the shell program or as a heredoc delimiter.

### Validation status

- Source data flow: confirmed by inspection of upstream workflow and release-notes generator.
- Heredoc breakout: reproduced locally with a harmless marker command.
- Full GitHub Actions execution: not performed.
- Secret access or exfiltration: not attempted.
- This is a draft report for maintainer validation, not an upstream submission.
