# DIRECTUS-WF-001 — Stored command injection in release preparation workflow

## Advisory details

### Title

Stored shell command injection through contributor-controlled release notes in `.github/workflows/prepare-release.yml`

### Summary

The Directus release preparation workflow inserts generated release notes directly into a shell heredoc. Contributor-controlled changeset notice text is retained as raw Markdown and reaches that workflow output. A crafted notice can exploit both the workflow's `GITHUB_OUTPUT` heredoc parser and the later shell heredoc, causing attacker-controlled shell commands to execute when a maintainer runs the release workflow.

The vulnerable `Create release PR` step exposes `secrets.RELEASE_PAT` as `GH_TOKEN`. Therefore, successful command execution occurs in a step with access to that credential. The credential's precise permissions have not been established in this report.

### Details

Affected upstream files:

- `.github/workflows/prepare-release.yml`
  - `Generate release notes and update versions` writes the release notes to `$GITHUB_OUTPUT` using the fixed delimiter `EOF`.
  - `Create release PR` later interpolates `${{ steps.changeset-version.outputs.release_notes }}` directly inside a shell heredoc also using `EOF`.
  - The latter step sets `GH_TOKEN: ${{ secrets.RELEASE_PAT }}`.
- `packages/release-notes-generator/src/utils/process-release-lines.ts` extracts the body of a `::: notice` block and retains its contents.
- `packages/release-notes-generator/src/utils/generate-markdown.ts` appends `notice.notice` directly to the generated Markdown without escaping shell heredoc delimiters.
- `packages/release-notes-generator/readme.md` documents the notice-block feature.

The data flow is:

1. A contributor authors a changeset notice.
2. The changeset is merged into the release branch.
3. A maintainer dispatches `Prepare Release`.
4. The release-notes generator preserves the notice text in generated Markdown.
5. The workflow writes that Markdown to `GITHUB_OUTPUT` using `release_notes<<EOF`.
6. A crafted notice closes that first output block, then opens a second output block with the same key (`release_notes<<BAR`). The GitHub Actions runner processes output records in order and assigns each output to a dictionary by key; the later duplicate `release_notes` value replaces the earlier one. A further harmless output block consumes the workflow's fixed trailing `EOF` delimiter so the output file remains valid.
7. The replacement output begins with a line equal to `EOF`. When GitHub substitutes it into the later `Create release PR` shell script, that line closes the script's original heredoc. The following lines are parsed as shell commands.

The relevant runner implementation is in the official GitHub Actions runner source:
https://github.com/actions/runner/blob/main/src/Runner.Worker/FileCommandManager.cs

In `EnvFileKeyValuePairs`, heredoc-style output entries are parsed sequentially. `SetOutputFileCommand` passes each parsed pair to `context.SetOutput`; repeated output names are assigned again, so the later value wins.

### Proof of concept

Use a harmless marker-file command. A malicious changeset can use this notice content:

```md
---
'@directus/api': patch
---

::: notice
EOF
release_notes<<BAR
EOF
printf 'DIRECTUS_RELEASE_POC_CONFIRMED' > "$RUNNER_TEMP/directus-release-poc"
cat <<'EOF'
BAR
dummy<<EOF
:::

Normal changeset summary
```

The important detail is the nested output construction:

- The first `EOF` terminates the workflow's initial `release_notes<<EOF` output block.
- `release_notes<<BAR` starts a second output with the same name.
- The second block's value begins with `EOF`, followed by the marker command and a nested shell heredoc opener.
- `dummy<<EOF` consumes the remainder of the generated output and the workflow's fixed final `EOF`, keeping the runner's output-file parser from rejecting the step.
- The runner's later duplicate assignment replaces the original `release_notes` output with the crafted value.

**Reproduction performed:** I locally reconstructed the workflow's `GITHUB_OUTPUT` file format, parsed the nested and duplicate output records following the GitHub runner's `EnvFileKeyValuePairs` logic, then inserted the resulting `release_notes` value into the same shell-heredoc structure used by `Create release PR`. Bash executed the harmless marker command and created `$RUNNER_TEMP/directus-release-poc` containing `DIRECTUS_RELEASE_POC_CONFIRMED`. The shell script completed successfully.

This is stronger than a standalone heredoc demonstration: it exercises the two-stage output-file parsing and subsequent shell parsing that form the vulnerability's source-level exploit chain. It was still a local reproduction, not a run of Directus' actual GitHub Actions workflow.

### Impact

This is stored OS command injection (CWE-78) in Directus release automation.

An attacker who can get a malicious changeset merged and cause a maintainer to run the release workflow can execute arbitrary shell commands in the trusted release job.

Potential consequences include:

- Access to credentials available to the vulnerable step, including `RELEASE_PAT`.
- Unauthorized changes to release branches or pull requests, subject to the token's permissions.
- Tampering with release outputs and disruption or compromise of the software release process.
- Potential downstream supply-chain impact if a compromised release is published.

The exact scope of credential access and downstream impact depends on the configured permissions of `RELEASE_PAT`; those have not been verified here.

### Weakness

- CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### Suggested remediation

Do not interpolate generated release notes into a `run:` script or use a predictable fixed delimiter for untrusted multiline output.

- Pass release notes as data, not as part of shell source.
- Use a safely generated temporary file or a script that reads the content as data.
- For `GITHUB_OUTPUT`, use a cryptographically random delimiter and ensure it cannot occur as a complete line in the value; alternatively avoid multiline output transport and pass a file/artifact.
- Build the pull-request body with a program that treats the release notes as data, then use `gh pr create --body-file` / `gh pr edit --body-file`.

### Validation status

- Upstream source data flow: confirmed by inspection.
- GitHub Actions runner output-file behavior: checked against the official `actions/runner` implementation.
- Two-stage `GITHUB_OUTPUT` plus Bash heredoc exploit chain: reproduced locally; harmless marker file created and shell exited successfully.
- **Actual Directus release-notes generator: executed successfully in GitHub Actions.** The isolated test installed the repository dependencies, built `@directus/release-notes-generator`, and ran the real `pnpm changeset version` against the malicious `.changeset/live-release-poc.md`.
- **Actual generated output and output-file handling: confirmed.** The workflow used the same `awk` extraction and `GITHUB_OUTPUT` heredoc-writing sequence as `.github/workflows/prepare-release.yml`.
- **Actual second-stage shell injection: confirmed in GitHub-hosted Actions.** The next step interpolated `${{ steps.changeset-version.outputs.release_notes }}` into the same shell heredoc structure as the vulnerable `Create release PR` step. The marker file was created with the expected content, and the step asserted the exact marker value.
- Live run: https://github.com/brx-zyy/directus/actions/runs/44090195006
- Run commit: `6106061ee2560ed813cce6fad8eeabd25771fce5`
- Evidence in the job log: `POC_CONFIRMED: injected shell command executed` followed by `DIRECTUS_LIVE_POC_CONFIRMED`.
- Evidence artifact: `directus-release-notes-poc` (artifact ID `14330898274`), downloadable from the run's Artifacts section.
- The original production `Prepare Release` workflow was not dispatched. The exploit chain was reproduced in an isolated workflow on the fork using the real Directus generator and the same vulnerable output/shell construction, without `RELEASE_PAT` or any secret access.
- Secret access or exfiltration: not attempted.
- This is a draft report in the research fork, not an upstream submission.
