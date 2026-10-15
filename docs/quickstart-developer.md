English · [Español](es/inicio-rapido-desarrollador.md)

# Quickstart for a developer

All you need is Docker. Nothing is installed, your code isn't run, and nothing leaves your machine. The engines'
advisory databases stay in the `pitangus-cache` volume: only the first scan downloads them.

**Scan your project** (from its folder):

```bash
docker run --rm -v "$PWD":/src:ro -v pitangus-cache:/data ghcr.io/pitangus-dev/pitangus-worker:0.14 python -m pitangus --data-dir /data scan /src
```

**Only what your change adds:** append `--base origin/main`. What was already there isn't charged to you.

**Fix it with your own AI:** append `--format prompt` and paste each prompt into Claude, Cursor or Copilot. It carries
the rule, the place, the matched code and the fix, never a secret's value.

**Before every push**, with [pre-commit](https://pre-commit.com) (`pre-commit install --hook-type pre-push`). It scans
what you're about to push, the commits as git holds them, against what the remote already has: an untracked file or an
uncommitted edit never blocks it.

```yaml
repos:
  - repo: https://github.com/Pitangus-Dev/pitangus
    rev: v0.14.0          # the first release with the hook
    hooks:
      - id: pitangus
```

The hook analyzes what you're about to push, not your working tree: the committed changes against `origin/main`
(`PITANGUS_BASE` sets another base), so a file you haven't committed, tracked or not, can't block the push. A base
that doesn't exist stops the hook with a message that says so.

**On every pull request** (GitHub), in `.github/workflows/pitangus.yml`:

```yaml
on: pull_request
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: Pitangus-Dev/pitangus@v0.14.0   # pin it to the tag's commit SHA
```

Exit codes: `0` pass · `1` findings at or above `--fail-on` (high by default) · `3` an engine couldn't run, which is
never taken as clean. Options, other CIs and a team server: [Scanning from the terminal and in CI](cli.md) ·
[Quickstart with the panel](quickstart.md).
