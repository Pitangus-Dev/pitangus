"""Scan of a local folder: `pitangus scan`. For the terminal, pre-commit and CI.

Without `--base` everything is scanned. With `--base main` the starting point (the merge-base
with that branch) is scanned too and only what the change introduces is reported: what was
already there doesn't block. A folder is scanned as it is on disk, uncommitted changes and new
non-ignored files included. `--commit REF` and `--staged` scan what git holds instead (a commit,
or the index: what the next commit will hold): an untracked file or an unstaged edit can't
change the result. That is what the pre-commit hook scans.

An incomplete scan never passes as clean: if an engine couldn't run, the command
says so and exits with its own code.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from tempfile import TemporaryDirectory

from pitangus.modules.findings.canonical import growth
from pitangus.modules.findings.identity import formers
from pitangus.modules.pullrequests.review import SEVERITY_ORDER, changed_lines, classify, markdown_rows, renames, verdict
from pitangus.modules.scanning.repository import scan_repository
from pitangus.modules.sources.repositories import snapshot_directory
from pitangus.shared.i18n import default_locale, localize, msg, t, text
from pitangus.shared.masking import mask

# Exit codes (documented in docs/cli.md).
EXIT_OK, EXIT_BLOCKED, EXIT_ERROR, EXIT_INCOMPLETE = 0, 1, 2, 3
FAIL_ON = ("critical", "high", "medium", "low", "never")
# Branch, tag, SHA or git expression (HEAD~1, origin/main…). Never starts with "-": it can't
# sneak in as a git option.
REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/@^~{}+-]{0,199}")
CORE_ENGINES = ("opengrep", "betterleaks", "trivy", "osv-scanner")
# Optional: one that fails doesn't make the analysis incomplete, but the output says what it didn't check.
OPTIONAL_ENGINES = ("checkov", "zizmor")


class LocalScanError(ValueError):
    """Carries a message; `str()` renders it in the default locale (the CLI's)."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return text(self.message, default_locale())


def _git_command(path: Path, *args: str) -> list[str]:
    # safe.directory: inside the container the mounted folder belongs to another user. core.fsmonitor=false:
    # a repository's local config can't launch programs while the diff is computed.
    return ["git", "-c", f"safe.directory={path}", "-c", "core.fsmonitor=false", "-C", str(path), *args]


def _git(path: Path, *args: str, binary: bool = False, timeout: int = 120, may_fail: bool = False):
    """`may_fail`: a non-zero exit returns None instead of raising (the caller explains it better than git)."""
    try:
        completed = subprocess.run(_git_command(path, *args), capture_output=True, text=not binary, timeout=timeout)
    except FileNotFoundError as exc:
        raise LocalScanError(msg("scanning.local.errors.no_git")) from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalScanError(msg("scanning.local.errors.git_timeout", command=args[0])) from exc
    if completed.returncode != 0 and may_fail:
        return None
    if completed.returncode != 0:
        detail = mask(" ".join((completed.stderr.decode(errors="replace") if binary else completed.stderr).split())[:200])
        raise LocalScanError(msg("scanning.local.errors.git_failed", command=args[0], detail=detail) if detail
                             else msg("scanning.local.errors.git_failed_silently", command=args[0]))
    return completed.stdout


def resolve(path: Path, ref: str) -> str:
    """The commit a reference names, or a message saying it doesn't exist (`--verify --quiet` exits 1 silently)."""
    if not REF.fullmatch(ref or ""):
        raise LocalScanError(msg("scanning.local.errors.invalid_ref", ref=repr(ref)))
    commit = (_git(path, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}", may_fail=True) or "").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise LocalScanError(msg("scanning.local.errors.unknown_ref", ref=repr(ref)))
    return commit


def merge_base(path: Path, base: str, head: str = "HEAD") -> str:
    """The commit the change starts from: the merge-base between the base and `head` (what is scanned)."""
    start, end = resolve(path, base), resolve(path, head)
    found = (_git(path, "merge-base", start, end, may_fail=True) or "").strip()
    if not found:
        raise LocalScanError(msg("scanning.local.errors.no_merge_base", base=repr(base), head=repr(head)))
    return found


def parse_diff(text: str) -> list[dict]:
    """`git diff --unified=0` → the same shape as a GitHub PR's files (filename, status, patch, and previous_filename
    for a renamed file)."""
    files, current, patch = [], None, []
    def close():
        if current is not None:
            current["patch"] = None if current.pop("binary", False) else "\n".join(patch)
            files.append(current)
    for line in text.splitlines():
        if line.startswith("diff --git "):
            close()
            current, patch = {"filename": None, "status": "modified"}, []
        elif current is None:
            continue
        elif line.startswith("+++ "):
            target = line[4:]
            if target == "/dev/null":
                current["status"] = "removed"
            else:
                current["filename"] = target[2:] if target.startswith("b/") else target
        elif line.startswith("--- "):
            source = line[4:]
            if source == "/dev/null":
                current["status"] = "added"
            elif not current["filename"]:
                current["filename"] = source[2:] if source.startswith("a/") else source
        elif line.startswith("rename from "):
            current["status"], current["previous_filename"] = "renamed", line[len("rename from "):]
        elif line.startswith("rename to "):
            current["filename"] = line[len("rename to "):]
        elif line.startswith("Binary files "):
            current["binary"] = True
            match = re.search(r" and (?:b/)?(.+) differ$", line)
            if match and match.group(1) != "/dev/null":
                current["filename"] = match.group(1)
        elif line.startswith(("@@", "+", "-", " ", "\\")):
            patch.append(line)
    close()
    return [item for item in files if item["filename"]]


def diff_files(path: Path, commit: str, revision: str | None = None, *, staged: bool = False) -> list[dict]:
    """What changed from `commit` to what is scanned: the working tree plus new non-ignored files, the commit
    `revision`, or the index (`staged`)."""
    target = (commit, revision) if revision else ("--cached", commit) if staged else (commit,)
    text = _git(path, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative", "-M", *target, "--")
    files = parse_diff(text)
    if revision or staged:
        return files
    untracked = _git(path, "ls-files", "--others", "--exclude-standard", "--", ".").splitlines()
    return files + [{"filename": name, "status": "added", "patch": None} for name in untracked if name]


def _tree_entries(path: Path, commit: str | None) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """((object, relative path) of each regular file of the folder in `commit`, or in the index when None; {path: kind}
    of every entry git holds there). Links and submodules aren't written, nor anything git shouldn't hold (`..`,
    `.git`): the snapshot declares each of them unexamined (sources.repositories.declare_committed)."""
    if commit:
        listing = _git(path, "ls-tree", "-r", "-z", commit, "--", binary=True)
    else:
        listing = _git(path, "ls-files", "--stage", "-z", binary=True)
    entries = []
    tree: dict[str, str] = {}
    for record in listing.split(b"\0"):
        meta, _, name = record.partition(b"\t")
        fields = meta.split()
        if len(fields) != 3 or not name:
            continue
        mode = fields[0]
        if not commit and fields[2] != b"0":   # an unmerged entry's other stages
            continue
        relative = name.decode("utf-8", errors="surrogateescape")
        tree[relative] = "submodule" if mode == b"160000" else "symlink" if mode == b"120000" else "file"
        if not mode.startswith(b"100"):
            continue
        sha = fields[2] if commit else fields[1]
        parts = relative.split("/")
        if relative.startswith("/") or any(part in ("", ".", "..") or part.lower() == ".git" for part in parts):
            continue
        entries.append((sha.decode(), relative))
    return entries, tree


def _write_blobs(path: Path, entries: list[tuple[str, str]], raw: Path) -> None:
    """Each object's content into `raw`, read from git's database in one `cat-file --batch` (no checkout, no filters)."""
    with tempfile.TemporaryFile() as requests:
        requests.write("".join(f"{sha}\n" for sha, _ in entries).encode())
        requests.seek(0)
        try:
            process = subprocess.Popen(_git_command(path, "cat-file", "--batch"), stdin=requests, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL)
        except FileNotFoundError as exc:
            raise LocalScanError(msg("scanning.local.errors.no_git")) from exc
        with process:
            for sha, relative in entries:
                header = process.stdout.readline().split()
                if len(header) != 3 or header[0].decode() != sha:
                    process.kill()
                    raise LocalScanError(msg("scanning.local.errors.git_failed_silently", command="cat-file"))
                content = process.stdout.read(int(header[2]))
                process.stdout.read(1)
                target = raw / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)


def snapshot_git(path: Path, destination: Path, commit: str | None = None) -> dict:
    """The folder as git holds it, at `commit` (a resolved commit) or in the index when None, with the same filters
    as a folder scan. Read from git's objects, never from the working tree: an untracked file or an unstaged edit
    can't get in. The raw copy stays next to it (`<destination>-raw`), whole, to tell a deleted file from a filtered one."""
    raw = destination.parent / f"{destination.name}-raw"
    raw.mkdir(parents=True, exist_ok=True)
    entries, tree = _tree_entries(path, commit)
    _write_blobs(path, entries, raw)
    destination.mkdir(parents=True, exist_ok=True)
    return snapshot_directory(raw, destination, committed=True, tree=tree)


def snapshot_commit(path: Path, commit: str, destination: Path) -> dict:
    """The folder as it was at `commit`, with the same filters as the current scan."""
    return snapshot_git(path, destination, resolve(path, commit))


def _engines(scan: dict) -> tuple[list[str], list[str]]:
    """Every core engine, as ran or didn't: one with no step at all (no Docker) didn't run either."""
    from pitangus.modules.scanning.engines import IMAGES
    ran, failed, seen = [], [], set()
    for step in scan.get("steps") or []:
        tool = (step.get("tool") or {}).get("name")
        if tool in CORE_ENGINES:
            seen.add(tool)
            (ran if step["status"] in ("completed", "partial") else failed).append(step["name"])
    return ran, failed + [IMAGES[key]["name"] for key in CORE_ENGINES if key not in seen]


def resolved_findings(before: list[dict], after: list[dict], changed: dict, root: Path, renamed: dict[str, str] | None = None) -> list[dict]:
    """What the starting point had and the change no longer has, each with how it went away.

    The gate's comparison the other way round (`canonical.growth`, as `classify` does for what the change introduces):
    families and copies counted across the whole repository, a renamed file (`renamed`: {new path: old path}) counted
    as its new name. So a copy moved within its file or to another one, a renamed file, a reformat or a fingerprint
    that changed is neither introduced nor fixed, and a family's instances never count as both.

    `fixed`: its file is one the change modified. `deleted`: its file is gone. `unattributed`: it went away although
    its file wasn't touched, so the change gets no credit."""
    back = {old: new for new, old in (renamed or {}).items()}
    identities, lost = growth(after, before, back)
    present = {item["fingerprint"] for item in after} | {former for item in after for former in formers(item)}
    groups: dict[str, list[dict]] = {}
    for item, identity in zip(before, identities):
        groups.setdefault(identity, []).append(item)
    gone = []
    for identity, group in groups.items():
        # The copies whose own fingerprint is gone first: they are the ones that went away.
        for item in sorted(group, key=lambda item: (item["fingerprint"] in present, item.get("path") or "", item.get("line") or 0))[:lost[identity]]:
            where = back.get(item.get("path") or "", item.get("path") or "")
            how = "fixed" if where in changed and (root / where).exists() else "deleted" if not (root / where).exists() else "unattributed"
            gone.append({**item, "resolution": how})
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    return sorted(gone, key=lambda item: (order.get(item["severity"], 9), item.get("path") or "", item.get("line") or 0))


def run(path: Path, *, data_dir: Path, base: str | None = None, baseline: bool = True, fail_on: str = "high",
        allow_osv_upload: bool = False, progress=None, name: str | None = None, exclude: list[str] | None = None,
        revision: str | None = None, staged: bool = False) -> dict:
    """Scans `path` and applies the threshold. Returns the result ready to display and the exit code.

    `exclude`: glob patterns relative to the root (`fixtures/**`, `**/testdata/**`) whose findings don't count.
    The output mentions them ("N in excluded paths"): nothing is hidden without saying so.
    `revision` (a commit) or `staged` (the index): scan what git holds there instead of the folder on disk."""
    from pitangus.modules.findings.exclusions import ExclusionError, excluded, normalize
    from pitangus.modules.findings.registry import blind_engines, unseen
    from pitangus.modules.scanning.engines import IMAGES, engines_available, engines_problem, names_engine
    try:
        patterns = normalize(list(exclude or []))
    except ExclusionError as exc:
        raise LocalScanError(msg("scanning.local.errors.exclude", error=exc.args[0] if exc.args else str(exc))) from exc
    path = path.expanduser().resolve()
    if not path.is_dir():
        raise LocalScanError(msg("scanning.local.errors.not_a_folder", path=str(path)))
    if fail_on not in FAIL_ON:
        raise LocalScanError(msg("scanning.local.errors.fail_on", options=", ".join(FAIL_ON)))
    if revision and staged:
        raise LocalScanError(msg("scanning.local.errors.commit_and_staged"))
    report = progress or (lambda level, message: None)
    target = resolve(path, revision) if revision else None
    commit = merge_base(path, base, target or "HEAD") if base else None  # before scanning: a wrong ref fails at once
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    name = (name or path.name).strip()[:100] or path.name
    source = {"id": f"local:{name}", "name": name, "provider": "local"}
    comparison = None
    resolved: list[dict] = []
    with TemporaryDirectory(prefix="scan-", dir=work) as temporary:
        head = Path(temporary) / "head"
        if target or staged:
            stats = snapshot_git(path, head, target)
            report("info", msg("scanning.local.progress.copied_commit", commit=target[:8], files=stats["files"]) if target
                   else msg("scanning.local.progress.copied_staged", files=stats["files"]))
        else:
            stats = snapshot_directory(path, head)
            report("info", msg("scanning.local.progress.copied", files=stats["files"]))
        scan = scan_repository(head, {**source, "files": stats["files"], "snapshot": stats},
                               allow_osv_upload=allow_osv_upload, data_dir=data_dir, progress=report)
        findings = [item for item in scan["findings"] if not excluded(item.get("path", ""), patterns)]
        skipped = len(scan["findings"]) - len(findings)
        if base:
            files = diff_files(path, commit, target, staged=staged)
            changed = changed_lines(files)
            report("info", msg("scanning.local.progress.comparing", base=base, commit=commit[:8], files=len(changed)))
            base_findings, base_status = None, None
            if baseline and changed:
                base_dir = Path(temporary) / "base"
                base_stats = snapshot_commit(path, commit, base_dir)
                report("info", msg("scanning.local.progress.baseline", files=base_stats["files"]))
                base_scan = scan_repository(base_dir, {**source, "files": base_stats["files"], "snapshot": base_stats},
                                            allow_osv_upload=allow_osv_upload, data_dir=data_dir)
                # Both sides alike: the same excluded paths, grouped and counted by the registry's identity (classify).
                base_findings = [item for item in base_scan["findings"] if not excluded(item.get("path", ""), patterns)]
                base_status = base_scan["status"]
                # Only two complete scans prove something went away: a failed engine also "loses" findings.
                # Nor does one an engine that failed in either scan (an optional one can fail in a complete scan).
                if base_status == "completed" and scan["status"] == "completed":
                    blind = blind_engines(base_scan) | blind_engines(scan)
                    before = [item for item in base_scan["findings"]
                              if not excluded(item.get("path", ""), patterns) and not unseen(item, blind)]
                    resolved = resolved_findings(before, scan["findings"], changed,
                                                 Path(temporary) / "head-raw" if target or staged else path, renames(files))
            outcome = classify(findings, changed, base_findings, renames(files))
            findings = outcome["introduced"]
            comparison = {"base": base, "merge_base": commit, "changed_files": len(changed),
                          "baseline": base_findings is not None, "baseline_status": base_status,
                          "preexisting_in_changed_code": len(outcome["preexisting"]),
                          "resolved_verifiable": base_findings is not None and base_status == "completed" and scan["status"] == "completed",
                          "resolved": {how: sum(1 for item in resolved if item["resolution"] == how)
                                       for how in ("fixed", "deleted", "unattributed")}}
    ran, failed = _engines(scan)
    missing = [] if engines_available() else [engines_problem() or msg("scanning.local.no_docker")]
    incomplete = scan["status"] == "incomplete" or bool(failed) or bool(missing)
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda item: (order.get(item["severity"], 9), item["path"], item["line"]))
    gate = verdict(findings, fail_on)
    code = EXIT_BLOCKED if gate["blocking"] else EXIT_OK
    if incomplete and code == EXIT_OK:
        code = EXIT_INCOMPLETE
    return {"target": str(path), "name": name, "snapshot": target or ("index" if staged else "worktree"),
            "comparison": comparison, "fail_on": fail_on,
            "excluded": {"patterns": patterns, "findings": skipped},
            "status": "incomplete" if incomplete else "completed", "engines": {"ran": ran, "failed": failed},
            # The detail alone when it already names its engine, so the name isn't said twice.
            "not_analyzed": missing + [step["detail"] if names_engine(step["detail"], (IMAGES.get(step["tool"]["name"]) or {}).get("name"))
                                       else msg("scanning.local.not_analyzed_step", step=step["name"], detail=step["detail"])
                                       for step in scan.get("steps") or []
                                       if (step.get("tool") or {}).get("name") in (*CORE_ENGINES, *OPTIONAL_ENGINES)
                                       and step["status"] not in ("completed", "partial")],
            "findings": findings, "resolved": resolved, "gate": gate, "exit_code": code, "scan": scan}


# --- output ----------------------------------------------------------------------------

SEVERITY_TEXT = {"critical": "scanning.cli.severity.critical", "high": "scanning.cli.severity.high",
                 "medium": "scanning.cli.severity.medium", "low": "scanning.cli.severity.low", "info": "scanning.cli.severity.info"}
FAIL_ON_TEXT = {"critical": "scanning.cli.fail_on.critical", "high": "scanning.cli.fail_on.high", "medium": "scanning.cli.fail_on.medium",
                "low": "scanning.cli.fail_on.low", "never": "scanning.cli.fail_on.never"}


def _severity(level: str, locale: str) -> str:
    return t(SEVERITY_TEXT[level], locale) if level in SEVERITY_TEXT else level


def _grouped(findings: list[dict], locale: str) -> list[tuple[str, str, str]]:
    """One line per fix: advisories of the same package are closed by a single upgrade.

    The proposed version is the highest of the ones that fix each advisory (the one that closes them all)."""
    from pitangus.modules.intel.advisories import compare_versions
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    rows, packages = [], {}
    for item in findings:
        package = item.get("package") or {}
        if item.get("scanner") == "sca" and package.get("name"):
            packages.setdefault((item["path"], package["name"], package.get("version") or ""), []).append(item)
        else:
            rows.append((item["severity"], f"{item['path']}:{item['line']}", text(item["title"], locale)))
    for (path, name, version), items in packages.items():
        worst = min((item["severity"] for item in items), key=lambda level: order.get(level, 9))
        fixes = [item["package"]["fixed_version"] for item in items if item["package"].get("fixed_version")]
        target = None
        for fix in fixes:
            target = fix if target is None or compare_versions(fix, target) > 0 else target
        counts = ", ".join(f"{sum(1 for item in items if item['severity'] == level)} {_severity(level, locale).lower()}"
                           for level in SEVERITY_ORDER if any(item["severity"] == level for item in items))
        advice = t("scanning.cli.upgrade", locale, version=target) if target and len(fixes) == len(items) else \
            t("scanning.cli.upgrade_partial", locale, version=target) if target else t("scanning.cli.no_fix", locale)
        rows.append((worst, path, t("scanning.cli.package_row", locale, package=name, version=version,
                                    advisories=t("scanning.cli.advisories", locale, count=len(items)), counts=counts, advice=advice)))
    return sorted(rows, key=lambda row: (order.get(row[0], 9), row[1]))


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _safe(value) -> str:
    """Paths and titles come from the scanned repository: with no control characters, a file name can't
    move the cursor, erase lines or fake the verdict in the terminal or the CI log (CWE-150)."""
    return _CONTROL.sub("?", str(value))


def _scanned(result: dict, locale: str) -> list[str]:
    """What was scanned when it isn't the folder on disk: a commit or the index."""
    snapshot = result.get("snapshot") or "worktree"
    return [] if snapshot == "worktree" else [t("scanning.cli.at_staged", locale)] if snapshot == "index" \
        else [t("scanning.cli.at_commit", locale, commit=snapshot[:8])]


def render_text(result: dict, *, limit: int = 50, locale: str | None = None) -> str:
    locale = locale or default_locale()
    comparison = result["comparison"]
    scope = (t("scanning.cli.scope_changes", locale, base=comparison["base"], commit=comparison["merge_base"][:8],
               count=comparison["changed_files"]) if comparison else t("scanning.cli.scope_all", locale))
    lines = [" · ".join(["Pitangus", _safe(result["name"]), *_scanned(result, locale), _safe(scope)]), ""]
    if comparison and not comparison["baseline"] and comparison["changed_files"]:
        lines += [t("scanning.cli.no_baseline", locale), ""]
    findings = result["findings"]
    rows = _grouped(findings, locale)
    if findings:
        for severity, where, title in rows[:limit]:
            lines.append(f"{_severity(severity, locale).upper().ljust(8)} {_safe(where)}  {_safe(title)}")
        if len(rows) > limit:
            lines.append(t("scanning.cli.more", locale, count=len(rows) - limit))
    else:
        lines.append(t("scanning.cli.no_new_findings", locale) if comparison else t("scanning.cli.no_findings", locale))
    if comparison and comparison["preexisting_in_changed_code"]:
        lines += ["", t("scanning.cli.preexisting", locale, count=comparison["preexisting_in_changed_code"])]
    lines += _resolved_text(result, locale, limit)
    skipped = (result.get("excluded") or {}).get("findings") or 0
    if skipped:
        lines += ["", t("scanning.cli.excluded", locale, count=skipped,
                        patterns=", ".join(_safe(item) for item in result["excluded"]["patterns"]))]
    ran = ", ".join(text(item, locale) for item in result["engines"]["ran"]) or t("scanning.cli.no_engines", locale)
    failed = ", ".join(text(item, locale) for item in result["engines"]["failed"])
    lines += ["", t("scanning.cli.engines_failed", locale, ran=ran, failed=failed) if failed else t("scanning.cli.engines", locale, ran=ran)]
    for item in result["not_analyzed"]:
        lines.append(t("scanning.cli.not_analyzed", locale, item=_safe(text(item, locale))))
    lines += _unexamined(result, locale)
    lines += _suppressed_inline(result, locale)
    verdict_line = t({EXIT_OK: "scanning.cli.verdict.pass", EXIT_BLOCKED: "scanning.cli.verdict.blocked",
                      EXIT_INCOMPLETE: "scanning.cli.verdict.incomplete"}[result["exit_code"]], locale)
    detail = _counted(result, [row[0] for row in rows], locale)
    lines += ["", t("scanning.cli.verdict_line", locale, verdict=verdict_line, threshold=t(FAIL_ON_TEXT[result["fail_on"]], locale),
                    detail=detail)]
    return "\n".join(lines) + "\n"


def _unexamined(result: dict, locale: str, shown: int = 3) -> list[str]:
    """The files an engine that ran didn't examine, by engine and reason (what the copy left out is said once, not
    per engine): nothing it could have found there counts as gone."""
    from pitangus.modules.scanning.engine_contract import reason_message
    scan = result.get("scan") or {}
    names = {(step.get("tool") or {}).get("name"): step["name"] for step in scan.get("steps") or []}
    groups: dict[tuple[str, str], list[str]] = {}
    for engine, cover in (scan.get("coverage") or {}).items():
        # Units only one of the engine's scanners skipped (engine_contract.coverage's `by_scanner`) are listed too.
        scoped = [item for units in (cover.get("by_scanner") or {}).values() for item in units.items()]
        for unit, why in dict([*scoped, *(cover.get("unexamined") or {}).items()]).items():
            if why not in ("left_out", "workspace"):   # a workspace member was read in its workspace's lockfile
                groups.setdefault((names.get(engine) or engine, why), []).append(unit)
    # The same files left out of several engines for the same reason (the folders only the secret scanners read): one line.
    engines: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for (engine, why), units in sorted(groups.items()):
        engines.setdefault((why, tuple(sorted(units))), []).append(engine)
    def listed(units) -> str:
        return ", ".join(_safe(unit) for unit in sorted(units)[:shown]) + ("…" if len(units) > shown else "")
    left_out = (scan.get("unexamined") or {}).get("*") or []
    return ([t("scanning.cli.left_out", locale, count=len(left_out), paths=listed(left_out))] if left_out else []) + \
        [t("scanning.cli.unexamined", locale, engine=", ".join(_safe(engine) for engine in engines_), count=len(units),
           reason=text(reason_message(why), locale), paths=listed(units))
         for (why, units), engines_ in sorted(engines.items(), key=lambda item: (item[1], item[0]))]


def _suppressed_inline(result: dict, locale: str, shown: int = 5) -> list[str]:
    """Where a `gitleaks:allow` comment in the code allowed a secret (file:line, never the value): honoured, and said."""
    places = sorted({place for cover in ((result.get("scan") or {}).get("coverage") or {}).values()
                     for place in cover.get("suppressed_inline") or []})
    if not places:
        return []
    listed = ", ".join(_safe(place) for place in places[:shown]) + ("…" if len(places) > shown else "")
    return [t("scanning.cli.suppressed_inline", locale, count=len(places), places=listed)]


def _counted(result: dict, severities: list[str], locale: str) -> str:
    """The verdict's count, of the rows shown (a package's advisories are one row), not of the findings behind them."""
    if result["exit_code"] == EXIT_INCOMPLETE:
        return t("scanning.cli.incomplete", locale)
    return text(verdict([{"severity": level} for level in severities], result["fail_on"])["description"], locale)


def _one_per_package(findings: list[dict], locale: str) -> list[dict]:
    """For the Markdown tables, as in the terminal: a package's advisories become one row with the version that closes them."""
    from pitangus.modules.intel.advisories import compare_versions
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    rows, packages = [], {}
    for item in findings:
        package = item.get("package") or {}
        if item.get("scanner") == "sca" and package.get("name"):
            packages.setdefault((item["path"], package["name"], package.get("version") or ""), []).append(item)
        else:
            rows.append(item)
    for items in packages.values():
        worst = min(items, key=lambda item: order.get(item["severity"], 9))
        fixes = [item["package"]["fixed_version"] for item in items if item["package"].get("fixed_version")]
        target = None
        for version in fixes:
            target = version if target is None or compare_versions(version, target) > 0 else target
        rows.append({**worst, "title": t("scanning.cli.advisories", locale, count=len(items)),
                     "package": {**worst["package"], "fixed_version": target if len(fixes) == len(items) else None}})
    return rows


def _resolved_text(result: dict, locale: str, limit: int) -> list[str]:
    comparison = result["comparison"]
    if not comparison or not comparison["baseline"]:
        return []
    if not comparison.get("resolved_verifiable"):
        return ["", t("scanning.cli.resolved.unverifiable", locale)]
    fixed = [item for item in result.get("resolved") or [] if item["resolution"] == "fixed"]
    lines = []
    if fixed:
        rows = _grouped(fixed, locale)
        lines += ["", t("scanning.cli.resolved.fixed", locale, count=len(rows))]
        lines += [f"  {_severity(severity, locale).upper().ljust(8)} {_safe(where)}  {_safe(title)}" for severity, where, title in rows[:limit]]
        if len(rows) > limit:
            lines.append("  " + t("scanning.cli.more", locale, count=len(rows) - limit))
    others = comparison["resolved"]
    for how in ("deleted", "unattributed"):
        if others.get(how):
            lines += [t(f"scanning.cli.resolved.{how}", locale, count=others[how])] if lines else \
                ["", t(f"scanning.cli.resolved.{how}", locale, count=others[how])]
    return lines


def render_json(result: dict, *, locale: str | None = None) -> str:
    from pitangus.modules.findings.fix_guide import attach
    fields = ("fingerprint", "severity", "scanner", "tool", "also_detected_by", "rule_id", "title", "path", "line",
              "cwe", "cve", "ghsa", "package", "malicious", "remediation", "fix", "priority", "kev", "epss")
    payload = {key: result.get(key) for key in ("target", "status", "comparison", "fail_on", "excluded", "engines", "not_analyzed", "exit_code")}
    payload["gate"] = result["gate"]
    # `fix`: the same fix guide as the panel (steps, commands and example), for whoever fixes from the terminal.
    findings = attach([dict(item) for item in result["findings"]])
    payload["findings"] = [{key: item.get(key) for key in fields if item.get(key) is not None} for item in findings]
    # What the starting point had and the change no longer has, with how it went away (fixed, deleted, unattributed).
    payload["resolved"] = [{key: item.get(key) for key in (*fields[:9], "package", "resolution") if item.get(key) is not None}
                           for item in result.get("resolved") or []]
    return json.dumps(localize(payload, locale or default_locale()), ensure_ascii=False, indent=2) + "\n"


def render_prompt(result: dict, *, limit: int = 50, locale: str | None = None) -> str:
    """One prompt per finding to paste into the developer's own AI assistant (findings/ai_prompt.py), worst first; no
    secret value and no code beyond each matched fragment."""
    from pitangus.modules.findings.ai_prompt import prompt
    from pitangus.modules.findings.fix_guide import attach
    locale = locale or default_locale()
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    findings = sorted(attach([dict(item) for item in result["findings"]]), key=lambda item: (order.get(item["severity"], 9), item["path"], item.get("line") or 0))
    allowed = "".join(line + "\n" for line in _suppressed_inline(result, locale))
    if not findings:
        return (t("scanning.cli.no_new_findings", locale) if result["comparison"] else t("scanning.cli.no_findings", locale)) + "\n" + allowed
    blocks = [prompt(finding, locale) for finding in findings[:limit]]
    more = [t("scanning.cli.more", locale, count=len(findings) - limit) + "\n"] if len(findings) > limit else []
    return "\n---\n\n".join(blocks + more + ([allowed] if allowed else []))


def render_sarif(result: dict, *, locale: str | None = None) -> str:
    from pitangus.modules.runs.store import render_repository_sarif
    locale = locale or default_locale()
    sarif = render_repository_sarif({"findings": localize(result["findings"], locale)})
    return json.dumps(localize(sarif, locale), ensure_ascii=False, indent=2) + "\n"


def render_markdown(result: dict, *, locale: str | None = None) -> str:
    """The same result as a Markdown summary (a CI job summary): verdict, what the change introduces and what it fixes."""
    locale = locale or default_locale()
    comparison = result["comparison"]
    scope = (t("scanning.cli.scope_changes", locale, base=comparison["base"], commit=comparison["merge_base"][:8],
               count=comparison["changed_files"]) if comparison else t("scanning.cli.scope_all", locale))
    verdict_line = t({EXIT_OK: "scanning.cli.verdict.pass", EXIT_BLOCKED: "scanning.cli.verdict.blocked",
                      EXIT_INCOMPLETE: "scanning.cli.verdict.incomplete"}[result["exit_code"]], locale)
    introduced = _one_per_package(result["findings"], locale)
    detail = _counted(result, [item["severity"] for item in introduced], locale)
    if comparison:  # the branch comes from the repository: in code, not Markdown
        scope = t("scanning.cli.scope_changes", locale, base=f"`{_safe(comparison['base']).replace('`', '')}`",
                  commit=comparison["merge_base"][:8], count=comparison["changed_files"])
    lines = [t("scanning.cli.summary.heading", locale, name=_safe(result["name"]).replace("`", "'")), "",
             " · ".join([*_scanned(result, locale), scope]), "",
             "**" + t("scanning.cli.verdict_line", locale, verdict=verdict_line, threshold=t(FAIL_ON_TEXT[result["fail_on"]], locale),
                      detail=detail) + "**"]
    more = "scanning.cli.summary.more"
    if result["findings"]:
        lines += ["", t("scanning.cli.summary.introduced", locale, count=len(introduced)), "",
                  *markdown_rows(introduced, locale, more=more)]
    if comparison and comparison["baseline"]:
        if not comparison.get("resolved_verifiable"):
            lines += ["", t("scanning.cli.resolved.unverifiable", locale)]
        else:
            fixed = _one_per_package([item for item in result.get("resolved") or [] if item["resolution"] == "fixed"], locale)
            if fixed:
                lines += ["", t("scanning.cli.summary.fixed", locale, count=len(fixed)), "",
                          *markdown_rows(fixed, locale, fix=False, more=more)]
            for how in ("deleted", "unattributed"):
                if comparison["resolved"].get(how):
                    lines += ["", t(f"scanning.cli.resolved.{how}", locale, count=comparison["resolved"][how])]
    if comparison and comparison["preexisting_in_changed_code"]:
        lines += ["", t("scanning.cli.preexisting", locale, count=comparison["preexisting_in_changed_code"])]
    ran = ", ".join(text(item, locale) for item in result["engines"]["ran"]) or t("scanning.cli.no_engines", locale)
    failed = ", ".join(text(item, locale) for item in result["engines"]["failed"])
    lines += ["", t("scanning.cli.engines_failed", locale, ran=ran, failed=failed) if failed else t("scanning.cli.engines", locale, ran=ran)]
    for item in result["not_analyzed"]:
        lines += ["", t("scanning.cli.not_analyzed", locale, item=_safe(text(item, locale)))]
    lines += [line for item in _unexamined(result, locale) for line in ("", item.replace("`", "'"))]
    return "\n".join(lines) + "\n"
