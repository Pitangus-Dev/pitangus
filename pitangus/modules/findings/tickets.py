"""The Jira issue linked to each finding, per asset and fingerprint (`jira-links`).

A link is {key, url, linked_at, by, destination, project} (plus `replaces`, the earlier issues, when someone asked to
create a new one anyway) and, once Pitangus commented on the issue, `sync`: "fixed"
after the verified-fix comment, "open" after the reappeared one. Creating issues is `runs/jira_sync.py`; the connector,
`integrations/jira.py`.
"""

from __future__ import annotations

from pathlib import Path

from pitangus.modules.findings.kinds import FINDING_RUNS
from pitangus.modules.sources.assets import asset_key
from pitangus.shared import documents


def load_links(data_dir: Path) -> dict:
    payload = documents.load(data_dir, "jira-links", {})
    return payload if isinstance(payload, dict) else {}


def _remember(data_dir: Path, asset: str, fingerprint: str, link: dict) -> None:
    with documents.lock(data_dir, "jira-links"):
        links = load_links(data_dir)
        links.setdefault(asset, {})[fingerprint] = link
        documents.save(data_dir, "jira-links", links)


remember = _remember


def forget_issues(data_dir: Path, keys: set[str]) -> int:
    """Drops every link to these issues (they no longer exist in Jira); an issue folded in (`merged`) takes the place
    of a gone one. Returns how many findings lost their link."""
    if not keys:
        return 0
    dropped = 0
    with documents.lock(data_dir, "jira-links"):
        links = load_links(data_dir)
        for asset in links.values():
            for fingerprint, link in list(asset.items()):
                if not isinstance(link, dict) or not any(issue.get("key") in keys for issue in _issues(link)):
                    continue
                remaining = [issue for issue in _issues(link) if issue.get("key") not in keys]
                if remaining:
                    asset[fingerprint] = fold(remaining)
                else:
                    del asset[fingerprint]
                    dropped += 1
        documents.save(data_dir, "jira-links", links)
    return dropped


def mark(data_dir: Path, asset: str, key: str, state: str, run_id: str) -> None:
    """Records on every finding linked to issue `key` what Pitangus last told the issue (see the module notes)."""
    with documents.edit(data_dir, "jira-links", {}) as payload:
        for link in (payload.get(asset) or {}).values():
            for issue in [link, *(link.get("merged") or [])] if isinstance(link, dict) else []:
                if issue.get("key") == key:
                    issue["sync"], issue["sync_run"] = state, run_id


def annotate(data_dir: Path, record: dict) -> dict:
    """Adds to each finding the ticket already created for it, if any."""
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        return record
    links = load_links(data_dir).get(asset_key(record), {})
    if not links:
        return record
    return {**record, "findings": [{**item, "ticket": links[item["fingerprint"]]} if item["fingerprint"] in links else item
                                   for item in record.get("findings", [])]}


def rename_assets(data_dir: Path, moved: dict[str, str]) -> None:
    """Assets that gained a stable identity (old key → new): their links move along; the new key's ones win."""
    if not moved:
        return
    with documents.edit(data_dir, "jira-links", {}) as payload:
        for old_key, uid in moved.items():
            if old_key in payload:
                merged = payload.pop(old_key)
                payload[uid] = {**merged, **payload.get(uid, {})}


def _issues(link: dict) -> list[dict]:
    """A link and the ones folded into it, each on its own."""
    return [{name: value for name, value in link.items() if name != "merged"}, *(link.get("merged") or [])]


def fold(links: list[dict]) -> dict:
    """One link for findings folded into one, losing none of their issues: the first stays the link, the other issues
    go in `merged`, and two links to one issue join what each replaced."""
    issues: dict = {}
    for link in links:
        for issue in _issues(link) if isinstance(link, dict) else []:
            known = issues.setdefault(issue.get("key"), dict(issue))
            extra = [item for item in issue.get("replaces") or [] if item not in (known.get("replaces") or [])]
            if extra:
                known["replaces"] = [*(known.get("replaces") or []), *extra]
    first, *rest = issues.values()
    return {**first, "merged": rest} if rest else first


def carry_over(data_dir: Path, key: str, moved: dict[str, str]) -> None:
    """Findings with a new fingerprint (former → new) keep their issue, so none is created twice; several folded into
    one keep every issue they had (`fold`), the one already under the new fingerprint first, else the oldest."""
    links = load_links(data_dir).get(key) or {}
    if not any(former in links for former in moved):
        return
    with documents.edit(data_dir, "jira-links", {}) as payload:
        asset = payload.setdefault(key, {})
        groups: dict[str, list[str]] = {}
        for former, new in moved.items():
            if isinstance(asset.get(former), dict):
                groups.setdefault(new, []).append(former)
        for new, formers in groups.items():
            older = sorted((asset[former] for former in formers), key=lambda link: (str(link.get("linked_at") or ""), str(link.get("key") or "")))
            asset[new] = fold([*([asset[new]] if isinstance(asset.get(new), dict) else []), *older])


def forget_asset(data_dir: Path, key: str) -> None:
    with documents.edit(data_dir, "jira-links", {}) as payload:
        payload.pop(key, None)
