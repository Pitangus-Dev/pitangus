"""Which repository each image is built from, and the scope of portfolio evidence.

An image says where it comes from in its OCI labels (`org.opencontainers.image.source` and `.revision`, read at scan
time). When that repository is analyzed too, the image is linked to it on its own. The team can set or override the
link by hand (images without labels, mirrored registries); a manual link wins over the label.

An image can also be added by hand before it is scanned (`sources.images`): it shows on the Images page and can be
linked, but it has no findings, so it stays out of the evidence catalog and of every portfolio scope until a scan.

The scope of a portfolio file (SBOM, VEX, consolidated evidence) is every analyzed asset, the repositories of one
organization, or a chosen set; with a repository come the images built from it unless that is turned off.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pitangus.modules.compliance import evidence
from pitangus.modules.sources import images as registered_images
from pitangus.shared import db, documents
from pitangus.shared.i18n import msg

DOCUMENT = "image-links"
SCOPE_MAX = 500


class ProvenanceError(ValueError):
    def __init__(self, message: dict):
        super().__init__(message)
        self.message = message


class ImageNotRegistered(ProvenanceError):
    pass


class ImageAnalyzed(ProvenanceError):
    pass


def _pending(data_dir: Path, rows: list[dict]) -> list[dict]:
    """Images added by hand and never scanned, shaped like catalog rows (`rows`, the catalog, says what was scanned)."""
    scanned = {row["key"] for row in rows}
    return [{"key": item["key"], "name": item["name"], "kind": "image", "last_complete": None, "last_status": None,
             "reference": item["reference"]} for item in registered_images.registered(data_dir) if item["key"] not in scanned]


def _latest_scan(data_dir: Path, key: str) -> dict | None:
    from pitangus.modules.runs.store import find_runs
    return next(iter(find_runs(data_dir, assets=[key], limit=1)), None)


def _reference(scan: dict) -> str | None:
    """The reference an image scan pulled: the one to scan it again."""
    return ((scan.get("source") or {}).get("image") or {}).get("reference") or scan.get("target")


def _labels(data_dir: Path) -> dict[str, dict]:
    """The OCI label of each image's latest scan: {image key: {"host", "repository", "revision"}}."""
    from pitangus.modules.runs.store import find_runs
    from pitangus.modules.sources.assets import asset_key
    found: dict[str, dict] = {}
    for row in find_runs(data_dir, types=("image_scan",)):  # most recent first
        key = asset_key(row)
        if key not in found:
            found[key] = ((row.get("source") or {}).get("image") or {}).get("built_from") or {}
    return found


def links(data_dir: Path, rows: list[dict] | None = None) -> dict[str, dict]:
    """{image key: {"repository": repo key or None, "name", "revision", "how": "label" | "manual"}}.

    `repository` is None when the label names a repository Pitangus hasn't analyzed (shown, but it can't bring it
    into a scope)."""
    rows = rows if rows is not None else evidence.catalog(data_dir)
    repos = {row["key"]: row for row in rows if row["kind"] == "repository"}
    by_name: dict[str, list[dict]] = {}
    for row in repos.values():
        by_name.setdefault(str(row["name"]).casefold(), []).append(row)
    labels, manual = _labels(data_dir), documents.load(data_dir, DOCUMENT, {}) or {}
    result: dict[str, dict] = {}
    for row in rows:
        if row["kind"] != "image":
            continue
        label = labels.get(row["key"]) or {}
        chosen = manual.get(row["key"])
        if isinstance(chosen, dict) and chosen.get("repository") in repos:
            repo = repos[chosen["repository"]]
            same = label.get("repository") and str(label["repository"]).casefold() == str(repo["name"]).casefold()
            result[row["key"]] = {"repository": repo["key"], "name": repo["name"], "revision": label.get("revision") if same else None,
                                  "how": "manual", "by": chosen.get("by"), "at": chosen.get("at")}
        elif label.get("repository"):
            # Same name on the same forge, and only one: never a guess between two repositories.
            candidates = [repo for repo in by_name.get(str(label["repository"]).casefold(), []) if _host(repo["key"]) in (None, label.get("host"))]
            match = candidates[0] if len(candidates) == 1 else None
            result[row["key"]] = {"repository": match["key"] if match else None, "name": match["name"] if match else label["repository"],
                                  "revision": label.get("revision"), "how": "label"}
    return result


def _host(key: str) -> str | None:
    """The forge of a repository asset, from its key (`github#123`, `github:org/repo`, `gitlab:…`); None if unknown."""
    return next((host for prefix, host in (("github", "github.com"), ("gitlab", "gitlab.com")) if key.startswith(prefix)), None)


def link_for(data_dir: Path, key: str) -> dict | None:
    return links(data_dir).get(key)


def set_link(data_dir: Path, image: str, repository: str | None, *, by: str) -> dict | None:
    """Links an image (analyzed, or added by hand) to a repository; `repository=None` goes back to what the image's
    label says."""
    rows = evidence.catalog(data_dir)
    rows += _pending(data_dir, rows)
    kinds = {row["key"]: row["kind"] for row in rows}
    if kinds.get(image) != "image":
        raise ProvenanceError(msg("compliance.provenance.not_an_image"))
    if repository is not None and kinds.get(repository) != "repository":
        raise ProvenanceError(msg("compliance.provenance.not_a_repository"))
    with documents.edit(data_dir, DOCUMENT, {}) as state:
        if repository is None:
            state.pop(image, None)
        else:
            state[image] = {"repository": repository, "by": by, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return links(data_dir, rows).get(image)


def register_image(data_dir: Path, image: dict, *, by: str, repository: str | None = None) -> dict:
    """Adds an image to the Images page without scanning it (`image` as `scanning.image.parse_reference` returns it)
    and, with `repository`, links it by hand. Added again before its first scan, it keeps the new reference; once
    scanned, only the link applies. Returns {"name", "reference", "created", "analyzed", "built_from"}, the name and
    reference being what the Images page shows for it; all or nothing."""
    key = image["asset"]
    with db.transaction(data_dir) as connection:
        db.lock(connection, "image-registry")
        rows = evidence.catalog(data_dir)
        scan = _latest_scan(data_dir, key)
        created = scan is None and registered_images.get(data_dir, key) is None
        if created and len(_pending(data_dir, rows)) >= registered_images.LIMIT:
            raise ProvenanceError(msg("compliance.provenance.too_many_images", max=registered_images.LIMIT))
        if scan is None:
            registered_images.register(data_dir, image, by=by)
            name, reference = image["name"], image["reference"]
        else:
            name, reference = next((row["name"] for row in rows if row["key"] == key), image["name"]), _reference(scan)
        built = set_link(data_dir, key, repository, by=by) if repository is not None \
            else links(data_dir, rows + _pending(data_dir, rows)).get(key)
    return {"name": name, "reference": reference, "created": created, "analyzed": scan is not None, "built_from": built}


def remove_image(data_dir: Path, key: str) -> None:
    """Takes an image added by hand off the Images page, with its manual link. Only one never scanned: a scanned image
    keeps its history."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "image-registry")
        if _latest_scan(data_dir, key) is not None:
            raise ImageAnalyzed(msg("compliance.provenance.image_analyzed"))
        if not registered_images.forget(data_dir, key):
            raise ImageNotRegistered(msg("compliance.provenance.image_not_registered"))
        with documents.edit(data_dir, DOCUMENT, {}) as state:
            state.pop(key, None)


LINK_FILTERS = ("all", "unlinked", "label", "manual")


def images(data_dir: Path, *, query: str = "", link: str = "all", repository: str | None = None) -> dict:
    """The Images page: each image with its latest scan, the reference to scan it (again) and where it is built from;
    the ones added by hand and not scanned yet come first (`analyzed: False`). Filtered by name, by how it is linked
    (`unlinked`: no analyzed repository) or by the `repository` it is built from. `counts` cover every image, whatever
    the filters, for the page's tabs."""
    from pitangus.modules.runs.store import find_runs
    from pitangus.modules.sources.assets import asset_key
    rows = evidence.catalog(data_dir)
    pending = _pending(data_dir, rows)
    built = links(data_dir, rows + pending)
    latest: dict[str, dict] = {}
    for row in find_runs(data_dir, types=("image_scan",)):  # most recent first
        latest.setdefault(asset_key(row), row)
    found = [{"key": row["key"], "name": row["name"], "reference": row["reference"], "last_scan": None, "last_complete": None,
              "analyzed": False, "built_from": built.get(row["key"])} for row in pending]
    for row in rows:
        if row["kind"] != "image":
            continue
        scan = latest.get(row["key"]) or {}
        found.append({"key": row["key"], "name": row["name"], "reference": _reference(scan),
                      "last_scan": {"run_id": scan["id"], "created_at": scan["created_at"], "status": scan["status"]} if scan else None,
                      "last_complete": row["last_complete"], "analyzed": True, "built_from": built.get(row["key"])})
    def how(item: dict) -> str:
        return item["built_from"]["how"] if (item["built_from"] or {}).get("repository") else "unlinked"
    built_by: dict[str, int] = {}
    for item in found:
        if (item["built_from"] or {}).get("repository"):
            built_by[item["built_from"]["repository"]] = built_by.get(item["built_from"]["repository"], 0) + 1
    if repository is not None:
        found = [item for item in found if (item["built_from"] or {}).get("repository") == repository]
    counts = {name: sum(1 for item in found if how(item) == name) for name in LINK_FILTERS[1:]}
    needle = query.strip().casefold()
    items = [item for item in found if (not needle or needle in item["name"].casefold()) and (link == "all" or how(item) == link)]
    return {"items": items, "counts": {"all": len(found), **counts}, "repositories": built_by}


def accounts(rows: list[dict]) -> list[str]:
    """Organizations (owners) of the analyzed repositories, for the scope picker."""
    return sorted({str(row["name"]).split("/", 1)[0] for row in rows if row["kind"] == "repository" and "/" in str(row["name"])},
                  key=str.casefold)


def scope(data_dir: Path, *, assets: list[str] | None = None, account: str | None = None, include_images: bool = True) -> list[dict]:
    """The catalog rows a portfolio file covers: all; the repositories of `account`; or the chosen `assets`. With
    `include_images`, the images built from a chosen repository come along."""
    rows = evidence.catalog(data_dir)
    if not assets and not account:
        return rows
    if account:
        prefix = f"{account.casefold()}/"
        chosen = [row for row in rows if row["kind"] == "repository" and str(row["name"]).casefold().startswith(prefix)]
    else:
        wanted = set((assets or [])[:SCOPE_MAX])
        chosen = [row for row in rows if row["key"] in wanted]
    if include_images:
        keys = {row["key"] for row in chosen}
        built = {image for image, link in links(data_dir, rows).items() if link.get("repository") in keys}
        chosen += [row for row in rows if row["key"] in built and row["key"] not in keys]
    return chosen
