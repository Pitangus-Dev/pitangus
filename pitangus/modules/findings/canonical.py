"""The canonical identity of a finding: what the problem is, never where an engine happened to print it.

Every kind of finding is identified by its content, the same way whichever engine reports it:

* **code** (SAST, imported SARIF, CI workflows): the rule, the file and the matched code with its comments and
  formatting removed. A line added above, a suppression comment or a reformat change nothing.
* **configuration** (IaC): the rule, the file and the resource's address (`aws_s3_bucket.data`); a report without an
  address is the rule in the file.
* **dependencies**: the advisory (its CVE when it has one), the package as a purl and its version as its ecosystem
  compares it (`v0.3.7` and `0.3.7` in Go are one version).
* **secrets**: the HMAC of the value with a key derived from the master key (computed where the value was read and
  never stored: scanning/secret_identity.py).
* **web**: the tool's rule, the host, the URL's path template (`/users/{}.html`, built from the URLs seen, never
  guessed from one), the evidence value and the kind of scan that saw it (`web.coverage`: an anonymous crawl, one with
  saved headers, one API definition, an exposure check), since only a scan of that kind can tell it is gone. The URL
  is read in its location form (its user information, query, fragment and matrix values and token-shaped path segments
  replaced: shared/render.py `location`, idempotent), and never as it is shown: templates are built on the URLs' keys
  (shared/web_keys.py, pinned before a URL is rendered), the earlier scans' too, and written back on the location form
  of the URL reported now; a stored finding's identity is pinned with it.

Identical problems share one identity: a family. A family is one finding with a count of its instances (the same line
pasted twice, the same secret in two files, one rule on many pages of a template); a copy adds one, removing one takes
one away, and position or order never enter an identity. When something has no content to tell copies apart, the
family is the rule in its unit, and the count does the rest.

`PITANGUS_IDENTITY_MODE` decides what happens with it: `v2` (the default) stores one finding per family (`count`,
`instances`), with the fingerprints its members had as former names so the registry carries their state over; `shadow`
writes each finding's `identity` and what grouping by it would change, without changing anything; `v1` ignores it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any, cast
from urllib.parse import urlsplit

from pitangus.modules.findings.identity import family_of, formers, legacy_formers, may_take, of_value, own_names, unlinkable
from pitangus.modules.intel.packages import package_identity
from pitangus.shared import settings, web_keys
from pitangus.shared.code_identity import anywhere_identity, content_identity, digest as _digest
from pitangus.shared.model import Finding

VERSION = 2
INSTANCES_MAX = 100     # instances one family lists (its count goes on)
FORMERS_MAX = 500       # former fingerprints one family remembers
TEMPLATE_URLS_MAX = 2_000  # URLs of one rule on one host a template is built from (the rest keep their own path)
SEPARATORS = frozenset("-_.~")


def mode() -> str:
    return settings.text("PITANGUS_IDENTITY_MODE")


def _template_url(value: str) -> str:
    """What a web template is built on for a URL or a key: the key (shared/web_keys.py), as a URL; the location form
    of what has none (a URL without a host)."""
    found = value if web_keys.is_key(value) else web_keys.key(value)
    return web_keys.bare(found) if found else web_keys.legacy(value)


def _web_url(finding: Mapping[str, Any]) -> str:
    return _template_url(web_keys.of_finding(finding) or str(finding.get("path") or ""))


def _web_template_key(url: str) -> tuple[str, str, list[str]]:
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", url, []
    return (parts.hostname or "").lower(), f"{parts.scheme}://{(parts.hostname or '').lower()}", parts.path.split("/")


def _bounded(left: str, right: str) -> str | None:
    """The template two different path segments share when what differs sits between separators (`index-{}.js` from
    `index-BkL9x2a1.js` and `index-C0aZ77qp.js`, `{}.html` from two documents); None when they are equal."""
    if left == right:
        return None
    shortest = min(len(left), len(right))
    start = 0
    while start < shortest and left[start] == right[start]:
        start += 1
    while start and left[start - 1] not in SEPARATORS:
        start -= 1
    end = 0
    while end < shortest - start and left[-1 - end] == right[-1 - end]:
        end += 1
    while end and left[len(left) - end] not in SEPARATORS:
        end -= 1
    return f"{left[:start]}{{}}{left[len(left) - end:] if end else ''}"


def _fits(template: str, segment: str) -> bool:
    prefix, _, suffix = template.partition("{}")
    return len(segment) > len(prefix) + len(suffix) and segment.startswith(prefix) and segment.endswith(suffix)


def _assign(segments: set[str]) -> dict[str, str]:
    """The template each literal segment takes among `segments` (one position of paths alike elsewhere): candidates
    come from neighbours in prefix and in suffix order, the most specific (longest fixed text) first, and one is used
    only when two segments fit it (or one template already there). Depends on the set, never on the order."""
    literal = sorted(segment for segment in segments if "{}" not in segment)
    existing = {segment for segment in segments if "{}" in segment}
    candidates = set(existing)
    for ordered in (literal, sorted(literal, key=lambda segment: segment[::-1])):
        for left, right in zip(ordered, ordered[1:]):
            template = _bounded(left, right)
            if template is not None and _fits(template, left) and _fits(template, right):
                candidates.add(template)
    assigned: dict[str, str] = {}
    for template in sorted(candidates, key=lambda item: (-(len(item) - 2), item)):
        fitting = [segment for segment in literal if segment not in assigned and _fits(template, segment)]
        if len(fitting) >= 2 or (fitting and template in existing):
            assigned.update(dict.fromkeys(fitting, template))
    return assigned


def web_templates(urls: Iterable[str]) -> dict[str, str]:
    """Each URL's path template among `urls` (one rule on one host): paths of the same depth that differ in one
    segment vary there (`/users/{}.html`, `/assets/index-{}.js`). Built from the URLs themselves, so a rebuilt asset's
    new hash and its old one share a template as soon as both have been seen, and nothing is guessed from one URL."""
    unique = sorted(set(urls))[:TEMPLATE_URLS_MAX]
    origin = {url: _web_template_key(url)[1] for url in unique}
    patterns = {url: _web_template_key(url)[2] for url in unique}
    changed = True
    while changed:
        changed = False
        for position in range(max((len(pattern) for pattern in patterns.values()), default=0)):
            buckets: dict[tuple, list[str]] = {}
            for url in unique:
                pattern = patterns[url]
                if position < len(pattern):
                    buckets.setdefault((origin[url], len(pattern), tuple(pattern[:position]), tuple(pattern[position + 1:])), []).append(url)
            for members in buckets.values():
                assigned = _assign({patterns[url][position] for url in members})
                for url in members:
                    template = assigned.get(patterns[url][position])
                    if template is not None:
                        patterns[url] = [*patterns[url][:position], template, *patterns[url][position + 1:]]
                        changed = True
    return {url: origin[url] + "/".join(patterns[url]) if origin[url] else url for url in unique}


def identity_of(finding: Mapping[str, Any], template: str | None = None) -> str:
    """The finding's canonical identity (see the module's docstring). `template`: its URL's path template, for a web
    finding (`web_templates`)."""
    if finding.get("identity"):
        return str(finding["identity"])
    scanner = str(finding.get("scanner") or "")
    rule, path = str(finding.get("rule_id") or ""), str(finding.get("path") or "")
    package = finding.get("package") or {}
    if scanner == "sca" and package.get("name"):
        identifiers = {rule, *(finding.get("cve") or []), *(finding.get("ghsa") or []), *((finding.get("advisory") or {}).get("aliases") or [])}
        return package_identity({item for item in identifiers if item}, rule, str(package.get("ecosystem") or ""),
                                str(package["name"]), str(package.get("version") or ""))
    if scanner == "dast":
        if template and not web_keys.is_key(finding.get("web_key")) and web_keys.of_finding(finding):
            # A template built on keys, written on the URL as reported (in clear: not stored yet).
            template = web_keys.template_in_clear(web_keys.legacy(path), template)
        return web_keys.identity(finding, template or web_keys.legacy(path))
    content = content_identity(finding)  # code and configuration (shared/code_identity.py)
    return content if content is not None else _digest("family", family_of(finding))


def _instance(finding: Mapping[str, Any]) -> tuple[str, int, str]:
    pinned = str(finding.get("web_key") or "") if finding.get("scanner") == "dast" and web_keys.is_key(finding.get("web_key")) else ""
    return str(finding.get("path") or ""), 0 if finding.get("scanner") in ("sca", "dast") else int(finding.get("line") or 0), pinned


def _grouped(finding: Mapping[str, Any]) -> bool:
    """A family already (a stored v2 run's finding): its count and instances say where its copies are."""
    return isinstance(finding.get("count"), int) and isinstance(finding.get("instances"), list)


def _units(finding: Mapping[str, Any]) -> list[tuple[str, int, str]]:
    """Where one report of a finding is: a dependency counts each manifest it is in, anything else each place. A
    stored web place carries its key (shared/web_keys.py), which tells it apart, never the URL shown."""
    if _grouped(finding):
        return [(str(item.get("path") or ""), int(item.get("line") or 0), str(item["key"]) if web_keys.is_key(item.get("key")) else "")
                for item in finding["instances"]]
    found = [_instance(finding)]
    for other in ((finding.get("package") or {}).get("also_in") or []):
        found.append((str(other), 0, ""))
    for place in finding.get("also_at") or []:  # the same report in other places, deduplicated by its engine's adapter
        found.append((str(place.get("path") or ""), int(place.get("line") or 0), ""))
    return found


def web_kind(finding: Mapping[str, Any]) -> str:
    """The kind of web scan that saw a finding (`web.coverage`), "baseline" (the anonymous crawl) when it doesn't say."""
    return str((finding.get("web") or {}).get("coverage") or "baseline")


def kind_of(finding: Mapping[str, Any]) -> str:
    """The kind of look a finding belongs to: a web finding's kind of scan, "" for anything else."""
    return web_kind(finding) if finding.get("scanner") == "dast" else ""


def keyed_by_kind(findings: list[Finding]) -> list[Finding]:
    """Each web finding's fingerprint naming its kind of scan (an anonymous crawl's stays the engine's): the engines'
    fingerprints don't, so an exposure check and a full scan reporting one page shared an entry in every identity mode.
    The engine's fingerprint becomes a former name, which the registry only follows within the same kind. Keying twice
    changes nothing."""
    keyed: list[Finding] = []
    for finding in findings:
        kind, fingerprint = kind_of(finding), str(finding.get("fingerprint") or "")
        if kind in ("", "baseline") or not fingerprint or finding.get("identity") \
                or any(_digest("web-kind", name, kind) == fingerprint for name in formers(finding)):
            keyed.append(finding)
            continue
        digest = _digest("web-kind", fingerprint, kind)
        names = list(dict.fromkeys([fingerprint, *(finding.get("previous_fingerprints") or [])]))
        keyed.append(cast(Finding, {**finding, "fingerprint": digest, "finding_id": digest[:16], "previous_fingerprints": names[:FORMERS_MAX]}))
    return keyed


def _web_group(finding: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """(tool, rule, host, kind of scan): the URLs one template is built from."""
    host, _, _ = _web_template_key(_web_url(finding))
    return str(finding.get("tool") or "").lower(), str(finding.get("rule_id") or ""), host, web_kind(finding)


def _known_for(known_urls: Iterable[Any], key: tuple[str, str, str, str]) -> list[str]:
    """The earlier URLs (their keys: shared/web_keys.py) of the rule and kind of scan `key` (tool, rule, host, kind)
    names, as templates are built on them: from (tool, rule, URL or key, kind) entries, only that rule's in that kind of
    scan, so neither another rule's pages nor those another kind of scan reached (behind a login, in an API) ever shape
    its template; a (tool, rule, URL) entry is of every kind and a bare URL of every rule (callers with one)."""
    return [_template_url(str(item) if isinstance(item, str) else str(item[2])) for item in known_urls
            if isinstance(item, str) or (len(item) in (3, 4) and str(item[0]).lower() == key[0] and str(item[1]) == key[1]
                                         and (len(item) == 3 or str(item[3] or "baseline") == key[3]))]


def _identities(findings: list[Finding], known_urls: Iterable[Any] = ()) -> list[str]:
    """Each finding's identity, in order: a web finding's from the path templates of the URLs among `findings` and
    `known_urls` ((tool, rule, URL) each, `registry.web_known`, or bare URLs: `_known_for`)."""
    known = list(known_urls)
    groups: dict[tuple[str, str, str, str], list[str]] = {}
    for finding in findings:
        if finding.get("scanner") == "dast":
            groups.setdefault(_web_group(finding), []).append(_web_url(finding))
    templates: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for key, urls in groups.items():
        templates[key] = web_templates([*urls, *(url for url in _known_for(known, key) if _web_template_key(url)[0] == key[2])])
    found = []
    for finding in findings:
        template = templates[_web_group(finding)].get(_web_url(finding)) if finding.get("scanner") == "dast" else None
        found.append(identity_of(finding, template))
    return found


def _places(members: list[Finding]) -> tuple[list[tuple[str, int, str]], int]:
    """A family's distinct places and its count: a member already grouped brings the copies past its listed instances."""
    distinct: dict[tuple[str, int], tuple[str, int, str]] = {}
    for member in members:
        for place in _units(member):
            distinct.setdefault((place[2] or place[0], place[1]), place)
    places = list(distinct.values())
    beyond = sum(max(0, int(member["count"]) - len(member["instances"])) for member in members if _grouped(member))
    return places, len(places) + beyond


def _families(findings: list[Finding], known_urls: Iterable[Any] = ()) -> dict[str, list[Finding]]:
    families: dict[str, list[Finding]] = {}
    for finding, identity in zip(findings, _identities(findings, known_urls)):
        families.setdefault(identity, []).append(finding)
    return families


def collapse(findings: list[Finding], known_urls: Iterable[Any] = ()) -> list[Finding]:
    """One finding per family: the first report keeps its fields, the fingerprint becomes the identity, `count` the
    number of distinct places it is in (a copy, a manifest, a page) and `instances` the first of them; the engines
    that reported it and every fingerprint its members had go along, so nothing is lost and the registry carries their
    state over. `known_urls`: the asset's web instances from earlier scans, (tool, rule, URL) each
    (`registry.web_known`), so a rule's template spans scans. Collapsing a
    collapsed run changes nothing."""
    result: list[Finding] = []
    for identity, members in _families(findings, known_urls).items():
        first = members[0]
        places, count = _places(members)
        tools = [str(member.get("tool") or "") for member in members]
        detected = list(dict.fromkeys([*tools, *(item for member in members for item in member.get("also_detected_by") or [])]))
        # A family named by its value keeps its value's names apart from its engines' fingerprints (findings/identity.py).
        valued = [member for member in members if of_value(member)]
        names = list(dict.fromkeys(name for member in members if not unlinkable(member)
                                   for name in (legacy_formers(member) if of_value(member) else [member["fingerprint"], *formers(member)])
                                   if name != identity))
        merged: dict[str, Any] = {key: value for key, value in first.items() if key not in ("family", "previous_fingerprint", "previous_fingerprints", "also_at")}
        merged.update(fingerprint=identity, finding_id=identity[:16], identity=identity, identity_version=VERSION, count=count,
                      instances=[{"path": path, **({"line": line} if line else {}), **({"key": key} if key else {})}
                                 for path, line, key in places[:INSTANCES_MAX]])
        if valued:
            merged["value_formers"] = list(dict.fromkeys(name for member in valued for name in formers(member) if name != identity))[:FORMERS_MAX]
        detected = [tool for tool in detected if tool and tool != first.get("tool")]
        if detected:
            merged["also_detected_by"] = detected
        if names:
            merged["previous_fingerprints"] = names[:FORMERS_MAX]
        result.append(cast(Finding, merged))
    return result


def family_counts(findings: Iterable[Mapping[str, Any]], known_urls: Iterable[Any] = ()) -> Counter[str]:
    """How many instances each family has, as the registry counts them (`collapse`'s `count`), whether `findings` are
    an engine's reports or a stored run already grouped."""
    return Counter({identity: _places(members)[1] for identity, members in _families(cast(list[Finding], list(findings)), known_urls).items()})


def anywhere(finding: Mapping[str, Any]) -> str | None:
    """What a code or configuration finding is wherever it sits in the repository (shared/code_identity.py
    `anywhere_identity`, pinned before its code is rendered)."""
    return anywhere_identity(finding)


def growth(base: Iterable[Mapping[str, Any]], head: list[Finding], renamed: Mapping[str, str] | None = None) -> tuple[list[str], Counter[str]]:
    """The PR gate's comparison, with the registry's identity: each head finding's family and how many instances each
    family gained over the base. Both sides are grouped and counted alike, whatever they are (an engine's reports, a
    stored run already grouped); a base family the head knows by a former name (scanned before a formula changed) is
    the same family, as the registry follows names (`identity.may_take`: a secret's engine fingerprint never makes two
    values one, so a PR that changes a secret's value in place introduces the new one). `renamed` ({head path: base path}, from git's or GitHub's rename detection): a renamed file's
    findings are counted as the base file's. And the whole repository decides what is new, not each file: an instance
    a family gained is no gain when another family of the same code (`anywhere`) lost one, so moving a line to another
    file introduces nothing and copying it there introduces one. The registry's identity stays per file."""
    before_findings = cast(list[Finding], list(base))
    renamed = renamed or {}
    as_base = [cast(Finding, {**finding, "path": renamed[str(finding.get("path"))]}) if str(finding.get("path")) in renamed else finding
               for finding in head]
    urls = [web_keys.of_finding(item) or str(item.get("path") or "") for item in [*before_findings, *head] if item.get("scanner") == "dast"]
    identities = _identities(as_base, urls)
    now = family_counts(as_base, urls)
    before = family_counts(before_findings, urls)
    alias: dict[str, tuple[str, Mapping[str, Any]]] = {}   # a base name: its family, and a report of it
    code: dict[str, str | None] = {}
    for finding, identity in zip(before_findings, _identities(before_findings, urls)):
        code.setdefault(identity, anywhere(finding))
        for name in own_names(finding):
            alias.setdefault(name, (identity, finding))
    names: dict[str, set[tuple[str, bool]]] = {}            # a head family's names, each marked legacy or not
    heads: dict[str, Finding] = {}
    for finding, identity in zip(as_base, identities):
        code[identity] = anywhere(finding)
        heads.setdefault(identity, finding)
        names.setdefault(identity, set()).update({(name, False) for name in own_names(finding)} | {(name, True) for name in legacy_formers(finding)})
    added: Counter[str] = Counter()
    lost: Counter[str] = Counter()     # instances gone from the base, by their code wherever it is
    claimed: set[str] = set(before) & set(now)
    for identity in sorted(now):
        prior = before.get(identity)
        if prior is None:
            # Only names the registry follows (identity.may_take): a value is never another value.
            matched = sorted({alias[name][0] for name, legacy in names[identity]
                              if name in alias and may_take(heads[identity], alias[name][1], legacy)} - set(now) - claimed)
            claimed.update(matched)
            prior = sum(before[item] for item in matched)
        if now[identity] > prior:
            added[identity] = now[identity] - prior
        elif prior > now[identity] and code[identity]:
            lost[str(code[identity])] += prior - now[identity]
    for identity in sorted(set(before) - claimed):
        if code[identity]:
            lost[str(code[identity])] += before[identity]
    for identity in sorted(added):
        moved = min(added[identity], lost[str(code[identity])]) if code[identity] else 0
        lost[str(code[identity])] -= moved
        added[identity] -= moved
    return identities, +added


def annotate(findings: list[Finding], known_urls: Iterable[Any] = ()) -> tuple[list[Finding], dict]:
    """Shadow mode: each finding with its `identity`, and what `collapse` would change (families, merged reports)."""
    families = collapse(findings, known_urls)
    member_of = {name: family["fingerprint"] for family in families for name in family.get("previous_fingerprints") or []}
    annotated = [cast(Finding, {**finding, "identity": member_of.get(finding["fingerprint"], finding["fingerprint"])}) for finding in findings]
    return annotated, {"version": VERSION, "findings": len(findings), "families": len(families),
                       "grouped": sum(1 for family in families if family["count"] > 1)}


def prepare(record: dict, known_urls: Iterable[Any] = ()) -> dict:
    """A finished run as the registry and everything after it sees it, per PITANGUS_IDENTITY_MODE; a web scan's
    fingerprints name its kind of scan in every mode (`keyed_by_kind`)."""
    current = mode()
    if not (record.get("findings") or record.get("excluded_findings")):
        return record
    if record.get("type") == "dast_scan":
        record = {**record, "findings": keyed_by_kind(record.get("findings") or []),
                  **({"excluded_findings": keyed_by_kind(record["excluded_findings"])} if record.get("excluded_findings") else {})}
    if current == "v1":
        return record
    known = list(known_urls)
    if current == "shadow":
        findings, summary = annotate(record.get("findings") or [], known)
        annotated = {**record, "findings": findings, "identity_shadow": summary}
        if record.get("excluded_findings"):
            annotated["excluded_findings"] = annotate(record["excluded_findings"], known)[0]
        return annotated
    findings = collapse(record.get("findings") or [], known)
    updated = {**record, "findings": findings, "identity_version": VERSION}
    if record.get("excluded_findings"):
        updated["excluded_findings"] = collapse(record["excluded_findings"], known)
    counts = record.get("summary")
    if isinstance(counts, dict) and "candidates" in counts:
        severities = {level: sum(1 for item in findings if item.get("severity") == level) for level in (counts.get("severities") or {})}
        updated["summary"] = {**counts, "candidates": len(findings), **({"severities": severities} if severities else {})}
    return updated
