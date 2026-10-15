"""Third-party code copied into a repository (vendored): libraries under `vendor/` or `public/js/libs/`, a minified
bundle, a file that opens with the license banner of a known library.

A code rule fires there as anywhere else, but the repository's owners don't write that code and won't fix it in place:
they update the library. Its SAST findings are listed apart, as excluded with the reason (never dropped, never fixed),
the way a `nosemgrep` comment withholds one. The decision reads only the file (the folders it sits in and its first
bytes), never the rule that fired, so every finding in one file gets the same answer; and never the file's own name:
anyone can call their code `lodash-helpers.js`, and renaming a file changes nothing about who wrote it. Secrets are not
withheld: a key inside a bundle is just as leaked.
"""

from __future__ import annotations

import re
from pathlib import Path

from pitangus.shared.i18n import MARK, msg
from pitangus.shared.model import Message

HEAD = 64_000
# Folders that hold someone else's code wherever they appear.
VENDOR_FOLDERS = {"vendor", "vendors", "third_party", "third-party", "thirdparty", "bower_components", "node_modules",
                  "jspm_packages", "web_modules"}
# `lib`, `libs` or `plugins` hold libraries when they sit among the static files a site serves (`public/lib`,
# `static/js/libs`, `assets/plugins`); elsewhere (`src/lib`) they are usually the project's own.
LIBRARY_FOLDERS = {"lib", "libs", "plugins", "external", "ext"}
STATIC_FOLDERS = {"public", "static", "assets", "js", "javascripts", "www", "wwwroot", "webroot", "htdocs"}
SCRIPT = re.compile(r"\.(?:m|c)?js$", re.I)
# Projects whose builds people copy into their repositories, spelled as their banners spell them (case matters: `THREE`
# is three.js's global, "three" is a word). Words of everyday English ("marked", "Foundation") stay out.
KNOWN = ("jQuery", "jquery", "jQuery UI", "Bootstrap", "bootstrap", "lodash", "Lodash", "Lo-Dash", "Underscore.js",
         "Moment.js", "moment.js", "Moment Timezone", "Chart.js", "AngularJS", "Angular", "React", "ReactDOM", "Vue.js",
         "Vue", "D3", "d3", "three.js", "THREE", "Ace", "wysihtml5", "Materialize", "Font Awesome", "Popper.js", "Popper",
         "Select2", "select2", "js-sha256", "js-sha1", "js-md5", "CryptoJS", "crypto-js", "JSEncrypt", "Backbone.js",
         "Handlebars", "handlebars", "mustache.js", "Knockout", "Modernizr", "RequireJS", "html5shiv", "Respond.js",
         "Highcharts", "highlight.js", "Prism", "CodeMirror", "TinyMCE", "CKEditor", "Summernote", "Quill", "DataTables",
         "Tether", "Semantic UI", "UIkit", "ECharts", "Leaflet", "Socket.IO", "SockJS", "axios", "Preact", "core-js",
         "regenerator-runtime", "FullCalendar", "Day.js", "Showdown", "markdown-it", "DOMPurify", "SweetAlert2",
         "SweetAlert", "toastr", "Hammer.js", "GSAP", "anime.js", "PDF.js", "pdf.js", "Video.js", "Plyr", "fancyBox",
         "clipboard.js", "Bootbox", "bootbox.js", "typeahead.js", "Sizzle", "QUnit", "Mocha", "Jasmine", "Chai",
         "Sinon.JS", "Ext JS", "Zepto", "Zepto.js", "MooTools", "Prototype JavaScript framework", "script.aculo.us", "YUI",
         "Ember", "Polymer", "Alpine.js", "htmx", "Tippy.js", "SortableJS", "jsPDF", "html2canvas", "JSZip",
         "FileSaver.js", "Mapbox GL JS", "OpenLayers", "Cytoscape", "vis.js", "Dropzone", "Cropper.js", "flatpickr",
         "Pikaday", "noUiSlider", "Swiper", "Slick", "Isotope", "es5-shim", "es6-shim", "json2.js")
# Families whose plugins carry the family's name (`bootstrap-transition.js`, `jquery.form`, `angular-route`).
FAMILIES = r"(?i:jquery|bootstrap|angular|d3)(?=[-.][a-z])"
NAMED = re.compile(r"(?:" + "|".join(re.escape(name) for name in sorted(KNOWN, key=len, reverse=True)) + rf")(?![\w-])|{FAMILIES}")
# A banner's first line once its comment markers, rules and leading tags are gone (`/*!`, ` * `, `//!`, `====`,
# `@license`, `[`).
MARKERS = re.compile(r"^(?:[/*!=\s\[-]|@(?:license|preserve|module|name|fileoverview)\b)+", re.I)
# The global the first statement after the banner declares (three.js names itself only there: `var THREE = {…`).
DECLARED = re.compile(r"\A\s*(?:(?:var|let|const)\s+|window\.)([\w$.]+)\s*=")
# A release: `v1.2`, `3.4.1`, or the version a tag or a property states (`@version 0.9.0`, `version : 2.29.1`,
# `REVISION: '67'`).
RELEASE = re.compile(r"\bv\d+\.\d+|(?<![\w.])\d+\.\d+\.\d+(?![\w.])|(?i:\b(?:version|revision)\b)\W{0,6}v?\d+(?:\.\d+)*")
LICENSE = re.compile(r"licen[cs]e|copyright|\(c\)|\bMIT\b|\bBSD\b|Apache|@author", re.I)
# What a library is at the least: a file this small is somebody's snippet, whatever its banner says.
LIBRARY_SIZE = 8_000
COMMENT = re.compile(rb"\A(?:\s|\xef\xbb\xbf)*(/\*.*?\*/|(?://[^\n]*\n\s*)+)", re.S)
PREAMBLE = 512


def classify(path: str, head: bytes) -> tuple[str, str] | None:
    """Why this file is someone else's code, as (kind, detail), or None. `head`: the file's first bytes (HEAD of them).
    Only its folders and its content decide: the same bytes under another file name get the same answer."""
    parts = [part for part in str(path or "").replace("\\", "/").split("/") if part not in ("", ".")]
    if not parts:
        return None
    folders, name = [part.lower() for part in parts[:-1]], parts[-1]
    for index, folder in enumerate(folders):
        if folder in VENDOR_FOLDERS or (folder in LIBRARY_FOLDERS and STATIC_FOLDERS & set(folders[:index])):
            return "folder", "/".join(parts[:index + 1])
    if not SCRIPT.search(name):
        return None
    if minified(head):
        return "minified", name
    if (library := banner(head)) is not None:
        return "banner", library
    return None


def minified(head: bytes) -> bool:
    """Written by a tool, not by hand: almost no whitespace, or lines hundreds of characters long on average."""
    if len(head) < 2048:
        return False
    lines = head.count(b"\n") + 1
    blank = sum(head.count(character) for character in b" \t\n\r")
    return blank / len(head) < 0.06 or len(head) / lines > 300


def banner(head: bytes) -> str | None:
    """The known library whose license banner opens the file, or None. The banner opens by naming a KNOWN project (or
    the first statement after it declares that project's global), it states a release and a license, copyright or
    author, and the file is as large as a library. A project's own header ("Acme Portal v2.3.0, Copyright Acme") names
    no known project, and a mention further down ("built on jQuery 3.7.1") doesn't open the banner."""
    if len(head) < LIBRARY_SIZE or not (comment := COMMENT.match(head)):
        return None
    text = comment.group(1).decode("utf-8", "replace")
    lead = next((cleaned for line in text.splitlines() if (cleaned := MARKERS.sub("", line).strip())), "")
    following = head[comment.end():comment.end() + PREAMBLE].decode("utf-8", "replace")
    declared = DECLARED.match(following)
    named = NAMED.match(lead) or (NAMED.fullmatch(declared.group(1)) if declared else None)
    if named is None or not LICENSE.search(text) or not RELEASE.search(text + "\n" + following.lstrip().split("\n", 1)[0]):
        return None
    return named.group(0)


WHY = {"folder": "scanning.vendored.why.folder", "minified": "scanning.vendored.why.minified",
       "banner": "scanning.vendored.why.banner"}


def reason(kind: str, detail: str) -> Message:
    return msg("scanning.vendored.reason", why=msg(WHY[kind], detail=detail))


def is_vendored(finding: dict) -> bool:
    reason = finding.get("excluded_reason")
    return isinstance(reason, dict) and reason.get(MARK) == "scanning.vendored.reason"


def read_head(snapshot: Path, relative: str) -> bytes:
    path = snapshot / relative
    try:
        if path.is_symlink() or not path.resolve().is_relative_to(snapshot.resolve()):
            return b""
        with path.open("rb") as handle:
            return handle.read(HEAD)
    except OSError:
        return b""


def withhold(findings: list, snapshot: Path) -> tuple[list, list]:
    """(kept, withheld): the SAST findings in third-party code move to the second list with why; nothing is lost."""
    kept, withheld, verdicts = [], [], {}
    for finding in findings:
        path = str(finding.get("path") or "")
        if finding.get("scanner") != "sast":
            kept.append(finding)
            continue
        if path not in verdicts:
            verdicts[path] = classify(path, read_head(snapshot, path))
        if (verdict := verdicts[path]) is None:
            kept.append(finding)
        else:
            withheld.append({**finding, "excluded_reason": reason(*verdict)})
    return kept, withheld
