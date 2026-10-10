# Changelog

Notable changes to Pitangus (called Tamandua up to 0.11). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are `major.minor` in the code (`pitangus/version.py`)
and `major.minor.patch` in the release tags. While Pitangus is in beta (0.x), the API and stored formats may change
between minor versions: anything that changes behaviour is called out below.

## [Unreleased]

### Added

- **OWASP guidance on every finding.** A curated, versioned mapping (`pitangus/modules/findings/references.yaml`,
  reviewed against the published indexes) links each finding to OWASP Cheat Sheet Series pages, its OWASP Top 10:2025
  category and, for code and web findings, the API Security Top 10 2023 risk and the WSTG v4.2 test that fit: by rule
  (ZAP, nuclei, testssl.sh, zizmor and container image checks), framework or file, CWE (100 CWEs, among them every one
  our rules and engines emit) and scanner. Served as `guidance: [{title, url, kind}]` on findings (computed when read,
  so old runs get it too), shown under **OWASP guidance** in the finding's detail after the tool's own references, and
  printed next to each finding's references in the technical PDF and the Markdown report. Links only; the tool's own
  guidance stays first and verbatim. A finding whose engine set no OWASP category (nuclei, testssl.sh, imported SARIF
  without tags) now gets its Top 10:2025 category from OWASP's CWE mapping when served; the technical PDF shows it next
  to the CWE.
- **Known vulnerabilities of the versions a site exposes.** After httpx, a passive web scan looks up the versions it
  read of well-known packages (Flask, Django, Werkzeug, Express, Next.js, jQuery, Bootstrap, AngularJS, Lodash… an
  explicit table, `web_versions.PRODUCTS`; at least `major.minor`) with OSV-Scanner 2.6.0 offline, on a CycloneDX SBOM
  of package URLs and the OSV databases in `data/osv-cache` (the same as dependency scans and the advisory watch);
  KEV and EPSS come from the local CVE copy (`cve_db.signals`). One finding per product and version (tool
  `httpx + OSV`, scanner `dast`, CWE-1395, confidence 5, "Flask 2.2.3 has known vulnerabilities") with every CVE and
  GHSA, the worst severity, the highest of the advisories' fixed versions and their references; a JavaScript library
  ZAP already reported at that version (10003) isn't repeated. New step `dast-versions` and a limitation saying the
  version isn't verified; when OSV-Scanner can't run, the step says why and earlier findings aren't marked fixed.
  Apache httpd, nginx, OpenSSL, PHP and other servers aren't looked up (no OSV package and no CPE ranges in the local
  CVE copy): the step lists them as not looked up.
- **ZAP's AJAX spider.** After the classic spider, the plan runs `spiderAjax` (one headless Firefox, 2 minutes, depth 5,
  100 states) from the domain's URL and again as each test user that signed in. It clicks links only (`elements: [a]`,
  no default elements, no random inputs), keeps to the context with a strict scope check and avoids logout links. The
  passive step says how many URLs it found, and ZAP's time limit grows 3 minutes per AJAX spider. Without test users
  ZAP's home stays `noexec`; only `/home/zap/.ZAP/webdriver`, a tmpfs of its own, lets geckodriver run.
- **ZAP's passive rules, explicit.** A `passiveScan-config` job opens the plan: passive scanning only inside the scope
  (`scanOnlyInScope`), every rule of the image at its default, and PII disclosure (10062), debug errors (10023),
  sensitive information in URLs (10024) and the Referer (10025), suspicious comments (10027), vulnerable JS libraries
  (10003) and the version-leaking header and banner rules set at Medium. The image bundles `pscanrules` and `retire`,
  not `pscanrulesBeta`/`pscanrulesAlpha`; those aren't installed at scan time.
- **Scheduled scans sign in as test users.** The schedule rule (`POST /api/domains/schedule`) takes `test_users` (up to
  3 ids, each signing in on a host of the saved scope) and `use_headers` (409 without saved headers); the panel picks
  them under the schedule in a web scan's review and on the domain's page. When the scan runs, a user deleted since is
  dropped from the rule, one now outside the scope is left out of that run, and missing headers aren't sent: the scan
  runs with the rest and the run and the schedule's note say what was left out. Stored in the existing
  `schedule_rule` JSON (no migration); rules saved before read as no users and no headers.
- **Outgoing address for sites that filter by IP.** New setting `PITANGUS_EGRESS_IPS` (IP addresses or CIDR ranges,
  comma-separated, validated at start-up); `GET /api/domains` answers it as `egress`. Without it, an administrator can
  detect the server's address once (`POST /api/domains/egress`: one HTTPS GET to `api.ipify.org`, no redirects, kept
  in the settings documents). The review of a web scan shows "If your site filters by IP, allow …" with a copy button,
  replacing the firewall/WAF fold.
- **Domains list and page.** "Add domain" sits next to the page title, a search filters the list ("Showing N of M"),
  and the whole row opens the domain. The domain's Overview ends with a **Disconnect domain** section that says
  exactly what is deleted; the action left the page's "…" menu.
- **Passive web scans run four more tools, still without attacking.** With their images pulled (`make engines` with
  `PITANGUS_DAST_ENABLED=1`; each pinned by version and multi-arch digest), a `dast_scan` runs katana 1.7.0
  (`projectdiscovery/katana`, a crawl with a headless browser whose in-scope URLs, without query strings, are stored
  with the run as `web_inventory` and handed to ZAP through an `import` job and to nuclei), ZAP, nuclei 3.11.1
  (`projectdiscovery/nuclei`) with nuclei-templates 10.4.9 downloaded once by the worker (SHA-256 pinned) and filtered
  to detection-only templates (GET/HEAD, no body, no fuzzing, no out-of-band calls, no attack markers or tags; CVE
  templates read fixed paths only), testssl.sh 3.2 (`ghcr.io/testssl/testssl.sh`, the project's own image; protocols,
  ciphers, certificate, HSTS, no vulnerability checks) on the first 3 hosts, and httpx 1.12.0
  (`projectdiscovery/httpx`), whose technologies land in the run's `summary.technologies` and on the domain's page
  (`last_scan.technologies` in `GET /api/domains`). Every tool runs in the hardened container with the scan's pinned
  addresses only, a dead resolver for ProjectDiscovery's own DNS client, at most 10 requests a second and a hard
  timeout; katana and nuclei get the saved headers on standard input when the scan asked for them. Each tool has a
  step (`dast-katana`, `dast-nuclei`, `dast-testssl`, `dast-httpx`: completed, partial or skipped with the reason); a
  tool that fails leaves its step partial, the scan goes on and its earlier findings aren't marked fixed. When ZAP,
  nuclei or testssl.sh report the same problem at the same URL (an explicit table: security headers, cookie flags,
  HSTS, deprecated TLS and weak ciphers, certificate problems, exposed `.git` or `.env`) it's one finding with
  `also_detected_by`, `related_rules` and each tool's evidence in `web.also`. The panel names every tool on the run and
  its findings, shows what the other tools saw on a web finding, a **Skipped** step state, and the technologies on the
  domain's page.

- **Related hosts and a scope saved per domain.** Adding a domain (with `PITANGUS_DAST_ENABLED=1`) queues a discovery
  job: subfinder 2.16.0 (`projectdiscovery/subfinder`, pinned by digest, pulled by `make engines` with web scans on)
  asks passive sources for names under the domain, with no API keys and a hard timeout, in the usual hardened container.
  Names that aren't a valid host under the domain, or that resolve to any private, loopback, link-local or metadata
  address, are dropped. Hosts land in the new `domain_hosts` table (migration `0013_domain_scope`) out of scope, with
  first and last sighting. `GET /api/domains/scope` lists them with the last round's state; `POST /api/domains/scope`
  (`set`, `add`, `remove`, `exclude_all`) saves the scope, only for DNS-verified domains (409 otherwise); `POST
  /api/domains/discover` searches again (202). `POST /api/domains/scans` takes `use_scope`: the worker reads the saved
  scope when the scan starts, pins and crawls its hosts and keeps the excluded ones out of ZAP's context
  (`excludePaths`). Weekly scans use the saved scope too. The panel shows it in the new scan (**Include subdomains**)
  and in a **Scope** tab on the domain's page, replacing the per-scan host list.
- **Domains: more ways to prove control, and a probe.** Besides the DNS TXT record, `POST /api/domains/verify` takes
  `method: "file"` (`https://<host>/.well-known/pitangus-verify.txt` with the token) or `"meta"` (`<meta
  name="pitangus-verify" content="<token>">` in the homepage), fetched once from the host's checked public address
  (certificate validated, no redirects, 10 s and 64 KB at most). The method that proved it is stored and the daily
  re-check asks for the same one. Only a DNS proof covers subdomains. `POST /api/domains/probe` checks a URL before
  registering it (`host`, `reachable`, `https`, `status`, `public`); `/api/domains/check` stays as an alias.
- **Passive web scans: scope, headers, API mode and a weekly schedule.** `POST /api/domains/scans` takes `mode`
  (`web` or `api`), `hosts` (up to 20 subdomains or `*.` wildcards of a DNS-verified domain; each listed host must
  resolve to public addresses and is pinned, wildcards only widen ZAP's context), `use_headers` and, in API mode, an
  OpenAPI 3.x / Swagger 2.0 definition (`spec`, JSON or YAML up to 5 MB in base64, or `spec_url` on a host of the
  scope); it answers `202` with `run_id`. API mode imports only the definition's GET and HEAD operations (others are
  dropped before ZAP sees it), aimed at the domain, refuses remote `$ref` and YAML aliases, and keeps only the
  definition's SHA-256 and operation count (`dast_scan` with `variant: "api"`). Request headers per domain (`POST
  /api/domains/headers`, at most 10, encrypted in the vault, never answered back) are added by ZAP's replacer to the
  scope's requests only; the plan now reaches ZAP on its standard input into a memory-only folder, and the values are
  scrubbed from what ZAP returns. ZAP's container gets `--dns 127.0.0.1`: only pinned names resolve. A weekly passive
  scan per domain (`POST /api/domains/schedule`) is queued by a new periodic task (`domain_scans`, hourly, only with
  `PITANGUS_DAST_ENABLED`); a lapsed proof or a running web scan is recorded as the reason it was skipped, and
  `GET /api/domains` shows the next and last scheduled scan and the latest web scan. A web scan only marks fixed what
  a scan like it had seen (same mode, definition and use of headers) on a host it looked at. Migration `0011` adds
  the proof method and the schedule columns. New runtime dependency: PyYAML (MIT).
- **Strix SARIF.** `import-sarif` places Strix's endpoint findings (anchored to `SECURITY.md` in its SARIF) at the
  endpoint's URL with its method, keeps Strix's severity label, and skips its coverage results; code findings stay at
  their file. Help texts of web findings are redacted like their messages.

- **Passive web scan of a verified domain**, launched from the panel (New analysis → Web application) or with
  `POST /api/domains/scans` (administrators). ZAP 2.17, pinned by digest, crawls the domain for up to 2 minutes and
  runs its passive rules over every response; no active scan, no AJAX spider, no form submissions. Off unless the
  server sets `PITANGUS_DAST_ENABLED=1`. Before it starts, the worker checks again that the domain's proof is current
  and its TXT record still published (gone: the proof is withdrawn), and that the name resolves to public addresses
  only; ZAP gets that address pinned and a context with the host only. One web scan at a time, 15 minutes at most;
  ZAP runs as its image's user with no capabilities, a read-only root, 3 GB and 2 CPUs and an explicit heap. Its SARIF
  goes through the `import-sarif` parser, so a native scan and an import of the same site share fingerprints. A new
  run type, `dast_scan`, is a full scan of the domain: what it no longer reports is marked fixed. It needs the Docker
  runner (the worker image without a socket doesn't carry ZAP and says so), and `make engines` pulls ZAP's image
  (about 1.2 GB) only with the variable on. The residual risk of an engine with network is in
  [security.md](docs/security.md).

- **Bring your own DAST.** `import-sarif` (CLI, panel, `POST /api/ci/sarif` and the Action) accepts the SARIF of web
  scanners (ZAP's `sarif-json` report, Nuclei's `-se`) against a **verified domain** (`--asset domain:<host>`, also
  the host or the domain's id). Their findings get `scanner: dast` (the `Web` source in Findings), the URL without its
  query string or fragment as the location, a fingerprint of rule, URL and parameter name (never the evidence, so the
  same alert doesn't come back as new on every run), and only the method, parameter and a bounded evidence are kept:
  never the request or response the tool attached, which carry cookies and authorization headers. A later full import
  of the same tool marks fixed what it no longer reports, like any import. Importing against a domain nobody vouches
  for (not verified, or the proof ran out) is refused with `409`. Recipes for GitHub Actions with the ZAP Automation
  Framework plan and with Nuclei in [integrations.md](docs/integrations.md#bring-your-own-dast).

- **Domains** (Scanning → Domains). The domain registry that was hidden is now in the panel: an administrator adds an
  HTTPS domain, publishes the TXT record shown (with copy buttons) and verifies it; everyone sees the domains and
  their status, with "Findings" once something was imported against one. The proof counts for 90 days and a daily
  periodic task looks the record up again (present: extended; gone: withdrawn; DNS not answering: nothing changes).
  Removing a domain deletes what was imported against it, and the panel says so before asking. API, administrators
  only for the writes: `GET /api/domains`, `POST /api/domains`, `POST /api/domains/verify`, `POST /api/domains/check`
  (one HTTPS `HEAD` to a public address, no redirects) and `POST /api/domains/remove`; verifying and probing count
  against the progressive lock-out. Storage moved from the `domains` document to the `domain_registry` table
  (Alembic `0010`, data migration `domains_to_table`). Native dynamic testing stays in development.
- **Web findings say what the scanner knows.** An imported or native web finding keeps its rule's description,
  solution, references (http(s) only, at most 8) and WASC ids, and the attack the scanner sent, all bounded and redacted
  (`web.description`, `web.solution`, `web.references`, `web.wasc`, `web.attack`). The panel shows them in order (what it
  is, where, evidence, how to fix it, how to check it, references), attributed to the scanner and as published. Pitangus
  only adds what it derives: the fragment of the evidence the result is about (`fix.web.highlight`, e.g. the
  `'unsafe-inline'` of the `style-src` the message names) and, for rules about response headers, a quoted `curl -sI`
  check (`fix.web.check`). Jira issues and the Markdown and technical reports carry the same.
- **Scheduled domain scans follow a rule.** The weekly switch became a schedule: daily, on one or more weekdays or on
  one or more days of the month (1–28), at a time of day in an IANA time zone (the browser's by default, checked by
  the server), at most once a day per domain. `POST /api/domains/schedule` takes `schedule: {frequency, weekdays,
  month_days, time, timezone}` or `null`; `GET /api/domains` answers it with `next_run_at` (UTC, computed by the
  server; the panel previews the same moment). The review of a web scan has a "Schedule" switch with "Also run now"
  (on by default; off, it only saves the schedule), and the domain's page says the schedule in plain words with
  Change and Turn off. A domain already scanned that local day moves on to its next run instead of a second scan.
  The periodic task looks for due scans every 5 minutes instead of every hour. **Changed:** `DomainRow.schedule` is
  now an object (with `next_run_at`, `last_run_at`, `last_run_id`, `note`) and the flat `schedule_next_at`,
  `schedule_last_at`, `schedule_last_run` and `schedule_note` fields are gone. Alembic `0012_scan_schedule` adds
  `schedule_rule`; the data migration `scan_schedule_rules` keeps existing weekly schedules on the weekday and time of
  their next run, in UTC.

### Fixed

- **A scheduled scan is queued exactly once.** Locking the due domain, queuing its scan and moving its schedule on
  are now one transaction: a crash in between, or two rounds at once, can neither queue a slot twice nor lose it.

- **Web findings read as web findings.** Their location is the URL, never `URL:1`; the fix and re-verify texts say to
  deploy and scan the domain again instead of pushing to a branch; and their priority no longer asks to "confirm
  reachability" (a code concept) but says whether it comes from a response header, a cookie, an attack the scanner sent
  or is informational. Findings stored before get the new texts when read.

- **The same web alert on a site's root is one finding.** ZAP reports `https://host` and `https://host/` as different
  results; Pitangus already took both as the root, but counted them as two findings. A repeated alert on the same URL
  and parameter is now one (in code, the same rule twice on a line still counts twice). A later import of the same tool
  marks the leftover copy fixed.
- **Verifying a domain asks its own nameservers.** It went through the local resolver, which keeps a "no such name" for
  the zone's negative TTL (30 minutes on Cloudflare): a domain verified a little too early stayed "TXT not found" long
  after the record was published. It now asks the zone's authoritative nameservers first, and the local resolver only
  if they can't be reached.
- **The ZAP recipe in "Bring your own DAST" works as written.** Run with `--user "$(id -u)"`, ZAP couldn't create its
  home folder and stopped at once; it now runs as its own user over a writable folder, the image is pinned
  (2.17.0 by digest), and the import points at `zap.json`, the file the `sarif-json` template actually writes. Tried
  end to end against a real domain.
- **An organization batch now uses every worker.** The leader fed the batch one repository at a time, and only while
  the queue was empty, so with several workers a batch advanced at the pace of one. It now keeps as many of its
  repositories queued as there are workers with nothing waiting, also while the leader itself is scanning; scans
  launched by hand keep precedence.
- **A batch is "finished" when its last scan is.** With several workers, the batch was marked done, and its Slack or
  Teams notice sent, as soon as its last repository was queued, while the last scans were still running, so the notice
  could report fewer scans and findings than there were. It now waits for every scan of the batch to end.

### Security

- **The panel drops the `shadcn` package (292 fewer packages in its lockfile, braces among them).** Only its stylesheet
  was used; it is now copied into the panel, so the CLI and its tree (fast-glob, ts-morph, braces with
  GHSA-vfj7-8cjw-p6xm, which has no fixed release) are no longer installed to build it. The built panel doesn't change.
- **Checkov's `requirements.txt` no longer lists asteval 1.0.6.** The image already installed 1.0.10 over it
  (`overrides.txt`); the vulnerable pin stayed in the lock and scanners reported it. An overridden package now appears
  only in `overrides.txt`, and a test checks it.

## [0.12.2] - 2026-10-09

### Added

- **Findings of several assets at once.** Findings has the same scope picker as Compliance: one asset (as before, with
  its runs and settings), an organization, a chosen set of repositories and images, or everything, with the images
  built from the chosen repositories. The cards add up the whole scope, a "By asset" block shows each asset's pending
  and critical findings and opens it on its own, and the table gains an Asset column. Triage (one finding or a
  selection across assets in one request, applied asset by asset with any failure named), Jira issues and the
  consolidated audit evidence work on the scope. The scope stays in the address, so a reload or a shared link opens the
  same view. New route `GET /api/findings/scope`; a very large scope lists the 10,000 most urgent findings of the tab
  and says so. `POST /api/findings/triage` also takes `selections` (`[{run_id, fingerprints}]`, one per asset, up to 500
  findings in all) instead of `run_id` and `fingerprints`, and answers each one's outcome in `results`; it fails as a
  whole only when none landed. The cards are counted by the server in every view: `summary.kpis` in an asset's state,
  a run (`GET /api/runs/{id}`) and a scope, with what was fixed (by a scan or by hand) never counted as pending.

- **Create the GitHub App from the panel** (Integrations → GitHub → Create on GitHub). GitHub's form opens with
  everything filled in (name, the four permissions, no webhook or OAuth, the return to this panel); you confirm there
  and come back with the App connected, instead of copying values and uploading the `.pem`. The App is still yours and
  its private key goes from GitHub straight to the server, encrypted; the link is single-use and lasts an hour. The
  manual guide stays, folded underneath. API: `POST /api/integrations/github/manifest` and the return at
  `/github/app-created`.

- **Add an image without scanning it** (Scanning → Images → Add image). Type its reference and, if you're an
  administrator, the repository it's built from; it shows on the list as "Not scanned yet" and is scanned when you
  choose ("Scan it now" does it right away). Adding one that is already there says so; if it isn't scanned yet, it now
  scans the reference you just typed. Its first scan lands on the same asset, keeping the link; until then it has no
  findings and stays out of the evidence scopes. At most 5,000 images wait unscanned at a time (scanned ones don't
  count). An administrator can remove an image that was never scanned. API: `POST /api/images` and `POST /api/images/remove`;
  `GET /api/images` items carry `analyzed`.

- **Connecting an installation takes one click.** Coming back from installing the App on GitHub (its Setup URL) no
  longer stops at a page that says to go back and look for it: it opens Integrations, which offers that account with
  **Connect** (only to administrators; the server still checks it belongs to the App). `/oauth/callback` no longer calls
  GitHub: it only hands the installation to the panel.

### Fixed

- **Slack and Teams notices read better.** No more emoji: each finding shows its severity in words and what it is,
  with where it is on the line below ("Dependency `next 14.2.3`" or the file and line), under "Most urgent". In Slack
  the edge of the message takes the colour of the most severe finding. Dependency advisories drop the repeated package
  prefix ("flatted 3.3.1: flatted: Flatted: Prototype pollution…" becomes "Prototype pollution…"); the signed webhook
  gets the same cleaner `title` and a new `dependency` flag per item.
- **Slack messages no longer show a warning next to "Open in Pitangus".** It was a button, and Slack treats every
  button as interactive: with an incoming webhook (no interactivity URL) it marked it with a warning. It is now a plain
  link that opens the same page.

### Security

- **The images no longer carry pip.** It installs the pinned dependencies and is then removed, from the app image and
  from Checkov's environment in the worker with the engines inside: nothing runs it, and the 25.0.1 that Python 3.12
  bundles has six known vulnerabilities (pip 26 would trade them for its vendored urllib3, msgpack and setuptools).
- **Checkov's asteval goes to 1.0.10** in the worker with the engines inside. Checkov 3.3.19 (and every later release
  so far) pins 1.0.6, which it uses to evaluate the Terraform expressions of the scanned repository; 1.0.9 fixed two
  sandbox escapes (GHSA-89v8-rhwq-hf77, GHSA-9w56-46f6-3qhx). It is installed by hash over the lock, from
  `docker/checkov/overrides.txt`; Checkov's results don't change.
- **The Docker client in the image goes to 29.9.0**, built with Go 1.26.9: the 13 Go standard library vulnerabilities
  of 29.8.2 (two high: CVE-2026-78667, CVE-2026-97031) are gone. It came out on 2026-10-09, so it goes in as an
  exception to the week-old rule, checked against its SHA-256 like before.
- The Python base image moves to the current `python:3.12-slim-bookworm` digest (still Python 3.12.15). The engines stay
  where they were: they are already the newest releases at least a week old, and the Go standard library fixes their
  remaining findings need (Go 1.26.9 and 1.27.2) came out on 2026-10-08.

### Upgrading from 0.12.1

- If you installed a release (`git clone --branch v0.12.1`, as in the quickstart), `make update` alone stays on it:
  `git fetch --tags && git checkout v0.12.2 && make update`. Following `main`, `make update` is enough. The new
  "Upgrade" section of [docs/installation.md](docs/installation.md#upgrade) explains both.
- The database gets one new table (the images added without scanning), created on start: nothing to do by hand.
- Slack and Teams notices change format (no emoji); a signed webhook receiver gets a cleaner `title` and a new
  `dependency` field per item.

## [0.12.1] - 2026-10-09

### Added

- **Images page** (Scanning → Images): every analyzed image, the repository it's built from and how it was linked
  (OCI label or by hand), with a "not linked" tab for the ones that still need one. An administrator links, changes or
  removes the link there; each row opens its findings or scans the image again. Repositories show how many images are
  built from each one, and from a repository you can link another image to it.
- **One scope picker for the evidence in Compliance.** Three steps: which assets (one, an organization, several or all),
  which framework, and the downloads for that scope, with a preview of what it covers (repositories, images, how many
  with a complete scan) before downloading anything. The separate "one asset" and "portfolio" blocks are gone.
- **An image knows which repository it is built from.** Pitangus reads its OCI labels (`org.opencontainers.image.source`
  and `.revision`, set by `docker/build-push-action` and GHCR) and links it to that repository when it is analyzed too;
  an administrator can set or change the link by hand in Compliance. The reports say "built from org/repo @ commit".
- **Portfolio evidence for the scope you choose**: every analyzed asset, the repositories of one organization, or a
  chosen set of repositories and images; with a repository come the images built from it (it can be turned off). It
  applies to the portfolio SBOM, VEX and consolidated audit evidence.
- **Audit evidence for eleven more frameworks.** European Union: NIS2 (Art. 21(2) and Implementing Regulation
  2024/2690), DORA (with RTS 2024/1774) and GDPR Art. 32. United States: NIST SSDF (SP 800-218), NIST CSF 2.0,
  NIST SP 800-53 Rev. 5 and the HIPAA Security Rule. Mexico: CNBV rules for banks (CUB) and crowdfunding institutions,
  e-money institutions (IFPE) and LFPDPPP Art. 18. Each control says what the evidence covers and what stays out
  (infrastructure scanning, external pentests, dynamic testing): it supports an audit, it doesn't certify compliance.

### Changed

- **The panel's paths are English** (`#/findings`, `#/compliance`, `#/images`…) whatever its language, so a shared link
  reads the same for everyone. The Spanish paths of earlier versions (`#/hallazgos`, `#/resumen`…) still work and are
  rewritten, so links already sent in Jira issues, notifications or bookmarks don't break.
- **New look for every PDF report** (technical, audit evidence, consolidated, threat model): a cover with the system,
  date, revision and reference; «Confidential» on every page and «page N of M» in the footer; Source Serif 4 and IBM
  Plex (embedded, SIL OFL) instead of Helvetica; ruled tables and key figures without fills; severity as coloured text.
- **The technical report reads like one a person would write**: a short executive summary, each action with an ID
  (PIT-001…) used throughout the report, and one sheet per critical or high code finding with what happens, how to
  fix it (before and after) and how to verify it. Method, coverage, sources and the closing notice are together in
  "About this report".

### Fixed

- `make openapi` works again: `openapi-typescript` runs from `web/tools/openapi` with the TypeScript 5 its compiler API
  needs (the panel moved to TypeScript 7).

- **A Jira rule's backfill no longer skips findings whose issues were deleted in Jira.** Like a manual export, it now
  asks Jira which linked issues still exist and creates again the ones that are gone; before, a cleanup in Jira left
  those findings out of every backfill. The backfill dialog's count asks Jira too, so it no longer offers "0 issues"
  when the linked ones were deleted.

- **Threat diagram arrows no longer run behind other components.** Each flow picks the sides and the curve that go
  around what is in between, and flows leaving the same side of a component spread along it instead of starting at one
  point; the editor, the SVG and the PDF draw them the same way. In the bundled examples, flows running over another
  component went from 108 of 156 to 12 (one flow per example still needs a route with bends). Wide curves and their
  labels now stay inside the exported drawing.

- **A threat marked mitigated or not applicable while the scans still find it** goes back to "with evidence", with a
  note saying who decided and asking to review the decision. The decision is kept and applies again once the
  evidence is gone.
- **Threat model reports for MITRE ATT&CK and attack trees** now open with their own figures (techniques by status;
  goals still reachable or cut), with the techniques or the trees in the body instead of an appendix after "0
  threats". An attack tree with no steps yet is no longer counted as cut.
- **LINDDUN is no longer mixed with STRIDE**: its "D" and "I" are counted apart, and the OWASP Threat Dragon export
  names its threats (Detecting, Identifying…) as LINDDUN instead of Denial of service or Information disclosure.
- "What to address first" no longer repeats a component already listed with evidence, and shows the high patterns
  when there are no critical ones. A flow can't take a component's ID. Smaller fixes: appendix letters in order,
  decision dates, plurals in Spanish, ATT&CK names in the report's language, linked repositories counted apart from
  pending ones, and the closing note no longer left alone on the last page.

- **The audit report's period is now real.** On a repository's state it keeps the findings detected by the end of the
  period and not fixed before it starts, and says so; a single scan outside the period is refused instead of being
  presented as evidence for it. The consolidated report filters the same way.
- **Figures that add up.** Findings out of scope no longer count as in scope; the critical and high figures are the
  open ones in both reports; a single scan no longer shows "0 fixed" (it can't know).
- **Evidence whole.** The revision is the git commit (the snapshot's SHA-256 goes apart, whole), the reference is no
  longer cut, long paths keep their file name and line, and the closing note no longer claims a review nobody signed.
- Smaller fixes: "page X of Y", code shown as code instead of backticks, dependency advisories located at their
  manifest, EPSS with the locale's decimal separator, Spanish agreeing with «hallazgos», and the Markdown export with
  its states translated and its headings nested properly.

### Security

- **The panel and the docs site build with pnpm instead of npm**, pinned by hash through corepack, with supply-chain
  settings in their `pnpm-workspace.yaml`. A release has to be a week old before it is installed, and a recent version
  that loses the provenance its predecessors had is refused. Transitive dependencies can't come from git or tarballs,
  and dependencies' install scripts never run (the way the 2025 npm worms spread). The lockfiles keep npm's versions,
  except that the docs site goes back to astro 7.3.5 and Starlight 0.42.5 (the newer ones came out that same day). A
  security fix younger than a week goes in as an exception for that exact version. `openapi-typescript` is now a pinned
  dev dependency instead of an `npx` download.
- **Vite 8.3.3 in the panel's development server** (GHSA-9jrq-w75r-8gcw, GHSA-vfpm-58rq-9qcg, GHSA-rq7h-c2jc-7f22).
  The built panel doesn't contain Vite.

### Upgrading from 0.12.0

- `make update` (or `git pull` and `make up`): the published `0.12` images move to 0.12.1. No migration to run by hand.
- The panel's addresses are now English; bookmarks and links with the Spanish ones keep working.

## [0.12.0] - 2026-10-08

### Changed

- **Tamandua is now Pitangus**: the great kiskadee (*Pitangus sulphuratus*, the bird Colombians call bichofué), made in
  Colombia by Arodium. New logo and palette in the panel and the PDF reports, and a new tagline: "Spot it. Fix it.
  Prove it." The repository moved to `Pitangus-Dev/pitangus`.
- **Every technical name follows, with no aliases**: the package and CLI (`pitangus`, `python -m pitangus`), the
  `PITANGUS_*` variables, the images (`ghcr.io/pitangus-dev/pitangus`, `-worker`, `-opengrep`), the GitHub Action
  (`Pitangus-Dev/pitangus`), the compose project, containers, database, user and volume (`pitangus`, `pitangus-pg`),
  the `X-Pitangus-*` headers, the session cookie (everyone signs in again), the `pitangus_*` metrics, the commit
  status context (`pitangus`: update branch protection rules that required `tamandua`), the DNS record for new domain
  verifications (`_pitangus.<domain>`) and the ids of custom secret rules (`pitangus-<id>`).
- **Kept working**: Jira field mappings saved with the old variable source (migrated on start), threat models exported
  as `tamandua-threat-model`, and domains already verified with their `_tamandua` record. On pull requests reviewed
  before the upgrade, the next review writes a new comment instead of updating the old one.

### Upgrading from Tamandua 0.11

1. On 0.11, take a backup: `make backup`.
2. Check out `v0.12.0` from `https://github.com/Pitangus-Dev/pitangus` and rename the variables in `.env`:
   `sed -i.bak -e 's/TAMANDUA_/PITANGUS_/g' -e 's#tamandua-appsec/tamandua#pitangus-dev/pitangus#g' .env`.
3. `make up` starts the new `pitangus` project with an empty database.
4. `make restore FROM=backups/<date> CONFIRM=restore` brings your data back.
5. Once everything works, remove the old containers with `docker compose -p tamandua down`. The old `tamandua-pg`
   volume stays until you delete it yourself.

## [0.11.0] - 2026-10-06

First release from this repository. Tamandua is in beta: the API and stored formats may change between minor
versions, and anything that changes behaviour is called out here.

### Included

- **Find**: Opengrep with Tamandua's rules (JS/TS, Python, Java, Go, PHP, Ruby, C#), Gitleaks, Trivy and OSV-Scanner
  for dependencies, Checkov and zizmor for infrastructure as code and GitHub Actions, Trivy and Grype for images, with
  no duplicates across engines. The code under analysis is never executed.
- **Prioritize and fix**: CISA KEV and EPSS on every advisory, the version that closes all of a package's advisories,
  the fix command for each package manager, **Verify again**, and automatic remediation once a finding is gone.
- **Pull requests and CI**: only what a PR introduces counts, with a comment and a status check; the GitHub Action
  and `tamandua scan` for any other CI (exit codes `0` pass, `1` findings, `2` usage error, `3` incomplete).
- **Evidence**: technical and audit PDF reports (SOC 2, ISO/IEC 27001), SARIF, JSON and Markdown, SBOM and VEX, and
  threat modeling tied to the findings. English and Spanish.
- **Self-hosting**: `make up` on a laptop; `make setup DOMAIN=…` on a server, with HTTPS (Caddy), the engines inside
  the worker image and **no Docker socket** (opt in with `SOCKET=1`); one compose file for Docker panels; Render.
- **Supply chain**: images for amd64 and arm64 signed with cosign (keyless), with SBOM and SLSA provenance; the GitHub
  Action and `make up` run exactly the digest whose signature they checked; Python dependencies locked with hashes;
  third-party images and actions pinned by digest; no release with a fixable critical vulnerability.
- **Operations**: backups encrypted with age (master key included) or, unencrypted, without the master key; restores
  that check every archive first; health checks, Prometheus metrics and memory and process ceilings.

### Upgrading from 0.10

- On a server set up with 0.10, the worker keeps the Docker socket. `make setup DOMAIN=… SOCKET=0` and `make up`
  move it to the engines inside the worker ([deploy-vps.md](docs/deploy-vps.md#engines-and-the-docker-socket)).
