English · [Español](es/actualizar.md)

# Upgrade Pitangus

Upgrading means moving the code to a new version, pulling (or rebuilding) its images and restarting. Your data stays:
the database, `data/` and `config/` are kept, and anything whose format changed is converted on start-up. This page
covers the general procedure and what changes when you move to 0.14. Every release also lists its changes in
[CHANGELOG.md](../CHANGELOG.md) and on the [Releases page](https://github.com/Pitangus-Dev/pitangus/releases).

## Before you upgrade

1. **Find out which version you run.** In the repository folder:

   ```bash
   git describe --tags
   ```

   ```text
   v0.12.2
   ```

   The panel's header shows it too, next to **New scan** (**Self-hosted · v0.12.2**), and `/api/health` answers it.
2. **Read the release notes** for every version between yours and the new one, especially their **Breaking**
   sections.
3. **Check that nothing is running.** Open **Scans** (`#/analyses`): no run should be **Queued** or **Scanning…**.
   A restart marks any running scan as failed, and the backup refuses to run while scans are in progress.
4. **Keep a copy of the master key** (`config/master.key`, or your `PITANGUS_MASTER_KEY`) somewhere safe, apart from
   the backups. Without it, the stored secrets can't be decrypted.

## Upgrade step by step

### If you installed a release

If you cloned a tag (`git clone --branch v0.14.x`, as in the [quickstart](quickstart.md)), the repository stays on that
version on purpose. Check out the new one first, then update:

```bash
git fetch --tags
git checkout v0.14.2      # the version you want
make update
```

On a fixed version, `make update` says so and doesn't pull:

```text
On v0.14.2 (a fixed version): not pulling. Check out the version you want first.
```

That's expected right after `git checkout`: the code is already at the new version.

### If you follow main

If you cloned without `--branch`, `make update` pulls the latest code by itself:

```bash
make update
```

### What `make update` does

1. Pulls the code (only when you follow a branch).
2. Takes a backup with `make backup`, into `backups/<date>/`:

   ```text
   Backup in backups/20261010-091500/
     Restore with: make restore FROM=backups/20261010-091500 CONFIRM=restore
   ```

3. Pulls the published images (or rebuilds them if you build from the code) and restarts with `make up`, which waits
   for the panel, pulls any missing engine image (`make engines`) and prints the URL.
4. On start-up, database migrations and data conversions run once, after saving a copy of what they touch in
   `data/backups/`. There's nothing to do by hand.

When it's done, open the panel and check the version in the header. Run `make doctor` and `make status` if anything
looks off.

> [!CAUTION]
> Don't go back to an older version over a database a newer version has migrated. To roll back, restore the backup
> `make update` took: `make restore FROM=backups/<date> CONFIRM=restore`, then check out the old version and
> `make up`.

## Upgrading to 0.14

0.14 is about trusting the results: a finding is fixed only with proof, the same problem keeps one identity from scan
to scan, and an engine that is off or didn't run never counts as a fix. `make update` is all most installations need,
but read this section before the first scan after upgrading: it doesn't behave like the scans before it.

### Identity and coverage are on by default

In 0.14, `PITANGUS_COVERAGE_MODE` defaults to `on` and `PITANGUS_IDENTITY_MODE` to `v2`. A finding is marked fixed only
when the engine that owns it proved, in a scan that worked, that it looked where the finding was; and identical problems
are one finding, a family with a count of its copies. To keep 0.13's behaviour while you check your repositories, set
both to `shadow` in `.env` and restart: each scan then records what the new rules would change without applying it, and
`pitangus identity-gate` tells you when switching changes nothing on your repositories (see
[Findings](findings.md#one-identity-per-problem)).

### What to expect on the first scan

The first scan with `PITANGUS_IDENTITY_MODE=v2` moves each stored finding, with its triage and its Jira issue, to its
family by its former fingerprints. The change of identity by itself opens nothing and fixes nothing:

- **Families with counts.** Where 0.13 listed the same problem several times (a line pasted twice, the same secret in
  two files, one rule on many pages of a template), you now see one finding with its count and where each copy is.
  Totals go down; no problem went away.
- **Triage is carried over conservatively.** When every copy of a family had the same decision, the family keeps it,
  with its expiry date and its ticket. When the decisions differ, or a copy had none, the family goes back to pending
  with the history of every copy: decide once for all of them.
- **Mass fixes are held.** A scan that would fix at least 30% of an asset's open findings, and at least 10 of them,
  fixes none: it holds those fixes and says so on the asset's page. Only a second scan that covers the same findings
  and again finds them gone releases them; an administrator can apply them at once with **Mark as fixed**. Openings are
  never held. Change the thresholds with `PITANGUS_FIX_HOLD_PERCENT` and `PITANGUS_FIX_HOLD_MINIMUM`.
- **What a scan couldn't check stays open.** A finding in a file an engine timed out on, a manifest that couldn't be
  resolved or an engine that is off is marked **Unverified since** that scan, outside deadlines and indicators, until
  a scan that looks again proves it gone. A dependency finding belongs to the project folder of the file it came from,
  whatever its package manager: a folder the engine listed no package from, or a file it no longer listed packages
  from while its folder is still there, is not examined, so deleting or emptying any lockfile never fixes what was found
  in it. Every engine that saw a finding must look again. Commit the lockfile to have it examined.
- **Changing the configuration fixes nothing.** Turning a rule or an engine off, changing an allowlist or updating the
  rule set leaves the findings it affects as not checked (configuration), never fixed, and sends nothing to Jira or
  the notifications.

### Betterleaks replaces Gitleaks

Secrets are now found by Betterleaks 1.9.0, from Gitleaks' own maintainers. Your secret detection settings carry over:
custom rules, disabled built-in rules and allowlists keep their format, and a disabled rule Betterleaks doesn't have is
dropped. A secret's identity is the HMAC of its value, not the engine's name for it, so the switch fixes nothing.
0.13 stored secrets without their value's identity: each one moves to it, with its triage and Jira issue, on the first
scan that reads the value, once. From then on two values are never one finding. If you changed a secret's value
between your last 0.13 scan and the first 0.14 one, the new value takes the old entry's triage: review the secrets you
had accepted or marked as false positives.

- **Expect some new secret findings.** Betterleaks brings 463 built-in rules instead of Gitleaks' 222, so the first
  scan can open secrets Gitleaks didn't recognize. Placeholders and example values (`YOUR-ACCESS-TOKEN`) are left out,
  and keys that are public by design, like Supabase's anon key, aren't reported as leaked secrets.
- **The secret engines read what their own lists skipped.** Betterleaks' and Trivy's built-in skip lists are off:
  committed `node_modules/` and `vendor/` folders, lockfiles, minified files, hidden folders, tests, examples and
  Markdown are read for secrets now, and a file an engine still passes over is listed as not analyzed by that engine.
  A match allowed by a `gitleaks:allow` comment is listed under **Excluded** with its file and line, never fixed
  (`PITANGUS_SECRETS_IGNORE_INLINE_ALLOW=1` ignores those comments). The secret pass takes longer on a repository with
  committed dependency folders: about 35 seconds more for a 600 MB `node_modules/`.
- **`generic-password` is on by default, with a filter.** It skips translation, test, documentation and example
  paths; templates and references (`${…}`, `{{…}}`, `process.env`, `getenv`…); interface text, identifiers and
  placeholders; values equal to their key's name; and weak values (fewer than 8 characters, or a single kind of
  character and fewer than 16). On a control corpus it went from 29 findings to 5, all of them real.
- **`generic-credential-uri` stays off**: it flags example URLs and documentation more than secrets. Turn it on in
  **Policies → Secret detection → Rules off by default** if you want it.

### Credential files are scanned

`.env*`, `.npmrc`, `.pypirc`, `.netrc`, SSH keys (`id_*`), `credentials`, `.git-credentials`, `.dockercfg`, `.s3cfg`,
`.boto` and `.htpasswd` were left out of every scan before 0.14. Now the secret engines read them, Betterleaks and
Trivy's secret scanner and no other engine, from a separate copy deleted as soon as they finish; their values are
never stored. A committed `.env` with real keys shows up on the first scan: rotate those keys, then triage.

### Optional engines: Checkov and Grype

Checkov and Grype are off by default: Trivy and zizmor already cover infrastructure and pipelines, and Trivy covers
images' packages. Off, an engine shows as **not run (disabled)** in the plan, the scan and the report, never as clean,
and what it found before stays open, unverified: turning an engine off fixes nothing. If you rely on them, set
`PITANGUS_CHECKOV_ENABLED=1` or `PITANGUS_GRYPE_ENABLED=1` in `.env` and run `make engines`, which pulls only the
images of the engines that are on.

### Exposure check, and the experimental full web scan

- **The exposure check is always available** for a verified domain, with nothing to turn on: each host's root and
  known paths (exposed files such as `.git` or `.env`, debug and status consoles, TLS, response headers) with httpx, testssl.sh and
  nuclei's detection-only templates. It's light: no crawl and no ZAP. `make engines` pulls its images, and a domain's
  scan button opens it.
- **The full web scan is experimental** and off unless `PITANGUS_DAST_ENABLED=1`: ZAP, katana and subfinder crawl the
  site. If you used it in 0.13, keep the variable in `.env`. Turning it off fixes nothing it found: those findings
  stay open until a scan of the same kind proves them gone.

### Database migrations

Two Alembic migrations and these data migrations run on their own at start-up, in this order (`make update` takes a
backup first):

| Migration | What it does |
| --- | --- |
| `0015_domain_session_check` | Adds a domain's session check page: with saved headers, a scan requests it before and after, and without a 2xx the scan is incomplete. |
| `0016_registry_control` | Adds what the registry keeps per asset about fixing its findings: the fixes held and what releases them, the last shadow comparison and the identity version its fingerprints follow. |
| `registry_identities` (data) | Stamps the canonical identity on stored dependency findings. Other findings get theirs on their next scan. |
| `registry_rule_baseline` (data) | Stamps stored findings with the 0.13.1 rules they were seen with, so a rule changed in 0.14 never fixes on the first scan. |
| `mask_stored_secrets`, `mask_stored_credentials` (data) | Replace the values secret engines detected wherever they were stored, and render each affected run's report and SARIF again. |
| `secret_value_identities` (data) | Marks secrets stored by 0.14 with their value's identity, so only that value's names link them from then on. |
| `registry_coverage_units` (data) | Derives each stored finding's coverage units from its path (a dependency's: its project folder). |
| `dependency_project_units` (data) | Declares the unit of each stored dependency finding (runs and the registry) as the project folder of every file it was seen in, whatever the package manager. |
| `render_stored_texts` (data) | Renders every stored text as its structure (runs, the registry, pending notifications); zizmor findings keep only their route. Identities are pinned first. |
| `render_stored_texts_lexicon` (data) | Renders every stored text again with the renderer that keeps a word only when it is a common word, never for its position (an imported SARIF's rule texts too). Identities are pinned first. |
| `web_location_keys` (data) | Renders every stored URL like any other (a web finding's location and its instances, a run's target, the pages a web scan lists, the runs' listing rows). Each web page's key and each web finding's identity are pinned first, from the URL as it was stored, so no identity changes. |

## Upgrading to 0.13

0.13 adds a full passive web scan, test users, a saved scope per domain, scheduled web scans and the new panel
identity. Most installations need nothing beyond `make update`. Read this section if you turned on web scans or use
the API.

### Engine images for web scans

If the server sets `PITANGUS_DAST_ENABLED=1`, web scans now run five more tools next to ZAP: subfinder, katana,
nuclei, httpx and testssl.sh, each pinned by version and digest. `make update` pulls them at the end (through
`make engines`), but only when the variable is on in `.env` or in the environment of the shell that runs `make`. Check
with:

```bash
make engines
```

```text
Engines: all images are ready.
```

If an image is missing, the web scan's step for that tool is marked **Skipped** with "The … image isn't on this
server: run make engines", and the rest of the scan goes on.

The nuclei templates (release 10.4.9) aren't an image: the worker downloads that release once, from GitHub
(`codeload.github.com`), the first time a web scan runs nuclei, and checks its pinned SHA-256. A worker that can't
reach GitHub skips nuclei and the run says why. See [What leaves your machine](security.md#what-leaves-your-machine).

### Database migrations

Alembic migrations `0010` to `0014` run on their own at start-up:

| Migration | What it does |
| --- | --- |
| `0010_domain_registry` | Moves domains from a settings document to their own table (data migration `domains_to_table`). |
| `0011_domain_proof_and_schedule` | Adds the proof method (DNS, file, meta) and the schedule columns. |
| `0012_scan_schedule` | Adds schedule rules; the data migration `scan_schedule_rules` keeps existing weekly schedules on the weekday and time of their next run, in UTC. |
| `0013_domain_scope` | Adds the related hosts and saved scope per domain. |
| `0014_domain_test_users` | Adds test users per domain, sealed with the master key. |

### Breaking changes in the API

If you call the API directly (scripts, dashboards), update these:

- **`DomainRow.schedule` is an object** in `GET /api/domains`: `frequency`, `weekdays`, `month_days`, `time`,
  `timezone`, `next_run_at`, `last_run_at`, `last_run_id`, `note`, `test_users` and `use_headers`, or `null` when no
  scan is scheduled. The flat fields `schedule_next_at`, `schedule_last_at`, `schedule_last_run` and `schedule_note`
  are gone.
- **`POST /api/domains/remove` answers `runs_kept`** instead of `runs_deleted`.
- **A web scan run's `web_inventory`** is now `{sources: {katana, robots, sitemap, openapi, zap}, count, urls}`, without
  `tool`.
- **testssl.sh findings get new fingerprints once.** Rule ids lose their certificate suffix and every certificate
  problem is one finding per host. The next web scan marks the old certificate findings fixed and opens the new ones;
  triage on the old ones doesn't carry over.

### Removing a domain keeps its history

Before 0.13, removing a domain deleted what had been imported or scanned against it. Now **Disconnect domain** (at the
bottom of the domain's **Overview** tab) deletes only its configuration: saved headers, test users, related hosts,
saved scope and scheduled scan. Its runs, findings, triage and Jira issues stay as evidence, and link back if the same
host is added again.

### New setting: `PITANGUS_EGRESS_IPS`

If your sites filter by IP (a firewall or a WAF), set the public addresses or CIDR ranges your worker's scans leave
from, comma-separated (at most 16):

```bash
PITANGUS_EGRESS_IPS=203.0.113.10, 2001:db8::/48
```

The review step of a web scan shows them, with a copy button, to whoever must allow them. An invalid value stops the
server at start-up. Without it, an administrator can click **Detect** once in that step. See
[Configuration](configuration.md).

## Upgrade issues

| Symptom | Cause | Fix |
| --- | --- | --- |
| `make update` stops with "N scans are running" | The backup refuses to run while scans are queued or running. | Wait for them to finish in **Scans** and run `make update` again. `FORCE=1 make update` marks them failed. |
| `make update` says "a fixed version: not pulling" and nothing changes | You installed a release and didn't check out the new one. | `git fetch --tags && git checkout v<new> && make update`. |
| An exposure check skips nuclei, testssl.sh or httpx | Their images weren't pulled: the pull failed. | Run `make engines`. |
| The full web scan skips ZAP, katana or subfinder, or isn't offered | `PITANGUS_DAST_ENABLED` isn't in `.env` (it's experimental and off by default), or the pull failed. | Add `PITANGUS_DAST_ENABLED=1` to `.env` and run `make engines`. |
| Checkov's or Grype's step says **not run (disabled)** | They're optional and off by default since 0.14. | Set `PITANGUS_CHECKOV_ENABLED=1` or `PITANGUS_GRYPE_ENABLED=1` in `.env` and run `make engines`. |
| New secret findings after the first scan | Betterleaks has more rules than Gitleaks, `generic-password` is on, and credential files, committed dependency folders and hidden files are read since 0.14. | Expected: rotate the real ones and triage the rest. |
| Fewer findings than before, some with a count | Identical problems are one family with a count. | Expected; the count and the list of copies are on the finding. |
| A scan says it held fixes | It would have fixed too much at once (the fix hold). | Scan again: a second covered scan releases them. An administrator can **Mark as fixed**. |
| The nuclei step says the templates couldn't be downloaded | The worker can't reach `codeload.github.com`, or a proxy changed the archive. | Allow that host for the worker and scan again; the download happens once. |
| The server doesn't start after setting `PITANGUS_EGRESS_IPS` | The value isn't a list of IP addresses or CIDR ranges. | Fix the value in `.env` (comma-separated, at most 16) and run `docker compose up -d`. |
| A script reading `schedule_next_at` or `runs_deleted` breaks | Those API fields changed in 0.13. | Read `schedule.next_run_at` and `runs_kept`. |
| Old testssl.sh certificate findings show as fixed and new ones as open | Their fingerprints changed once in 0.13. | Expected after the first web scan; triage the new findings. |
| The panel looks unchanged after the upgrade | The browser kept the old panel. | Reload the page; open tabs show **Reload** when the server was updated. |

More in [Troubleshooting](troubleshooting.md).

## Next steps

- [CHANGELOG.md](../CHANGELOG.md): every change in every release.
- [Installation](installation.md#backups): backups and restore in detail.
- [Findings](findings.md#proof-before-fixing): proof before fixing, the fix hold and identity in detail.
- [Scan a website or API](scanning-web.md): the exposure check and the full scan.
