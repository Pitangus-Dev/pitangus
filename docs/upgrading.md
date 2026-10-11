English · [Español](es/actualizar.md)

# Upgrade Pitangus

Upgrading means moving the code to a new version, pulling (or rebuilding) its images and restarting. Your data stays:
the database, `data/` and `config/` are kept, and anything whose format changed is converted on start-up. This page
covers the general procedure and what changes when you move to 0.13. Every release also lists its changes in
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

If you cloned a tag (`git clone --branch v0.13.x`, as in the [quickstart](quickstart.md)), the repository stays on that
version on purpose. Check out the new one first, then update:

```bash
git fetch --tags
git checkout v0.13.0      # the version you want
make update
```

On a fixed version, `make update` says so and doesn't pull:

```text
On v0.13.0 (a fixed version): not pulling. Check out the version you want first.
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
| Web scans skip katana, nuclei, testssl.sh, httpx or subfinder after upgrading | Their images weren't pulled: `PITANGUS_DAST_ENABLED` isn't in `.env`, or the pull failed. | Add `PITANGUS_DAST_ENABLED=1` to `.env` and run `make engines`. |
| The nuclei step says the templates couldn't be downloaded | The worker can't reach `codeload.github.com`, or a proxy changed the archive. | Allow that host for the worker and scan again; the download happens once. |
| The server doesn't start after setting `PITANGUS_EGRESS_IPS` | The value isn't a list of IP addresses or CIDR ranges. | Fix the value in `.env` (comma-separated, at most 16) and run `docker compose up -d`. |
| A script reading `schedule_next_at` or `runs_deleted` breaks | Those API fields changed in 0.13. | Read `schedule.next_run_at` and `runs_kept`. |
| Old testssl.sh certificate findings show as fixed and new ones as open | Their fingerprints changed once in 0.13. | Expected after the first web scan; triage the new findings. |
| The panel looks unchanged after the upgrade | The browser kept the old panel. | Reload the page; open tabs show **Reload** when the server was updated. |

More in [Troubleshooting](troubleshooting.md).

## Next steps

- [CHANGELOG.md](../CHANGELOG.md): every change in every release.
- [Installation](installation.md#backups): backups and restore in detail.
- [Scan a website or API](scanning-web.md): the web scan that 0.13 completes.
