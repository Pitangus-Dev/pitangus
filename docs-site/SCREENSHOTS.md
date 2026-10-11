# Screenshots for the documentation site

The pages mark where a screenshot helps with a comment in the canonical Markdown (`docs/*.md` and `docs/es/*.md`):

```markdown
<!-- screenshot: findings | The Findings table with a web problem grouped across three URLs -->
```

`scripts/sync-content.mjs` turns it into a figure that shows `public/screenshots/<name>-light.png` in the light theme
and `public/screenshots/<name>-dark.png` in the dark one, with the comment's text as the alt text (each language
writes its own). While an image is missing, the build leaves the figure out; `pnpm run dev` shows a dashed
placeholder instead. If only one theme exists, it is used for both.

## How to take them

- The panel at **1440×900** (device scale 1 or 2; the site scales them down), signed in as an administrator, panel
  language English, with the demo data (`make demo`) plus one verified domain with a finished web scan.
- One capture per theme: switch **Appearance** to Light, then Dark, in the panel's sidebar.
- PNG, cropped to the browser viewport (no browser chrome, no OS cursor), under 400 KB each (`oxipng -o 4` or
  `pngquant --quality 80-95` keeps them small).
- Nothing private: use the demo repositories and a domain you own; no real tokens, emails or customer names.
- Name them exactly as below: `<name>-light.png` and `<name>-dark.png`.

## List

| Name | Panel route | What must be visible | Used on |
| --- | --- | --- | --- |
| `overview` | `#/overview` | The Overview with the key figures row, findings by severity, the found-versus-fixed trend and the KEV/latest CVEs panels, 30-day range. | overview, findings, quickstart |
| `findings` | `#/findings` | The Findings table of the demo asset, with one web problem grouped by rule and title ("… · 3 URLs") expanded, the "N findings in M problems" line, severity chips and the filters toolbar. | findings |
| `finding-web-detail` | `#/findings` (open a web finding) | A web finding's detail: what it is, where (URL), evidence with the highlighted fragment, how to fix it from the tool, **OWASP guidance** links, and the other tools that saw it (also detected by nuclei or testssl.sh). | findings, scanning-web |
| `new-scan` | `#/new` | The guided **New scan** flow on its first step: the vertical step rail and the three types (Code, Container image, Web app or API). | quickstart, scanning-web |
| `new-scan-review` | `#/new?type=web&domain=<id>` (go to the last step) | The web scan's **Review and launch** step: the schedule switch with "Also run now", the chosen test users and headers, and "If your site filters by IP, allow …" with the copy button. | scanning-web |
| `domain` | `#/domain?id=<id>&tab=overview` | A verified domain's Overview: verification status and method, the latest web scan, technologies found by httpx, the schedule in plain words, and the **Disconnect domain** section at the bottom (scroll so the top half is visible). | scanning-web |
| `domain-scope` | `#/domain?id=<id>&tab=scope` | The **Scope** tab with hosts found by subfinder, some marked Analyze and others Exclude, and the last discovery round's state. | scanning-web |
| `domain-test-users` | `#/domain?id=<id>&tab=users` | The **Test users** tab with two users (one with password, one with password and TOTP), their login and check pages and when each was last used. No secrets are ever shown. | scanning-web |
| `scan-progress` | `#/analyses?run=<web run id>` | A finished web scan with its steps (ZAP, katana, nuclei, testssl.sh, httpx, versions, inventory), at least one **Partial** or **Skipped** step with its reason, and the coverage note. | scanning-web, concepts |
| `coverage` | `#/coverage` | The OWASP coverage matrix of a run: categories, rules, engines that covered each one and the categories static analysis can't cover, with their reason. | findings |
| `integrations` | `#/integrations` | Integrations as sections of rows (code providers, container registries, notifications, issue tracking, AI), each with its status. | overview, integrations |
| `command-palette` | any page, press `⌘K` / `Ctrl+K` | The command palette open with a short query, showing the Actions group (New scan, Import SARIF results, Add a domain…), pages and a domain result. | overview |

Spanish pages use the same files: the panel's language in the captures is English, and each page's alt text describes
it in the reader's language.
