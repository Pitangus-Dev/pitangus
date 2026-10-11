# Pitangus documentation site

This directory contains the Astro Starlight application that turns the repository's existing English and Spanish documentation into a searchable static site.

## Run it locally

Use Node.js 22.12 or newer and pnpm through corepack (`corepack enable`; `package.json` pins the version):

```bash
cd docs-site
pnpm install --frozen-lockfile
pnpm run dev       # http://localhost:4321
pnpm run check     # source consistency and Astro type checks
pnpm run build     # production build and internal-link validation
pnpm run preview   # http://localhost:4322 after a build
```

The default local base path is `/`. To test the production URL exactly:

```bash
SITE_URL=https://docs.pitangus.dev BASE_PATH=/ pnpm run build
SITE_URL=https://docs.pitangus.dev BASE_PATH=/ pnpm run preview
```

On PowerShell:

```powershell
$env:SITE_URL = 'https://docs.pitangus.dev'
$env:BASE_PATH = '/'
pnpm run build
pnpm run preview
```

## Canonical content

Do not edit `src/content/docs/`. It is generated and ignored by Git.

- English documentation stays in `../docs/*.md`.
- Spanish documentation stays in `../docs/es/*.md`.
- Contributor guides stay in `../.github/CONTRIBUTING*.md`.
- The Starlight home pages live in `content/` because they use MDX components and site-specific frontmatter.
- `scripts/sync-content.mjs` gives translated pages matching slugs, adds metadata and edit links, rewrites repository links, and copies documentation assets, the logo, and the favicon.

Every `dev`, `check`, and `build` command runs the sync first. When adding an English document, add its Spanish counterpart, its file name and its description in both languages in `scripts/pages.mjs` (the description is the page's meta description, 50 to 160 characters), and its place in the sidebar (`astro.config.mjs`). `scripts/check-sources.mjs` fails the build when a page has no counterpart, no description, more than one H1 or a title another page already uses.

Three Markdown conventions work on GitHub and on the site:

- GitHub alerts (`> [!NOTE]`, `> [!TIP]`, `> [!WARNING]`, `> [!CAUTION]`) become asides in the identity manual's state colours: note in info, tip in ok, warning in attention (orange) and caution in critical.
- `<!-- screenshot: name | alt text -->` on its own line becomes a figure with `public/screenshots/name-light.png` and `name-dark.png`, following the reader's theme. While the images are missing the build leaves it out and `pnpm run dev` shows a placeholder. The list of captures, with routes and what each must show, is in [SCREENSHOTS.md](SCREENSHOTS.md).
- GitHub renders a ```` ```mermaid ```` block; the site doesn't. Put `<!-- diagram: name | alt text | caption -->` on the line right before it, and the site shows `docs/assets/name-<locale>-light.svg` and `-dark.svg` (or `name-light.svg`/`name-dark.svg`) in its place, following the reader's theme. A Mermaid block without that line, or a missing SVG, fails the build. Draw the SVGs by hand in the identity's tokens, with `<title>`, `<desc>` and real `<text>`.

The site follows the identity manual (`.claude/skills/pitangus-brand`) in `src/styles/custom.css`: IBM Plex Sans and Mono self-hosted through `@fontsource` (no font CDN), cool neutrals, ink text and links, sulphur only for the logo and the home page's primary action, and code blocks themed in `astro.config.mjs` with the same tokens. `public/og.png` is the image shared links show.

## Generated API reference

`scripts/sync-content.mjs` reads `../web/src/shared/api/openapi.json` and generates the automation API reference. It includes only routes explicitly intended for unauthenticated health checks or token-authenticated operation: health, Prometheus metrics, external periodic tasks, and CI SARIF import. Session routes used by the panel are intentionally excluded because they are not a stable public API.

After changing a FastAPI route, run this from the repository root before building the site:

```bash
make openapi
```

The complete schema is used only as a build input and is not copied into the public site because it also describes the panel's internal session routes. FastAPI does not serve that schema or interactive API documentation at runtime.

## Security headers, search engines and assistants

The build writes, after Astro, what the host and machines read:

- `dist/_headers` (`integrations/security-headers.mjs`): HSTS for two years with `includeSubDomains` and `preload`, a strict Content Security Policy, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Cross-Origin-Opener-Policy` and a `Permissions-Policy` that turns every feature off; `/_astro/*` is cached for a year. The CSP allows each inline script Starlight emits (theme, selects, sidebar, search shortcut) by its SHA-256, so it never needs editing by hand, and `'wasm-unsafe-eval'` because the search (Pagefind) compiles WebAssembly; without it search stays on "Searching…". `scripts/check-headers.mjs` fails the build if any page has an inline script whose hash is missing, an inline event handler or a `javascript:` URL.
- `llms.txt` and `llms-full.txt` at the root (English) and under `/es/` (Spanish), from `integrations/llms-txt.mjs`: every page in sidebar order with its description, and the full text with absolute links.
- `robots.txt` (`src/pages/robots.txt.ts`) allows every crawler, AI assistants named one by one, and points to the sitemap; `integrations/sitemap-lastmod.mjs` adds each page's date and an `x-default` alternate to the sitemap.
- JSON-LD in every page's head (`src/routeData.ts`): Organization and WebSite everywhere, WebPage on the home pages, TechArticle and BreadcrumbList on the others, and FAQPage on the FAQ, built from its visible questions and answers. `scripts/check-seo.mjs` fails the build if a page lacks one h1, a description, canonical and hreflang links, Open Graph and Twitter tags, valid JSON-LD, its sitemap date or its line in `llms.txt`.

To try the headers in a browser before deploying, serve the build the way Cloudflare will:

```bash
pnpm run build
node scripts/serve-dist.mjs   # http://localhost:4323, with dist/_headers applied and the 404 page
```

## Deployment

The landing is an independent deployment at `https://pitangus.dev/`; the documentation lives at `https://docs.pitangus.dev/`, so neither owns a path in the other. Both are Cloudflare Workers that only serve static files (`wrangler.jsonc`: no `*.workers.dev` address, no preview URLs, `404.html` for missing pages), which is what makes `_headers` apply.

Cloudflare Workers Builds publishes `docs.pitangus.dev` from `main` (set up as below on 2026-10-11). `.github/workflows/docs.yml` only validates the site on pull requests and pushes; GitHub Pages is retired.

### Move docs.pitangus.dev to Cloudflare

In the Cloudflare dashboard, account that holds the `pitangus.dev` zone:

1. **Workers & Pages → Create → Import a repository**, choose GitHub and `Pitangus-Dev/pitangus` (install or extend the Cloudflare GitHub app to that repository if asked).
2. Project name `pitangus-docs` (it must match `name` in `wrangler.jsonc`). Under **Advanced settings → Root directory**, `docs-site`.
3. **Build command:**

   ```bash
   git fetch --unshallow --quiet || true; corepack enable && pnpm install --frozen-lockfile && pnpm run build
   ```

   **Deploy command:** `npx --yes wrangler@4.146.0 deploy` (Wrangler pinned, the same version as the landing). Production branch `main`; turn off builds for other branches (it would only rebuild the same site).
4. **Build variables:** `NODE_VERSION` = `22`, `COREPACK_ENABLE_DOWNLOAD_PROMPT` = `0`, `SITE_URL` = `https://docs.pitangus.dev`, `BASE_PATH` = `/`. Under **Build watch paths**, include `docs/*`, `docs-site/*`, `.github/CONTRIBUTING*`, `pitangus/shared/settings.py` and `web/src/shared/api/openapi.json`.
5. Save and deploy, and read the build log. The whole repository is cloned, so `../docs` is there. Cloudflare doesn't document whether Workers Builds clones the full history: the `git fetch --unshallow` covers a shallow clone, and if it can't, the sync step logs `Warning: shallow git clone`, which means every page would show the newest commit's date. In that case use the GitHub Actions route below instead.
6. Point the domain. In **DNS → Records** of `pitangus.dev`, delete the `CNAME` `docs → pitangus-dev.github.io` (a Worker custom domain can't be added while another record holds the name; the docs are unreachable for the minute between this step and the next). Then, in the Worker, **Settings → Domains & Routes → Add → Custom domain**: `docs.pitangus.dev`. Cloudflare creates the record and the certificate.
7. Check it: `curl -sI https://docs.pitangus.dev/` shows `content-security-policy` and `strict-transport-security`; a search on the site returns results; [securityheaders.com](https://securityheaders.com/?q=docs.pitangus.dev&followRedirects=on) grades A+.
8. Leave the AI crawlers in: under **Security → Settings** (bots), keep **Block AI bots** off and don't turn on Cloudflare's managed `robots.txt`, which would replace or prepend to this site's own.
9. Retire GitHub Pages: in the repository, **Settings → Pages**, remove the custom domain and set **Source** to none (or unpublish). Then delete the `upload-pages-artifact` step and the `deploy` job from `.github/workflows/docs.yml`, which keeps building and checking pull requests.

Optional: **Analytics & Logs → Web Analytics** for the Worker; the CSP already allows its beacon.

### Or publish from GitHub Actions

If Workers Builds can't be used (the history problem above, or you prefer not to install the Cloudflare app on the repository), `.github/workflows/docs-cloudflare.yml` builds with the full history and deploys with `cloudflare/wrangler-action` pinned by commit. It only runs by hand:

1. In Cloudflare, create an API token from the **Edit Cloudflare Workers** template, limited to this account (and, under zone resources, `pitangus.dev`). The first deploy creates the Worker if it doesn't exist.
2. In the repository, **Settings → Environments → New environment** `docs-cloudflare` (restrict it to `main`), with the secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` (the account ID is on the account's overview page).
3. **Actions → Documentation (Cloudflare) → Run workflow.** Then steps 6 to 9 above.
