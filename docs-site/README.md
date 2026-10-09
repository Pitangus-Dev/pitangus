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

The default local base path is `/`. To test the GitHub Pages project path exactly:

```bash
SITE_URL=https://pitangus-dev.github.io BASE_PATH=/pitangus pnpm run build
SITE_URL=https://pitangus-dev.github.io BASE_PATH=/pitangus pnpm run preview
```

On PowerShell:

```powershell
$env:SITE_URL = 'https://pitangus-dev.github.io'
$env:BASE_PATH = '/pitangus'
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

Every `dev`, `check`, and `build` command runs the sync first. When adding an English document, add its Spanish counterpart and update the filename map, metadata, and sidebar.

## Generated API reference

`scripts/sync-content.mjs` reads `../web/src/shared/api/openapi.json` and generates the automation API reference. It includes only routes explicitly intended for unauthenticated health checks or token-authenticated operation: health, Prometheus metrics, external periodic tasks, and CI SARIF import. Session routes used by the panel are intentionally excluded because they are not a stable public API.

After changing a FastAPI route, run this from the repository root before building the site:

```bash
make openapi
```

The complete schema is used only as a build input and is not copied into the public site because it also describes the panel's internal session routes. FastAPI does not serve that schema or interactive API documentation at runtime.

## Deployment decision

The public landing is deployed from the separate `Pitangus-Dev/pitangus-dev.github.io` repository. Its workflow uploads one `dist` artifact that owns the organization Pages root. A second Pages deployment cannot safely add `/docs/` without replacing or coordinating that artifact.

For that reason, `.github/workflows/docs.yml` validates the site on pull requests and pushes, but publication is manual. When approved and enabled under **Settings → Pages → GitHub Actions**, it publishes this repository's project site at:

`https://pitangus-dev.github.io/pitangus/`

This does not modify or overwrite the landing. To use the preferred `https://pitangus-dev.github.io/docs/` address later, update the landing repository's build to copy this site's output into `dist/docs/` before its single Pages artifact is uploaded. That cross-repository change is deliberately outside this implementation.
