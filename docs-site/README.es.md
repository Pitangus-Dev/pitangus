# Sitio de documentación de Pitangus

Este directorio contiene la aplicación Astro Starlight que convierte la documentación existente en inglés y español en un sitio estático con buscador.

## Ejecución local

Usa Node.js 22.12 o posterior y pnpm con corepack (`corepack enable`; `package.json` fija la versión):

```bash
cd docs-site
pnpm install --frozen-lockfile
pnpm run dev       # http://localhost:4321
pnpm run check     # consistencia de fuentes y tipos de Astro
pnpm run build     # build de producción y validación de enlaces internos
pnpm run preview   # http://localhost:4322 después del build
```

La ruta base local es `/`. Para probar exactamente la URL de producción desde PowerShell:

```powershell
$env:SITE_URL = 'https://docs.pitangus.dev'
$env:BASE_PATH = '/'
pnpm run build
pnpm run preview
```

## Contenido canónico

No edites `src/content/docs/`: se genera y Git lo ignora.

- La documentación en inglés permanece en `../docs/*.md`.
- La documentación en español permanece en `../docs/es/*.md`.
- Las guías para contribuir permanecen en `../.github/CONTRIBUTING*.md`.
- Las portadas de Starlight viven en `content/` porque usan componentes MDX y metadatos propios del sitio.
- `scripts/sync-content.mjs` alinea los slugs de ambos idiomas, añade metadatos y enlaces de edición, ajusta enlaces al repositorio y copia los recursos documentales, el logo y el favicon.

Cada comando `dev`, `check` y `build` sincroniza primero. Al añadir un documento en inglés, añade su versión en español, su nombre de archivo y su descripción en ambos idiomas en `scripts/pages.mjs` (es la meta descripción de la página, de 50 a 160 caracteres) y su lugar en la barra lateral (`astro.config.mjs`). `scripts/check-sources.mjs` detiene el build si una página no tiene contraparte, no tiene descripción, tiene más de un H1 o repite el título de otra.

Tres convenciones de Markdown funcionan en GitHub y en el sitio:

- Las alertas de GitHub (`> [!NOTE]`, `> [!TIP]`, `> [!WARNING]`, `> [!CAUTION]`) se convierten en avisos con los colores de estado del manual de identidad: note en info, tip en ok, warning en atención (naranja) y caution en crítico.
- `<!-- screenshot: nombre | texto alternativo -->` en su propia línea se convierte en una figura con `public/screenshots/nombre-light.png` y `nombre-dark.png`, según el tema de quien lee. Mientras falten las imágenes el build la omite y `pnpm run dev` muestra un marcador. La lista de capturas, con rutas y qué debe verse en cada una, está en [SCREENSHOTS.md](SCREENSHOTS.md).
- GitHub dibuja un bloque ```` ```mermaid ````; el sitio no. Pon `<!-- diagram: nombre | texto alternativo | pie -->` en la línea justo anterior y el sitio muestra en su lugar `docs/assets/nombre-<idioma>-light.svg` y `-dark.svg` (o `nombre-light.svg`/`nombre-dark.svg`), según el tema de quien lee. Un bloque Mermaid sin esa línea, o un SVG que falte, hace fallar el build. Los SVG se dibujan a mano con los tokens de la identidad, con `<title>`, `<desc>` y `<text>` reales.

El sitio sigue el manual de identidad (`.claude/skills/pitangus-brand`) en `src/styles/custom.css`: IBM Plex Sans y Mono servidas desde el propio sitio con `@fontsource` (sin CDN de fuentes), neutros fríos, texto y enlaces en tinta, azufre solo para el logo y la acción principal de la portada, y bloques de código con los mismos tokens, definidos en `astro.config.mjs`. `public/og.png` es la imagen que muestran los enlaces compartidos.

## Referencia de API generada

`scripts/sync-content.mjs` lee `../web/src/shared/api/openapi.json` y genera la referencia de automatización. Solo incluye rutas destinadas de forma explícita a la comprobación pública de salud o a operaciones autenticadas con token: métricas de Prometheus, tareas periódicas externas e importación SARIF desde CI. Las rutas de sesión del panel se excluyen porque no son una API pública estable.

Después de cambiar una ruta FastAPI, ejecuta desde la raíz:

```bash
make openapi
```

El esquema completo solo se usa como entrada del build y no se copia al sitio público porque también describe las rutas internas de sesión del panel. FastAPI no sirve ese esquema ni una interfaz interactiva en ejecución.

## Cabeceras de seguridad, buscadores y asistentes

Después de Astro, el build escribe lo que leen el hosting y las máquinas:

- `dist/_headers` (`integrations/security-headers.mjs`): HSTS de dos años con `includeSubDomains` y `preload`, una Content Security Policy estricta, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Cross-Origin-Opener-Policy` y una `Permissions-Policy` que apaga todas las funciones; `/_astro/*` se guarda en caché un año. La CSP admite cada script en línea que emite Starlight (tema, selectores, barra lateral, atajo de búsqueda) por su SHA-256, así que nunca se edita a mano, y `'wasm-unsafe-eval'` porque la búsqueda (Pagefind) compila WebAssembly; sin él la búsqueda se queda en «Buscando…». `scripts/check-headers.mjs` hace fallar el build si una página tiene un script en línea sin su hash, un manejador de eventos en línea o una URL `javascript:`.
- `llms.txt` y `llms-full.txt` en la raíz (inglés) y bajo `/es/` (español), desde `integrations/llms-txt.mjs`: todas las páginas en el orden de la barra lateral con su descripción, y el texto completo con enlaces absolutos.
- `robots.txt` (`src/pages/robots.txt.ts`) admite a todos los rastreadores, con los de asistentes de IA nombrados uno a uno, y apunta al sitemap; `integrations/sitemap-lastmod.mjs` añade al sitemap la fecha de cada página y la alternativa `x-default`.
- JSON-LD en el head de cada página (`src/routeData.ts`): Organization y WebSite en todas, WebPage en las portadas, TechArticle y BreadcrumbList en las demás, y FAQPage en las preguntas frecuentes, a partir de las preguntas y respuestas visibles. `scripts/check-seo.mjs` hace fallar el build si a una página le falta un h1 único, la descripción, los enlaces canonical y hreflang, las etiquetas Open Graph y Twitter, un JSON-LD válido, su fecha en el sitemap o su línea en `llms.txt`.

Para probar las cabeceras en un navegador antes de desplegar, sirve el build como lo hará Cloudflare:

```bash
pnpm run build
node scripts/serve-dist.mjs   # http://localhost:4323, con dist/_headers aplicado y la página 404
```

## Despliegue

La landing es un despliegue independiente en `https://pitangus.dev/`; la documentación vive en `https://docs.pitangus.dev/`, así que ninguna controla una ruta de la otra. Las dos son Workers de Cloudflare que solo sirven archivos estáticos (`wrangler.jsonc`: sin dirección `*.workers.dev`, sin URLs de vista previa, `404.html` para lo que no existe), y por eso se aplica `_headers`.

Cloudflare Workers Builds publica `docs.pitangus.dev` desde `main` (configurado como se explica abajo el 2026-10-11). `.github/workflows/docs.yml` solo valida el sitio en pull requests y pushes; GitHub Pages está retirado.

### Pasar docs.pitangus.dev a Cloudflare

En el panel de Cloudflare, en la cuenta que tiene la zona `pitangus.dev`:

1. **Workers & Pages → Create → Import a repository**, elige GitHub y `Pitangus-Dev/pitangus` (si lo pide, instala o amplía la app de Cloudflare en GitHub a ese repositorio).
2. Nombre del proyecto `pitangus-docs` (debe coincidir con `name` en `wrangler.jsonc`). En **Advanced settings → Root directory**, `docs-site`.
3. **Build command:**

   ```bash
   git fetch --unshallow --quiet || true; corepack enable && pnpm install --frozen-lockfile && pnpm run build
   ```

   **Deploy command:** `npx --yes wrangler@4.146.0 deploy` (Wrangler fijado, la misma versión que la landing). Rama de producción `main`; desactiva los builds de otras ramas (solo reconstruirían el mismo sitio).
4. **Build variables:** `NODE_VERSION` = `22`, `COREPACK_ENABLE_DOWNLOAD_PROMPT` = `0`, `SITE_URL` = `https://docs.pitangus.dev`, `BASE_PATH` = `/`. En **Build watch paths**, incluye `docs/*`, `docs-site/*`, `.github/CONTRIBUTING*`, `pitangus/shared/settings.py` y `web/src/shared/api/openapi.json`.
5. Guarda, despliega y lee el log del build. Se clona el repositorio entero, así que `../docs` está. Cloudflare no documenta si Workers Builds clona el historial completo: el `git fetch --unshallow` cubre un clon superficial y, si no puede, el paso de sincronización escribe `Warning: shallow git clone`, que significa que todas las páginas mostrarían la fecha del último commit. En ese caso usa la vía de GitHub Actions de más abajo.
6. Apunta el dominio. En **DNS → Records** de `pitangus.dev`, borra el `CNAME` `docs → pitangus-dev.github.io` (no se puede añadir un dominio personalizado a un Worker mientras otro registro ocupa el nombre; la documentación no responde durante el minuto entre este paso y el siguiente). Luego, en el Worker, **Settings → Domains & Routes → Add → Custom domain**: `docs.pitangus.dev`. Cloudflare crea el registro y el certificado.
7. Compruébalo: `curl -sI https://docs.pitangus.dev/` muestra `content-security-policy` y `strict-transport-security`; una búsqueda en el sitio devuelve resultados; [securityheaders.com](https://securityheaders.com/?q=docs.pitangus.dev&followRedirects=on) da A+.
8. Deja pasar a los rastreadores de IA: en **Security → Settings** (bots), mantén **Block AI bots** apagado y no actives el `robots.txt` gestionado por Cloudflare, que reemplazaría o antepondría reglas al de este sitio.
9. Retira GitHub Pages: en el repositorio, **Settings → Pages**, quita el dominio personalizado y deja **Source** en ninguno (o despublica). Después borra el paso `upload-pages-artifact` y el job `deploy` de `.github/workflows/docs.yml`, que sigue construyendo y revisando las pull requests.

Opcional: **Analytics & Logs → Web Analytics** para el Worker; la CSP ya admite su baliza.

### O publicar desde GitHub Actions

Si no se puede usar Workers Builds (el problema del historial de arriba, o prefieres no instalar la app de Cloudflare en el repositorio), `.github/workflows/docs-cloudflare.yml` construye con el historial completo y despliega con `cloudflare/wrangler-action` fijado por commit. Solo se ejecuta a mano:

1. En Cloudflare, crea un token de API desde la plantilla **Edit Cloudflare Workers**, limitado a esta cuenta (y, en recursos de zona, a `pitangus.dev`). El primer despliegue crea el Worker si no existe.
2. En el repositorio, **Settings → Environments → New environment** `docs-cloudflare` (restringido a `main`), con los secretos `CLOUDFLARE_API_TOKEN` y `CLOUDFLARE_ACCOUNT_ID` (el ID de cuenta está en la página de resumen de la cuenta).
3. **Actions → Documentation (Cloudflare) → Run workflow.** Después, los pasos 6 a 9 de arriba.
