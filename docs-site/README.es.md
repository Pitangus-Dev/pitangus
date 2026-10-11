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

## Decisión de despliegue

La landing pública sigue siendo un despliegue independiente en `https://pitangus.dev/`. La documentación usa el subdominio dedicado `https://docs.pitangus.dev/` para que ninguno de los despliegues tenga que controlar una ruta dentro del artefacto del otro.

`.github/workflows/docs.yml` valida el sitio en pull requests y pushes, mientras que la publicación sigue siendo manual mediante `workflow_dispatch`. Para activar el dominio personalizado:

1. En este repositorio, selecciona **Settings → Pages → GitHub Actions** y establece `docs.pitangus.dev` como dominio personalizado.
2. En el DNS de Cloudflare, crea un registro `CNAME` llamado `docs` que apunte a `pitangus-dev.github.io`. Déjalo inicialmente como **Solo DNS** mientras GitHub valida el dominio y aprovisiona HTTPS.
3. Ejecuta manualmente el workflow **Documentation** y activa **Enforce HTTPS** cuando GitHub habilite la opción.
4. Actualiza el enlace **Read the docs** de la landing a `https://docs.pitangus.dev/` desde su propio repositorio.

Los despliegues mediante GitHub Actions no necesitan un archivo `CNAME` versionado; el dominio personalizado se guarda en la configuración de Pages del repositorio.
