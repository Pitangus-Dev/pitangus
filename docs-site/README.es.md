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

La ruta base local es `/`. Para probar exactamente la ruta de proyecto en GitHub Pages desde PowerShell:

```powershell
$env:SITE_URL = 'https://pitangus-dev.github.io'
$env:BASE_PATH = '/pitangus'
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

Cada comando `dev`, `check` y `build` sincroniza primero. Al añadir un documento en inglés, añade su versión en español y actualiza el mapa de archivos, los metadatos y la barra lateral.

## Referencia de API generada

`scripts/sync-content.mjs` lee `../web/src/shared/api/openapi.json` y genera la referencia de automatización. Solo incluye rutas destinadas de forma explícita a la comprobación pública de salud o a operaciones autenticadas con token: métricas de Prometheus, tareas periódicas externas e importación SARIF desde CI. Las rutas de sesión del panel se excluyen porque no son una API pública estable.

Después de cambiar una ruta FastAPI, ejecuta desde la raíz:

```bash
make openapi
```

El esquema completo solo se usa como entrada del build y no se copia al sitio público porque también describe las rutas internas de sesión del panel. FastAPI no sirve ese esquema ni una interfaz interactiva en ejecución.

## Decisión de despliegue

La landing pública se despliega desde el repositorio separado `Pitangus-Dev/pitangus-dev.github.io`. Su workflow sube un único artefacto `dist` que ocupa la raíz de Pages de la organización. Otro despliegue de Pages no puede añadir `/docs/` de forma segura sin sustituir o coordinar ese artefacto.

Por eso, `.github/workflows/docs.yml` valida el sitio en pull requests y pushes, pero la publicación es manual. Cuando se apruebe y se active **Settings → Pages → GitHub Actions**, publica el sitio de proyecto de este repositorio en:

`https://pitangus-dev.github.io/pitangus/`

La landing no se modifica ni se sobrescribe. Para usar más adelante la dirección preferida `https://pitangus-dev.github.io/docs/`, el build de la landing debe copiar la salida de este sitio a `dist/docs/` antes de subir su único artefacto de Pages. Ese cambio entre repositorios queda deliberadamente fuera de esta implementación.
