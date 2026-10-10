[English](../cli.md) · Español

# Analizar desde la terminal y en CI (`scan`)

`scan` analiza una carpeta local con los mismos motores que el panel (Opengrep, Gitleaks,
Trivy, OSV-Scanner, Checkov, zizmor), sin ejecutar su código y sin enviarlo a ningún servicio.
Sirve para revisar tu cambio antes de subirlo y para bloquear un pull request en CI.

## Uso rápido

Desde la carpeta de Pitangus (solo hace falta `make` y Docker):

```bash
make scan DIR=../mi-repo
make scan DIR=../mi-repo ARGS="--base main"
```

Con `--base main` solo se informa de lo que **tu cambio introduce**. Pitangus analiza también el
punto de partida (el merge-base con `main`) y descarta lo que ya estaba: si tocas un
`package-lock.json` que ya tenía vulnerabilidades, no te las cobra; si añades una dependencia
vulnerable, sí. Cuenta lo que aún no has subido (cambios sin commit y archivos nuevos que git no
ignora), así que funciona antes del push.

```text
Pitangus · mi-repo · cambios respecto a main (merge-base 73223791, 3 archivos)

CRÍTICA  app.py:8  Injection: eval exec non literal
ALTA     requirements.txt  urllib3 1.26.4: 9 avisos (5 alta, 4 media) → actualiza a 2.7.0
ALTA     settings.py:1  Token personal de GitHub expuesto

4 ya existían en el código que tocas: no bloquean.

Corregido en este cambio (1): estaba en el punto de partida, ya no está y su archivo cambió.
  ALTA     db.py:14  SQL construido concatenando cadenas

Motores: Opengrep 1.30.0, Gitleaks 8.30.1, Trivy 0.75.0, OSV-Scanner 2.6.0

BLOQUEA · umbral: alta o superior · 7 hallazgos nuevos de severidad alta o superior
```

**Lo que corrige el cambio.** Al comparar los dos análisis también sale lo que tenía el punto de partida y el
cambio ya no tiene. Cuenta como **corregido** solo si los dos análisis terminaron y su archivo es uno de los que el
cambio modificó. Si desapareció porque se borró el archivo, o sin que se tocara su archivo, la salida lo dice y no lo
cuenta como corrección; si alguno de los dos análisis quedó incompleto, dice que no se puede verificar. Un hallazgo
que solo se movió (misma regla, mismo archivo) no se reporta. Sirve para lo que detectan los motores de Pitangus; los
hallazgos importados de otras herramientas se verifican importando de nuevo los resultados de esa herramienta.

Los avisos de una misma dependencia salen en una línea con la versión que los cierra todos.
`--format json` y `--format sarif` conservan cada aviso por separado.

## Opciones

| Opción | Qué hace |
| --- | --- |
| `--base REF` | Rama o commit de partida (`main`, `origin/main`, un SHA). Solo cuenta lo que introduce el cambio. |
| `--no-baseline` | Con `--base`, no analiza el punto de partida: tarda la mitad, pero cuenta todo lo que cae en líneas cambiadas (y cualquier aviso de un lockfile que toques). |
| `--fail-on` | Severidad desde la que falla: `critical`, `high` (por defecto), `medium`, `low` o `never` (solo informa). |
| `--format` | `text` (por defecto), `json` o `sarif` (SARIF 2.1.0, con `security-severity` para GitHub code scanning). |
| `--output FILE` | Escribe el resultado en un archivo; el resumen en texto sale igualmente por la salida de errores. |
| `--exclude PATRÓN` | Ruta cuyos hallazgos no cuentan: glob relativo a la raíz (`fixtures`, `**/testdata`, `docs/*.md`). Como en `.gitignore`, una carpeta excluye todo lo que tiene dentro; `*` no cruza `/` y `**` sí. Repetible. La salida dice cuántos se excluyeron. |
| `--allow-incomplete` | No falla si un motor no pudo ejecutarse. Por defecto sí falla: un análisis que no terminó no equivale a «limpio». |
| `--allow-osv-upload` | Autoriza consultas externas (nombres y versiones de dependencias a OSV y deps.dev para resolver transitivas). Por defecto no sale nada. |
| `--name` | Nombre a mostrar (útil dentro de un contenedor, donde la carpeta se llama `/src`). |
| `--summary ARCHIVO` | Añade además un resumen en Markdown: veredicto, lo que el cambio introduce y lo que corrige (la Action lo escribe en la página de resumen de la ejecución). |
| `--quiet` | Sin mensajes de progreso. |

El progreso va a la salida de errores; la salida estándar queda limpia para `json` y `sarif`.

## Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Pasa: nada del umbral o peor. |
| `1` | Bloquea: hay hallazgos nuevos del umbral o peores. |
| `2` | Error de uso: carpeta inexistente, referencia de git inválida o inexistente (¿falta `git fetch`?). |
| `3` | Incompleto: algún motor no se ejecutó (Docker, imágenes, red). Revisa las líneas «Sin analizar». |

`make` convierte cualquier fallo en su propio código 2; en CI, la Action y `docker run` (abajo)
conservan el código exacto.

## Antes de subir (pre-push)

Un análisis completo tarda del orden de medio minuto, así que encaja mejor en `pre-push` que en
`pre-commit`. En `.git/hooks/pre-push` de tu repositorio (y `chmod +x`):

```sh
#!/bin/sh
make -s -C ~/pitangus scan DIR="$(git rev-parse --show-toplevel)" ARGS="--base origin/main --quiet"
```

## Importar resultados de otras herramientas (`import-sarif`)

```sh
python -m pitangus import-sarif ARCHIVO [ARCHIVO...] --asset NOMBRE [--tool NOMBRE] [--partial] [--commit SHA] [--branch NOMBRE] [--server URL]
```

Añade los hallazgos de cualquier herramienta que escriba SARIF 2.1.0 (Semgrep, CodeQL, Snyk, Trivy, Strix, ZAP,
Nuclei…) al registro de un activo que Pitangus ya conoce, por su clave o por su nombre (`owner/repo`), o de un dominio
verificado (`domain:app.example.com`, mira [Trae tu propio DAST](integraciones.md#trae-tu-propio-dast)). Desde ese
momento siguen el mismo ciclo que los de Pitangus: triage, plazos, incidencias y avisos.

- **Completa por defecto:** lo que esa misma herramienta deje de reportar queda remediado. Los análisis de Pitangus
  nunca remedian un hallazgo importado, porque sus motores no ven lo que encontró otra herramienta.
- `--partial`: la herramienta miró solo una parte del activo; la importación abre y actualiza, nunca remedia.
- `--tool` reemplaza el nombre de herramienta que trae el SARIF. Varios archivos forman una sola importación.
- `--server https://…` envía los archivos a `/api/ci/sarif` de ese servidor con el token de `PITANGUS_IMPORT_TOKEN`
  (una variable de entorno, nunca una opción; `http://` sin cifrar solo para localhost). Sin `--server` importa en
  la base de datos local (en el propio servidor).

Muestra una línea por herramienta. Códigos de salida: `0` importado, `2` error de uso, del documento o del servidor.
En el panel, **Nuevo análisis → Importar SARIF** hace lo mismo desde el navegador.

## En CI

En CI, Pitangus corre desde la imagen publicada del worker, `ghcr.io/pitangus-dev/pitangus-worker:0.12`, que trae
los motores dentro y los ejecuta como procesos propios: nada que construir y sin socket de Docker.

### GitHub Actions

Un paso con la Action de Pitangus. En un pull request compara por su cuenta con la rama base, y deja un SARIF listo
para code scanning:

```yaml
name: Pitangus
on:
  pull_request:
  push:
    branches: [main]

permissions: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # para subir el SARIF a code scanning
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0              # hace falta la historia para comparar con la base
          persist-credentials: false
      - id: pitangus
        uses: Pitangus-Dev/pitangus@v0.12.2   # fíjala al SHA del commit de la etiqueta, como las demás
        with:
          exclude: |
            fixtures/
      - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2  # v4.38.2
        if: always() && steps.pitangus.outputs.sarif != ''
        with:
          sarif_file: ${{ steps.pitangus.outputs.sarif }}
          category: pitangus
```

El paso termina con el mismo código que `scan` (tabla de arriba): falla con `1`, `2` y `3`. El informe sale en el
log, en inglés salvo que el paso ponga `env: PITANGUS_DEFAULT_LOCALE: es`.

| Entrada | Por defecto | Qué hace |
| --- | --- | --- |
| `path` | `.` | Carpeta a analizar, relativa al workspace. |
| `base` | vacío | Como `--base`. Vacío: `origin/<rama base>` en un pull request y análisis completo en lo demás; `none`: siempre completo. |
| `fail-on` | `high` | Como `--fail-on`: `critical`, `high`, `medium`, `low` o `never`. |
| `exclude` | vacío | Un patrón por línea; cada uno se convierte en un `--exclude`. |
| `name` | el nombre del repositorio | Como `--name`. |
| `sarif` | `$RUNNER_TEMP/pitangus.sarif` | Dónde escribir el SARIF (las rutas relativas parten del workspace). |
| `image` | `ghcr.io/pitangus-dev/pitangus-worker:0.12` | Imagen del worker. Fíjala por digest (`…@sha256:…`) si no quieres que nada cambie sin avisar. |
| `verify` | `true` | `false`: no comprueba la firma de la imagen. Solo para una `image` tuya (un fork, un espejo privado): la imagen publicada se comprueba siempre. |
| `allow-incomplete` | `false` | `true`: como `--allow-incomplete`. |
| `scan` | `true` | `false`: no analiza, solo importa (más abajo). |
| `import-sarif` | vacío | SARIF de otras herramientas que se envían a un servidor Pitangus, uno por línea. |
| `server` | vacío | El servidor Pitangus (`https://…`) para `import-sarif`. |
| `token` | vacío | El `PITANGUS_IMPORT_TOKEN` del servidor, desde un secreto. Al contenedor solo le llega como variable de entorno. |
| `asset` | `owner/name` del repositorio | Activo (que el servidor ya conoce) al que se suman los hallazgos importados. |
| `import-partial` | `false` | `true`: la herramienta importada miró solo una parte del activo, así que lo que no reporta sigue abierto. En una pull request siempre está activo: sus resultados son de la rama, no del activo. |
| `registry-token` | vacío | Solo si usas la imagen desde un registro privado tuyo (un espejo, un fork): un token para descargarla. La imagen publicada es pública. |
| `registry-user` | quien lanzó el workflow | Usuario de `registry-token`. |

| Salida | Qué es |
| --- | --- |
| `sarif` | Ruta del SARIF que escribió el análisis (vacía si no escribió ninguno). |
| `exit-code` | `0` pasa, `1` bloquea, `2` error de uso o una imagen cuya firma no se pudo comprobar, `3` incompleto. Si además importa, manda el código del análisis salvo que sea `0`. |

La página de resumen de la ejecución muestra el veredicto, lo que la pull request introduce y lo que corrige.

Antes de ejecutar nada, la Action resuelve la imagen a su digest, comprueba la firma cosign de ese digest (keyless: el
certificado tiene que venir del workflow de release de Pitangus en una etiqueta `v*`, por el emisor OIDC de GitHub) y
ejecuta ese mismo digest: lo que corre es justo lo que se comprobó. Fijar la Action por SHA fija su código; esto fija
la imagen. Instala cosign con un `sigstore/cosign-installer` fijado.

Cómo corre: `docker run` de la imagen con el usuario del runner, sin capabilities, con el sistema de archivos de
solo lectura, el workspace montado en solo lectura y las cachés de los motores en `$RUNNER_TEMP/pitangus` (varios
pasos del mismo job las comparten). Ahí los motores no pueden tener una red vacía propia (un `docker run` normal no
permite los espacios de nombres de usuario que hacen falta), así que comparten la red del contenedor y corren con sus
opciones sin conexión; tu código sigue sin enviarse a ningún sitio.

#### Resultados de otras herramientas

Con `import-sarif`, la Action envía el SARIF de cualquier herramienta (Semgrep, CodeQL, Snyk…) a tu servidor
Pitangus, que suma sus hallazgos al registro del activo junto a los suyos. El servidor necesita
`PITANGUS_IMPORT_TOKEN` ([configuración](configuracion.md)) y debe conocer ya el activo. Por ejemplo, solo Semgrep,
sin el análisis propio de Pitangus:

```yaml
      - name: Semgrep
        run: |
          python -m pip install semgrep   # fija la versión
          semgrep scan --config p/ci --metrics off --sarif --output semgrep.sarif
      - uses: Pitangus-Dev/pitangus@v0.12.2
        if: always()
        with:
          scan: false
          import-sarif: semgrep.sarif
          server: https://pitangus.example.com
          token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
```

Deja `scan` en `true` para analizar e importar en el mismo paso.

### GitLab CI

La imagen del worker como imagen del job: ya trae git, Python y los motores, y corre con un usuario sin privilegios.
Sin socket de Docker y sin Docker-in-Docker.

```yaml
pitangus:
  stage: test
  image: ghcr.io/pitangus-dev/pitangus-worker:0.12
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"   # hace falta la historia para comparar con la base
    BASE: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
  script:
    # El checkout es de otro usuario: hay que decirle a git que es de confianza.
    - git -c safe.directory="$CI_PROJECT_DIR" fetch origin "$BASE:refs/remotes/origin/$BASE"
    - python -m pitangus scan . --name "$CI_PROJECT_NAME" --base "origin/$BASE"
```

En un runner con ejecutor `shell`, usa `docker run` como hace la Action, sin el socket:

```sh
mkdir -p /tmp/pitangus-data   # la creas tú, no Docker: tiene que ser de tu usuario
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/src:ro -v /tmp/pitangus-data:/data \
  ghcr.io/pitangus-dev/pitangus-worker:0.12 python -m pitangus scan /src --name "$CI_PROJECT_NAME" --base "origin/$BASE"
```

> El propio repositorio de Pitangus usa la Action en [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), y
> además se analiza con la imagen construida en cada commit (con `--exclude fixtures/` para sus ejemplos vulnerables
> a propósito). La plantilla de GitLab está comprobada en local con la misma imagen y un checkout de otro usuario,
> pero aún no en un runner real. Si algo falla, el motivo aparece en la línea «Sin analizar».

**Exclusiones en CI.** `exclude` vive en el workflow, que un pull request puede modificar. Protege
`.github/workflows/` (o `.gitlab-ci.yml`) con CODEOWNERS y revisión obligatoria para que nadie se excluya a sí mismo
sin que se vea. (En el panel las exclusiones viven en el servidor por eso mismo.)

## Privacidad

El código se copia a una carpeta temporal (sin enlaces simbólicos ni lo que el análisis ignora) y
se borra al terminar. Los motores lo leen en solo lectura, sin red salvo para descargar sus bases
públicas de avisos. Nada del repositorio sale de la máquina salvo que pases `--allow-osv-upload`.
