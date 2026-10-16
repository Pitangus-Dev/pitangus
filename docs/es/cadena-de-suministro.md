[English](../supply-chain.md) · Español

# Cadena de suministro

Pitangus ejecuta motores de terceros sobre tu código, así que la pregunta «¿qué estoy ejecutando exactamente?» tiene una respuesta precisa: cada motor y cada imagen base van fijados por digest, cada imagen de una versión está firmada y puedes comprobar esa firma antes de instalar. Esta página enumera qué está fijado, cómo se comprueba y en qué parte del repositorio vive cada afirmación. Solo dice lo que hace el código de `main`; lo que no cubre está al final.

## Por qué importa

Una etiqueta de versión es un puntero, y quien tenga las credenciales del mantenedor puede moverla. En marzo de 2026 unos atacantes hicieron justo eso con las GitHub Actions del proyecto Trivy: reapuntaron etiquetas de versión existentes de `aquasecurity/trivy-action` (76 de sus 77 etiquetas, según [CrowdStrike](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise)) hacia código que robaba los secretos de cada workflow que lo ejecutaba, y `setup-trivy` también se vio afectada ([Snyk](https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/)). Los workflows que pedían una etiqueta ejecutaron el código del atacante sin que cambiara nada en su propio repositorio; un SHA de commit completo o un digest de imagen no se pueden mover así. Ambos análisis recomiendan fijar por SHA de commit.

Ese es el mecanismo alrededor del cual está construido Pitangus: nada de lo que ejecuta se nombra solo con una etiqueta. Ningún workflow de este repositorio usa esas dos acciones.

## De un vistazo

| Qué | Cómo se fija o se comprueba | Dónde |
| --- | --- | --- |
| Imágenes de los motores (Trivy, OSV-Scanner, Betterleaks, Grype, Checkov, zizmor y los del análisis web) | Por digest `sha256` | `IMAGES` en [`engines.py`](../../pitangus/modules/scanning/engines.py), [`docker/app/Dockerfile`](../../docker/app/Dockerfile) |
| Opengrep | Binario oficial comprobado contra su SHA-256, sobre una base fijada por digest | [`docker/engines/opengrep/Dockerfile`](../../docker/engines/opengrep/Dockerfile) |
| Imágenes base, Caddy, PostgreSQL | Por digest | Dockerfiles y archivos compose |
| Paquetes de Python | Con hashes en el lock (`--require-hashes`) | `requirements.txt`, `docker/checkov/requirements.txt` |
| GitHub Actions que usa este repositorio | SHA de commit completo, con la versión en un comentario | [`.github/workflows/`](../../.github/workflows/) |
| Imágenes de cada versión | Construidas desde una etiqueta `v*`, con SBOM y procedencia adjuntos, firmadas con cosign (sin clave) | [`release.yml`](../../.github/workflows/release.yml) |
| Imagen que usan la GitHub Action y el hook de pre-commit | Firma comprobada, ejecutada por digest | [`action.yml`](../../action.yml), [`hooks/pitangus-docker`](../../hooks/pitangus-docker) |
| Las prácticas del propio repositorio | Puntuadas por OpenSSF Scorecard, cada semana | [`scorecard.yml`](../../.github/workflows/scorecard.yml) |

## Imágenes de los motores

Cada motor corre desde una imagen cuya referencia termina en `@sha256:…`. La lista única es `IMAGES` en `pitangus/modules/scanning/engines.py`: Trivy, OSV-Scanner, Betterleaks, Grype, Checkov y zizmor, más ZAP, subfinder, katana, nuclei, testssl.sh y httpx para los análisis web. Una imagen se descarga siempre por ese digest, así que una etiqueta que se mueva en Docker Hub o en GHCR no cambia nada aquí.

La imagen del worker con los motores dentro (la que usan los servidores y las integraciones de CI) copia los mismos binarios de los mismos digests: `FROM <imagen>@sha256:… AS trivy`, y así con los demás, en `docker/app/Dockerfile`. `tests/test_packaging.py` falla si las dos listas no coinciden, si alguna imagen de un compose o un Dockerfile no lleva digest, o si el lock de Checkov o las sumas de Opengrep difieren entre la imagen de la app y la del motor.

Dos motores no se descargan de un registro:

- **Opengrep** se construye con el binario oficial de la versión del proyecto, comprobado contra el SHA-256 escrito en el Dockerfile (uno por arquitectura). Si no coincide, la imagen no se construye. `docker/engines/opengrep/VERIFY.md` explica cómo repetir la verificación Cosign original al actualizar.
- **Checkov** se instala desde un conjunto de paquetes con hashes en el lock (`pip install --require-hashes`).

Otras descargas de la construcción se comprueban igual: la CLI de Docker contra su SHA-256, y el archivo de plantillas de nuclei, en ejecución, contra un SHA-256 fijado en el código ([Seguridad](seguridad.md#qué-sale-de-tu-máquina)).

## Cómo se construyen y firman las imágenes de cada versión

Subir una etiqueta `v*` ejecuta [`release.yml`](../../.github/workflows/release.yml), que publica tres imágenes en GHCR:

| Imagen | Contenido |
| --- | --- |
| `ghcr.io/pitangus-dev/pitangus:<versión>` | Panel, API y worker |
| `ghcr.io/pitangus-dev/pitangus-worker:<versión>` | Worker con los motores dentro, sin necesitar el socket de Docker |
| `ghcr.io/pitangus-dev/pitangus-opengrep:<versión del motor>` | El motor Opengrep |

Lo que hace el workflow, en orden:

1. Rechaza una etiqueta que no coincida con `pitangus/version.py`.
2. Construye la imagen una vez para revisarla y le pasa Trivy, desde la misma imagen fijada por digest: **no se publica una imagen con una vulnerabilidad crítica que ya tenga corrección.**
3. Construye y sube para `linux/amd64` y `linux/arm64` con `sbom: true` y `provenance: mode=max`: BuildKit adjunta a la imagen un SBOM en SPDX y una declaración de procedencia SLSA.
4. Firma la imagen por digest, nunca por etiqueta, con `cosign sign --recursive`: **sin clave** (keyless), con la identidad OIDC de GitHub del propio workflow, así que no hay ninguna clave de firma que guardar ni que se pueda filtrar. Después comprueba su propia firma antes de terminar el job.

El job que puede escribir paquetes corre solo desde el entorno `release`, con `contents: read`, `packages: write` e `id-token: write` y nada más. Las etiquetas `v*` están protegidas por una regla del repositorio para que no se puedan mover ni borrar (lo anota la cabecera del workflow), y eso es lo que da sentido a la identidad de abajo.

La firma une un digest de imagen con esta identidad de certificado, emitida por el proveedor OIDC de GitHub:

```
https://github.com/Pitangus-Dev/pitangus/.github/workflows/release.yml@refs/tags/v<mayor>.<menor>[.<parche>]
```

Una construcción desde un fork, desde otro workflow o desde una rama tiene otra identidad y no pasa la comprobación.

## Verifica una versión antes de instalarla

Necesitas [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) y la CLI de Docker.

```bash
# 1. La firma: tiene que venir del workflow de release de una etiqueta v*.
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Pitangus-Dev/pitangus/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+(\.[0-9]+)?$' \
  ghcr.io/pitangus-dev/pitangus-worker:0.15
# El "docker-manifest-digest" de la salida es la imagen exacta que se firmó: úsala (imagen@sha256:…) de aquí en adelante.

# 2. El SBOM y la procedencia adjuntos.
docker buildx imagetools inspect ghcr.io/pitangus-dev/pitangus-worker:0.15 --format '{{json .SBOM}}'
docker buildx imagetools inspect ghcr.io/pitangus-dev/pitangus-worker:0.15 --format '{{json .Provenance}}'
```

En un servidor no hace falta ejecutarlo a mano:

- `make setup PREBUILT=1` y `make up` hacen la misma comprobación (`make verify-images`) sobre las imágenes de la versión que tienes descargada, se niegan a arrancar si falla y escriben el digest verificado en `.env` (`PITANGUS_IMAGE_TAG=0.15@sha256:…`). Cada arranque posterior, `docker compose up` incluido, ejecuta exactamente esa imagen. `make update` comprueba y fija la versión nueva. Sin cosign, `make up` arranca igualmente y avisa de que no se comprobaron las firmas.
- Si construyes desde el código (`make up` sin `PREBUILT`) no hace falta ninguna firma: las imágenes base y los motores van fijados por digest en el repositorio que clonaste, así que descarga una etiqueta `v*` y lee lo que construyes.

## La GitHub Action y el hook de pre-commit

Las dos ejecutan la imagen publicada del worker, y las dos se niegan a ejecutar una imagen que el workflow de release de Pitangus no haya firmado.

- **La GitHub Action** ([`action.yml`](../../action.yml)) resuelve la imagen (por defecto `ghcr.io/pitangus-dev/pitangus-worker:0.15`) hasta su digest, instala cosign con un `sigstore/cosign-installer` fijado, verifica ese digest con la identidad de arriba y ejecuta ese mismo digest. Si la comprobación falla, el paso termina con código 2. `verify: false` se rechaza para la imagen publicada y existe solo para una imagen propia. Para fijarla tú, pasa una `image` que ya lleve digest (`…pitangus-worker:0.15@sha256:…`); se verifica igual. Fija también la Action al commit de una etiqueta de versión, como indican los ejemplos de [Terminal y CI](cli.md).
- **El hook de pre-commit** ([`hooks/pitangus-docker`](../../hooks/pitangus-docker)) trae la imagen escrita como `…pitangus-worker:0.15@sha256:…`, nunca una etiqueta sola. `make pin-hook` reescribe ese digest después de cada versión, tras comprobar la firma con el mismo comando. Con cosign instalado, el hook vuelve a verificar la firma antes de cada ejecución y sale con código 2 si falla; sin cosign, lo dice y ejecuta.

## El pipeline de este repositorio

- **Las acciones de terceros van fijadas por SHA de commit**, con la versión en un comentario (`# v7.0.1`). `tests/test_packaging.py` y `tests/test_action.py` hacen fallar la construcción si algún `uses:` de un workflow o de `action.yml` no es un SHA de 40 caracteres (la única excepción es `./`, el job de CI que prueba la propia Action).
- **Privilegios mínimos.** Todos los workflows empiezan con `permissions: {}` (una prueba lo exige) y cada job pide solo lo que necesita. Todos los checkouts usan `persist-credentials: false`, y en los pasos de shell los valores de los eventos llegan al script por `env:`, nunca interpolados en el comando (`tests/test_action.py` lo comprueba).
- **Pitangus se analiza a sí mismo.** El job de CI «Pitangus on itself» ejecuta los motores del propio producto en cada pull request, zizmor incluido sobre los workflows, y bloquea lo que el cambio introduce desde severidad alta.
- **OpenSSF Scorecard** ([`scorecard.yml`](../../.github/workflows/scorecard.yml)) puntúa el repositorio en dependencias fijadas, permisos del token, protección de ramas y etiquetas, actualización de dependencias y más, en cada push a `main`, cada semana y cuando cambia la protección de ramas. El resultado es público, en la insignia del README y en el [visor de Scorecard](https://scorecard.dev/viewer/?uri=github.com/Pitangus-Dev/pitangus), y los hallazgos van a code scanning. Solo lee el repositorio; no cambia nada.

## Cómo se revisan las actualizaciones

- **Dependabot** ([`dependabot.yml`](../../.github/dependabot.yml)) propone cada semana actualizaciones agrupadas de GitHub Actions, imágenes base y paquetes de Python y npm, e ignora las versiones con menos de 7 días (`cooldown`): una versión secuestrada suele detectarse y retirarse en pocos días. Las actualizaciones de seguridad no esperan.
- **El panel y el sitio de documentación** se instalan con pnpm y unos ajustes de `pnpm-workspace.yaml` que rechazan versiones con menos de una semana (`minimumReleaseAge`), rechazan una versión que pierde la procedencia que tenían las anteriores, bloquean dependencias desde URL de git o de archivos tar y nunca ejecutan los scripts de instalación de las dependencias. Una corrección con menos de una semana entra como excepción para una versión exacta (`minimumReleaseAgeExclude`), con el aviso de seguridad y la fecha en que deja de hacer falta. Mira [Desarrollo](desarrollo.md).
- **Las imágenes de los motores se actualizan a mano**, en un pull request que cambia el digest en `IMAGES` y en el Dockerfile a la vez; a Dependabot se le indica que no las toque para que ambos no se desincronicen, y la prueba de empaquetado falla si lo hacen. No hay una regla automática de antigüedad para ellas: la revisión es el propio pull request, el CI (con el autoanálisis incluido) y la barrera de la publicación descrita arriba. Una regla del repositorio sobre `main` exige pull requests y comprobaciones de estado superadas (es un ajuste del repositorio, así que no está en el código).

## Lo que esto no te da

- Una firma válida dice que la imagen la construyó el workflow de release de Pitangus desde una etiqueta `v*` de este repositorio. No dice que el código no tenga errores. Fijar un motor evita que cambie sin que lo sepas; no vuelve fiable el código del propio motor, y por eso los motores corren sin capacidades, con el sistema de archivos en solo lectura y, donde la plataforma lo permite, sin red ([Seguridad](seguridad.md#análisis-del-código)).
- Las construcciones no son reproducibles bit a bit, y la procedencia es la declaración de BuildKit, no un nivel SLSA reclamado.
- En un portátil el worker sigue usando el socket de Docker, que equivale a root en el host ([concesiones conocidas](seguridad.md#concesiones-conocidas)).
- Una puntuación de Scorecard es una heurística sobre los ajustes del repositorio. Es un indicio, no una garantía.

Para reportar una vulnerabilidad en cualquiera de estas piezas, ve a [SECURITY.es.md](../../.github/SECURITY.es.md).
