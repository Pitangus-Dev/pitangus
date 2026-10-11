[English](../scanning-code.md) · Español

# Analiza tu código y tus dependencias (SAST, SCA, secretos, IaC)

Un análisis de código lee un repositorio sin ejecutarlo y busca cinco tipos de problemas: fallas en tu propio código
(**SAST**, análisis estático de seguridad de aplicaciones), dependencias con vulnerabilidades conocidas (**SCA**,
análisis de composición de software), secretos subidos por error, configuración de infraestructura riesgosa
(**IaC**, infraestructura como código: Terraform, Kubernetes, Dockerfiles…) y pipelines de CI/CD riesgosos. Cada
resultado es un *hallazgo*: un candidato que confirmas y corriges, no la prueba de una falla explotable. Un resultado
limpio no demuestra que no haya vulnerabilidades. Los términos están explicados en el [glosario](glosario.md).

Pitangus no escribe sus propios motores: ejecuta motores de código abierto conocidos, cada uno fijado por digest, y
reúne sus resultados en un solo registro con triage, plazos y evidencias (consulta
[Hallazgos, triage y corrección](hallazgos.md)).

## Requisitos previos

- Pitangus en marcha ([instalación](instalacion.md) o el [inicio rápido](inicio-rapido.md)), con Docker disponible
  para el worker. Sin Docker solo corre una alternativa reducida (consulta [Errores frecuentes](#errores-frecuentes)).
- Las imágenes de los motores: `make up` construye la imagen de Opengrep y descarga los motores que falten;
  `make engines` solo los descarga.
- Para repositorios de GitHub: la GitHub App instalada en ellos ([Conectar GitHub](github-app.md)). Las carpetas del
  espacio de trabajo del servidor se pueden analizar sin ella.
- Para la terminal: solo `make` y Docker, desde la carpeta de Pitangus.

## Lanzar un análisis desde el panel

1. Haz clic en **Nuevo análisis** (o pulsa `N`).
2. Elige **Código**.
3. En **Repositorios**, elige uno o varios, o la organización completa. A mano puedes elegir hasta 100; una
   organización completa no tiene tope. Varios repositorios corren como un lote, uno tras otro, que puedes seguir y
   cancelar en **Análisis**.
4. Si quieres, en **Contexto**, cuenta qué hace la aplicación y qué te preocupa. Aparece en el informe como nota de
   tu equipo.
5. En **Revisar y lanzar**, comprueba qué se va a ejecutar (los lenguajes con reglas SAST, secretos, dependencias,
   infraestructura). Deja **Consultar dependencias en línea con OSV** apagado salvo que quieras enviar nombres y
   versiones de paquetes (consulta [Hallazgos de dependencias](#hallazgos-de-dependencias)). Lánzalo.

<!-- screenshot: new-scan | El flujo Nuevo análisis en su primer paso, con Código, Imagen de contenedor y Aplicación web o API como tipos de análisis -->

El análisis queda en cola y empieza en cuanto haya un worker libre. Consulta
[Análisis en segundo plano y progreso](#análisis-en-segundo-plano-y-progreso).

## Lanzar un análisis desde la terminal

`make scan` analiza una carpeta local con los mismos motores que el panel. Nunca ejecuta tu código ni lo envía a
ninguna parte:

```bash
make scan DIR=../mi-repo
```

Con `--base` solo cuenta lo que introduce tu cambio, que es lo que necesitas antes de un push o en CI:

```bash
make scan DIR=../mi-repo ARGS="--base main"
```

La salida se ve así (recortada). Sale en inglés salvo que definas `PITANGUS_DEFAULT_LOCALE=es`:

```text
Pitangus · mi-repo · changes since main (merge-base 73223791, 3 files)

CRITICAL app.py:8  Injection: eval exec non literal
HIGH     requirements.txt  urllib3 1.26.4: 9 advisories (5 high, 4 medium) → update to 2.7.0
HIGH     settings.py:1  Exposed GitHub personal access token

Engines: Opengrep 1.30.0, Gitleaks 8.30.1, Trivy 0.75.0, OSV-Scanner 2.6.0

BLOCKED · threshold: high or above · 7 new findings at severity high or above
```

Los códigos de salida son `0` (pasa), `1` (hallazgos en el umbral o por encima), `2` (entrada inválida) y `3` (un
motor no corrió, así que el análisis está incompleto). Todas las opciones, la GitHub Action y GitLab CI están en
[Analizar desde la terminal y en CI](cli.md).

## Motores de análisis

Cada motor corre en su propio contenedor, fijado por digest, sin capabilities, sin escalada de privilegios y con la
copia del código montada en solo lectura.

| Motor | Qué cubre | Red |
| --- | --- | --- |
| **Opengrep 1.30.0** | SAST con las reglas de Pitangus (`rules/`, MIT) para JavaScript, TypeScript, Python, Java, Go, PHP, Ruby y C# | Ninguna |
| **Gitleaks 8.30.1** | Secretos, con el valor ocultado | Ninguna |
| **Trivy 0.75.0** | Dependencias de cualquier ecosistema, configuración de infraestructura (Dockerfile, Kubernetes, Terraform) y secretos | Solo para descargar su base de vulnerabilidades, en caché en `data/trivy-cache/`; no envía nada del repositorio |
| **OSV-Scanner 2.6.0** | Dependencias, contra la base de OSV (que incluye la base de avisos de GitHub); entiende más formatos, como `.csproj` y `Directory.Packages.props` de .NET, `gradle.lockfile`, `uv.lock`, `Pipfile.lock`, `pubspec.lock` | Solo para descargar las bases de OSV, en caché en `data/osv-cache/`; la comparación es local |
| **Checkov 3.3.19** | IaC (Terraform, CloudFormation, Kubernetes, Helm, Kustomize, ARM, Bicep, Serverless, OpenAPI, Ansible, Dockerfile) y pipelines (GitHub Actions, GitLab CI, Bitbucket, Azure Pipelines, CircleCI, Argo) | Ninguna (`--skip-download`, sin módulos externos) |
| **zizmor 1.30.1** | GitHub Actions a fondo: inyección en plantillas, disparadores peligrosos (`pull_request_target`), permisos del token, acciones sin fijar por SHA o archivadas, credenciales que persisten tras `checkout` | Ninguna (`--offline`) |

La imagen de Opengrep se construye en local con `make build` (o `make up`): descarga el binario oficial y lo
comprueba contra su SHA-256 fijado (`docker/engines/opengrep/VERIFY.md` explica la verificación con Cosign).

**Las reglas de Pitangus.** Las reglas del registro de Semgrep no se pueden incluir en un producto (su licencia es
de uso interno desde diciembre de 2024), así que Pitangus escribe las suyas: 58 reglas dirigidas a sinks concretos
(ejecución de código, SQL, deserialización, HTML sin escapar, TLS sin verificar), 14 de ellas con seguimiento de
datos (taint) desde las entradas de la petición. Se validan contra `fixtures/sast-samples/`, donde las 58 se activan
con código vulnerable. Cada ejecución dice qué lenguajes del repositorio tienen reglas y cuáles no.

Los manifiestos y lockfiles entran en la copia por nombre, sin el límite de 2 MB que aplica a los archivos de código
(un `package-lock.json` grande es normal), con un tope de seguridad de 64 MB.

### Varios motores, un hallazgo

Trivy y Checkov revisan la misma infraestructura y se solapan en muchas reglas, igual que Checkov y zizmor en GitHub
Actions. Cuando dos motores ven **el mismo problema en el mismo sitio** (mismo archivo, líneas que se solapan, regla
equivalente), queda un solo hallazgo: el del motor principal, marcado «Detectado por Trivy y Checkov», con las reglas
equivalentes a la vista y un punto más de confianza. Lo que ve un solo motor se agrega tal cual.

| Cobertura | Principal | Suma |
| --- | --- | --- |
| Infraestructura como código | Trivy | Checkov |
| GitHub Actions y otros pipelines | zizmor | Checkov |
| Configuración de imágenes | Reglas de Pitangus | Trivy y Checkov |

La equivalencia de reglas es una tabla medida sobre repositorios de referencia vulnerables a propósito (TerraGoat,
CfnGoat, KubernetesGoat y CI/CD-Goat) y revisada par a par; si la tabla no conoce un par, se comparan los títulos.
En esos repositorios, Checkov suma entre un 39 % más de problemas (Kubernetes) y más del doble (Terraform) sobre lo
que ya encuentra Trivy:

| Repositorio | Trivy | Checkov | Fusionados | Nuevos de Checkov | zizmor |
| --- | --- | --- | --- | --- | --- |
| TerraGoat (Terraform) | 244 | 472 | 196 | 276 | 13 |
| KubernetesGoat (Kubernetes, Helm) | 321 | 349 | 225 | 124 | 0 |
| CfnGoat (CloudFormation) | 67 | 70 | 42 | 28 | 9 |
| CI/CD-Goat (pipelines) | 45 | 90 | 69 | 21 | 209 |

La edición gratuita de Checkov no da severidad. En las reglas emparejadas con Trivy se usa la de Trivy; en el resto,
una regla en el código (`checkov_severity`) sube a alta la exposición pública, los privilegios, las credenciales o el
TLS desactivado, baja a baja las etiquetas, la monitorización, las copias de seguridad o las claves gestionadas por el
cliente, y deja todo lo demás en media. zizmor sí da severidad; «acción sin fijar por SHA» baja a media, porque
explotarla exige comprometer antes la acción de terceros. Los hallazgos de Checkov y zizmor no guardan fragmentos de
código, solo regla, archivo y líneas, porque el fragmento podría contener un secreto.

Con las dependencias pasa lo mismo: un aviso que reportan Trivy y OSV-Scanner, aunque uno lo nombre por su CVE y el
otro por su GHSA, es **un solo hallazgo** «detectado por Trivy y OSV-Scanner», con la misma huella que le daría
cualquiera de los dos por separado, así que el triage y los tickets lo siguen.

## Hallazgos de dependencias

Las **dependencias de desarrollo** (`devDependencies`, grupos de desarrollo) también se analizan y se marcan como
**Dependencia de desarrollo**: no llegan a producción, pero se ejecutan en las máquinas del equipo y en CI, que es
justo donde golpean los ataques a la cadena de suministro. Bajan un nivel de prioridad salvo que estén en CISA KEV.

Cada aviso de dependencia llega listo para decidir:

- **Detalles del aviso.** Resumen, alias CVE y GHSA, CWE (el tipo de debilidad) y el vector CVSS; la puntuación CVSS
  se calcula a partir del vector con la fórmula 3.1, no se copia.
- **Versión corregida.** Se elige del rango que contiene la versión instalada: quien está en `minimatch 9.0.5` lee
  «actualiza a 9.0.6», no «a 10.2.3». El panel agrupa los avisos por paquete y dice qué versión los corrige todos.
- **Señales de explotación.** Dos fuentes públicas descargadas en bloque una vez al día en `data/feeds/`: el
  catálogo **CISA KEV** (vulnerabilidades que se sabe que se explotan) y **EPSS** (la probabilidad de explotación en
  los próximos 30 días). Nadie recibe consultas CVE por CVE que revelen qué dependencias tienes.
- **Prioridad con sus motivos a la vista.** **Actuar ya** si está en KEV o combina CVSS ≥ 9 con un EPSS alto; si no,
  **Atender** o **Seguir**. El hallazgo dice por qué.
- **Una huella estable**, independiente de la ruta del lockfile, para que el mismo aviso no aparezca como hallazgo
  nuevo (ni como ticket duplicado) en cada ejecución.

Los paquetes maliciosos conocidos (avisos `MAL-*` de OpenSSF, vía OSV) se marcan como **Malicioso**, críticos y
Actuar ya, con la corrección real: quitar el paquete y rotar los secretos de cada máquina donde se instaló.

### La consulta en línea a OSV (opcional)

Por defecto, la lista de dependencias no sale del servidor: Trivy y OSV-Scanner descargan sus bases y comparan en
local. **Consultar dependencias en línea con OSV** en el panel, o `--allow-osv-upload` en la CLI, permite enviar
**solo nombres y versiones de paquetes** (nunca código):

- Con los motores disponibles, permite que OSV-Scanner resuelva dependencias transitivas de manifiestos sin lockfile
  (consulta deps.dev). Sin el permiso, solo compara lo que declaran los manifiestos y lockfiles.
- Sin Docker, es la única forma de revisar dependencias (contra `api.osv.dev`). Sin el permiso, el paso de
  dependencias aparece como **No probado**, nunca como cero vulnerabilidades.

```bash
make scan DIR=../mi-repo ARGS="--allow-osv-upload"
```

Qué sale del servidor y cuándo está en [Seguridad](seguridad.md).

## Avisos nuevos sin reanalizar

Cada análisis guarda sus dependencias con sus versiones. Una vez al día (`PITANGUS_ADVISORY_WATCH_HOURS`, `24` por
defecto, `0` lo apaga) se comparan con la base de OSV actualizada usando OSV-Scanner **sin conexión**: se descargan los
avisos y la lista de dependencias se queda en el servidor. Lo que el registro no conocía se abre como una ejecución
**Avisos nuevos** que solo agrega hallazgos; el siguiente análisis completo tiene la última palabra. Los paquetes del
sistema operativo de las imágenes de contenedor se revisan cuando la imagen se vuelve a analizar.

## Revisión de pull requests

Con la GitHub App, Pitangus revisa cada pull request (PR) por lo que **introduce**, no por lo que ya estaba. No hay
webhooks, así que el servidor no necesita ser accesible desde internet.

### Actívala

En **Pull requests**, un administrador configura por repositorio:

- **Vigilancia activa**: enciende el repositorio en **Repositorios vigilados** (o **Vigilar todos los repositorios**). Un vigilante
  consulta cada `PITANGUS_PR_POLL_SECONDS` (300 s por defecto, 60 como mínimo) y encola una revisión por cada commit
  nuevo en la cabeza del PR. Los borradores se omiten. **Revisar ahora** revisa un PR a mano; **Reanalizar** revisa
  otra vez su último commit.
- **Ramas de destino**: solo se revisan los PR hacia estas ramas (la rama por defecto si no hay ninguna; hasta 10).
- **Comentar y marcar el commit en GitHub**: publica el resultado en el PR (activado por defecto).
- **Umbral de bloqueo**: **Crítica**, **Alta o superior** (por defecto), **Media o superior** o **Nunca bloquear**.
- **Reanalizar las ramas de destino cuando cambien**: tras un merge, la rama se analiza otra vez para que la
  comparación no quede desactualizada; como mucho una vez cada `PITANGUS_BRANCH_MIN_MINUTES` (60 min) por rama, y solo
  con la cola casi vacía, para que los análisis manuales y las revisiones de PR no esperen detrás.

La App necesita **Pull requests: Read and write** y **Commit statuses: Read and write**, que la guía de
configuración ya incluye. Si cambias los permisos de una App existente, acepta la actualización en GitHub
(*Settings → Applications → Installed GitHub Apps*); mientras tanto, el panel dice qué permiso falta.

### Qué cuenta como introducido

La revisión analiza el commit de cabeza del PR con los mismos motores y luego filtra:

- Un hallazgo de código o de secreto cuenta si cae en una línea que el diff agrega o modifica. Uno de dependencia
  cuenta si el PR toca el manifiesto o lockfile que la declara.
- Si su huella ya estaba en el último análisis de la rama de destino, es **preexistente**: se reporta aparte y no
  cuenta contra el PR. Sin un análisis previo, cuenta todo lo que caiga en líneas cambiadas, y la revisión lo dice.

El resultado es una ejecución más en el panel, con el triage compartido con la rama principal. En GitHub, Pitangus
publica **un solo comentario** que se reescribe en cada push (solo edita comentarios creados por esta App) y un
**estado de commit** `pitangus` que falla si el PR introduce algo en el umbral o por encima. Los secretos se citan
por regla y ubicación; su valor nunca se publica.

Los hallazgos de un PR entran en el registro del repositorio con origen «PR #n». Un commit posterior que lo elimine
lo marca como remediado; un PR cerrado sin merge retira sus hallazgos; un PR fusionado los deja para el siguiente
análisis completo.

## Análisis en segundo plano y progreso

Lanzar un análisis responde al instante y lo deja en cola. Uno o varios workers toman los análisis de la cola, cada
uno de a uno ([Escalar](escalar.md)). Mientras corre, aparece en **Análisis** como en cola o en curso, con un registro
del análisis escrito para personas: qué paso empezó, cuál terminó y con cuántos resultados. El panel lo muestra en
vivo y lo pliega al terminar. Nunca incluye rutas internas, salida cruda de las herramientas ni trazas; si algo
falla, dice en qué fase y da el ID para que un operador revise los logs. Al terminar, el panel muestra un aviso (y una
notificación del navegador, si diste permiso).

Cada motor es un paso con un estado: **Completado**, **Parcial**, **No probado**, **Inconcluso** u **Omitido**, con el motivo. Un
motor que no corrió nunca se muestra como «cero hallazgos»: la ejecución queda marcada como incompleta.

## Lo que no hace

- **La capa SAST es la más delgada.** 58 reglas para sinks concretos, sin conocimiento específico de frameworks más
  allá de lo que cubren. Un motor comercial encuentra fallas de lógica que estas reglas no ven.
- **Sin flujo de datos entre archivos.** El seguimiento de datos se queda dentro de un archivo. Cada ejecución lo dice
  en sus limitaciones. Para un análisis profundo, ejecuta tú CodeQL o Semgrep y
  [trae sus resultados](integraciones.md#traer-resultados-de-otros-analizadores): reciben el mismo ciclo de vida.
- **Sin análisis de alcanzabilidad.** Una dependencia vulnerable se reporta tanto si tu código llama a la función
  vulnerable como si no.
- El `.gitleaks.toml` del propio repositorio no se aplica, para que un PR no pueda debilitar la detección de
  secretos. Las reglas de secretos se ajustan en **Políticas** y por repositorio en **Hallazgos**.

## Errores frecuentes

| Lo que ves | Por qué | Qué hacer |
| --- | --- | --- |
| Docker no está disponible y solo se usan las reglas internas (solo Python) y los patrones de secretos | El worker no llega a Docker | Da acceso a Docker al worker, o usa la imagen del worker que trae los motores ([Contenedores](contenedores.md)). Hasta entonces solo corren el SAST de Python y los patrones de secretos, y los pasos lo dicen. |
| La imagen de Opengrep no está construida | Falta la imagen SAST que se construye en local | Ejecuta `make build` o `make up`. |
| El paso de dependencias aparece como **No probado** | No hay motores y no se permitió la consulta a OSV | Pon los motores a disposición o permite la consulta a OSV en ese análisis. |
| OSV-Scanner superó el tiempo límite | La primera ejecución descarga las bases de avisos | Vuelve a lanzar el análisis cuando termine la descarga. |
| `make scan` sale con `3` | Un motor no corrió, así que el resultado no demuestra nada | Revisa las líneas «Not analyzed»; usa `--allow-incomplete` solo si lo aceptas. |
| Un PR no muestra comentario en GitHub | La App no tiene permisos de escritura | Da acceso de escritura a **Pull requests** y **Commit statuses** y acepta la actualización. |

Más en [Solución de problemas](solucion-problemas.md).

## Siguientes pasos

- [Hallazgos, triage y corrección](hallazgos.md): qué hacer con los resultados.
- [Analiza imágenes de contenedor](analisis-de-imagenes.md).
- [Analizar desde la terminal y en CI](cli.md).
- [Evidencias de cumplimiento](cumplimiento.md): SBOM y VEX a partir de tus análisis.
- [Integraciones](integraciones.md): importar SARIF de otras herramientas, Jira, Slack y Teams.
