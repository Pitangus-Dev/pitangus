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

Engines: Opengrep 1.30.0, Betterleaks 1.9.0, Trivy 0.75.0, OSV-Scanner 2.6.0

BLOCKED · threshold: high or above · 3 new findings at severity high or above
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
| **Betterleaks 1.9.0** | Secretos, con el valor ocultado | Ninguna |
| **Trivy 0.75.0** | Dependencias de cualquier ecosistema, configuración de infraestructura (Dockerfile, Kubernetes, Terraform) y secretos | Solo para descargar sus bases de vulnerabilidades y sus checks de configuración, en caché en `data/trivy-cache/` y refrescados una sola vez para todos los workers cuando toca; no envía nada del repositorio |
| **OSV-Scanner 2.6.0** | Dependencias, contra la base de OSV (que incluye la base de avisos de GitHub); entiende más formatos, como `.csproj` y `Directory.Packages.props` de .NET, `gradle.lockfile`, `uv.lock`, `Pipfile.lock`, `pubspec.lock` | Solo para descargar las bases de OSV, en caché en `data/osv-cache/`; la comparación es local |
| **Checkov 3.3.19** (opcional, apagado por defecto: `PITANGUS_CHECKOV_ENABLED=1`) | IaC (Terraform, CloudFormation, Kubernetes, Helm, Kustomize, ARM, Bicep, Serverless, OpenAPI, Ansible, Dockerfile) y pipelines (GitHub Actions, GitLab CI, Bitbucket, Azure Pipelines, CircleCI, Argo) | Ninguna (`--skip-download`, sin módulos externos) |
| **zizmor 1.30.1** | GitHub Actions a fondo: inyección en plantillas, disparadores peligrosos (`pull_request_target`), permisos del token, acciones sin fijar por SHA o archivadas, credenciales que persisten tras `checkout` | Ninguna (`--offline`) |

La imagen de Opengrep se construye en local con `make build` (o `make up`): descarga el binario oficial y lo
comprueba contra su SHA-256 fijado (`docker/engines/opengrep/VERIFY.md` explica la verificación con Cosign).

**Las reglas de Pitangus.** Las reglas del registro de Semgrep no se pueden incluir en un producto (su licencia es
de uso interno desde diciembre de 2024), así que Pitangus escribe las suyas: 66 reglas dirigidas a sinks concretos
(ejecución de código, SQL, deserialización, HTML sin escapar, TLS sin verificar), 14 de ellas con seguimiento de
datos (taint) desde las entradas de la petición. Cada una tiene sus casos en `rules/tests/`, lo que debe detectar y lo
que debe dejar pasar, y la CI los corre (`make rules-test`) antes de que salga cualquier cambio en una regla. Cada
ejecución dice qué lenguajes del repositorio tienen reglas y cuáles no.

Dos reglas se midieron para la 0.14 sobre un corpus público de 17 aplicaciones (vulnerables a propósito y reales), con
cada coincidencia revisada a mano. `appsec.js.dom-xss-sink` (una variable escrita en `innerHTML`, `outerHTML`,
`document.write` o `insertAdjacentHTML`) viene **desactivada por defecto**: 3 de sus 18 coincidencias eran XSS; el resto
escribía constantes, datos del propio servidor de la aplicación o HTML que ya era seguro. Actívala con
`PITANGUS_SAST_OPT_IN_RULES=appsec.js.dom-xss-sink` ([configuracion.md](configuracion.md)); activada, ya no marca el HTML
de otro elemento, la salida de un sanitizador (`DOMPurify.sanitize`, `….sanitize(…)`) ni una política de Trusted Types
(`policy.createHTML(…)`): 3 de 16. Mientras una regla está desactivada, lo que encontró antes aparece como no comprobado
(regla desactivada), nunca como remediado. `appsec.java.hardcoded-password` sigue activa y ya no marca nombres de dónde
va una credencial o de qué forma tiene (`*_PATH`, `*_PARAM`, `*_HEADER`, `*_REGEX`, una sal…) ni valores que son rutas,
URLs, plantillas, texto o claves de propiedades (`spring.datasource.password`): de 9 de 11 a 9 de 9 en el corpus.

Una coincidencia silenciada con un comentario `nosemgrep` en el código sigue apareciendo, en **Excluidos** con ese
motivo: no queda remediada, y se reabre si el comentario desaparece.

Una coincidencia en código de terceros copiado en el repositorio aparece igual, en **Excluidos** con el motivo "código de
terceros": una carpeta de dependencias (`vendor/`, `third_party/`, `bower_components/`…), una carpeta de librerías entre
los archivos estáticos (`public/lib/`, `static/js/libs/`, `assets/plugins/`), un archivo minificado o uno de al menos
8 KB que empieza con la cabecera de licencia de una librería conocida (su nombre, una versión y una licencia: `jQuery
JavaScript Library v3.7.1`, `Materialize v0.100.1 … MIT License`). La decisión solo mira las carpetas y el contenido del
archivo, nunca su nombre ni la regla que saltó: tu propio `lodash-helpers.js` o `chart-core.js` se analiza como cualquier
otro, y una cabecera tuya (`Acme Portal v2.3.0, Copyright Acme`) no nombra ninguna librería conocida. Todas las
coincidencias de un archivo reciben la misma respuesta. Actualiza la librería en vez de parchearla en su sitio; si un
archivo es tuyo y deja de parecer una librería, sus hallazgos vuelven. Los secretos que aparezcan ahí no se apartan: una
clave dentro de un bundle está igual de expuesta.

**Qué lee cada motor.** Todo lo que está en el repositorio pasa por los escáneres de secretos (Betterleaks y el escáner
de secretos de Trivy), esté en la carpeta que esté y a la profundidad que sea: un token en `src/data/config.js`, en
`build/` o en `vendor/` se encuentra. Solo los metadatos del control de versiones (`.git/`) no se leen nunca. Los demás
motores (Opengrep, los escáneres de dependencias y configuración de Trivy, OSV-Scanner, Checkov, zizmor, el lector de
políticas) dejan fuera dos tipos de carpetas, que van a la copia que solo leen los escáneres de secretos:

- **dependencias**: carpetas en las que los gestores de paquetes instalan o copian (`node_modules/`, `bower_components/`,
  `jspm_packages/`, `site-packages/`, `venv/`, `vendor/`), estén donde estén;
- **generadas**: resultado de compilación (`dist/`, `build/`, `out/`, `target/`, `coverage/`, `htmlcov/`,
  `storybook-static/`, `__pycache__/`) en la raíz del repositorio, junto a un manifiesto de compilación
  (`packages/web/dist/` al lado de `packages/web/package.json`) o con mapas de código (source maps) dentro. En cualquier
  otro sitio (`src/build/`, `src/data/`) una carpeta es código fuente y la leen todos los motores.

El paso de la copia nombra esas carpetas, y cada motor las lista como no analizadas con ese motivo, así que nada de lo que
encontró ahí antes se da por remediado. Opengrep además deja fuera el código de pruebas (carpetas `test/` y `tests/`,
`*_test.go`) a propósito, cada uno listado igual; su propia lista por defecto (que también descartaba `build/`, `dist/`,
`vendor/` y `*.min.js` en cualquier sitio, sin decirlo) queda reemplazada. El nombre de un archivo nunca lo deja fuera: un
archivo minificado sale del SAST por su contenido. El análisis de una carpeta en disco (`pitangus scan`, sin `--commit`
ni `--staged`) deja fuera además lo que las herramientas instalan o usan de caché en esa máquina y nadie sube al
repositorio (`node_modules/`, `venv/`, `site-packages/`, `__pycache__/`…), y dice cuántas. El panel y la CLI muestran
estas carpetas por motor y motivo, no archivo por archivo.

**Lo confirmado es el árbol del commit.** GitHub y GitLab sirven el repositorio tal como lo arma `git archive`: sin lo
que `.gitattributes` marca como `export-ignore`, sin los archivos de un submódulo y con el puntero de un archivo de Git
LFS en lugar del archivo. Por eso la copia se contrasta con el árbol del propio commit (la API del proveedor para ese
commit exacto, o `git ls-tree` para un repositorio local o un commit): cada entrada que la copia no tiene tal como se
confirmó figura como no analizada, con el motivo (`export-ignore` o cualquier otra cosa que el archivo dejó fuera, un
objeto LFS que no se descargó, un submódulo, un enlace simbólico, un nombre con el que no se puede escribir un archivo,
como uno con `\`), y nada de lo que se encontró ahí antes se da por remediado. Una pull request que añade
`secret.py export-ignore` no esconde nada: el archivo figura como no analizado. Una lista de más de 5.000 entradas se
declara por carpeta, nunca se corta.

**Las listas propias de los escáneres de secretos están apagadas.** Betterleaks y Trivy traen listas de rutas que se
saltan sin avisar (`node_modules/`, `vendor/`, lockfiles, pruebas, ejemplos, Markdown, imágenes, `jquery*.js`…).
Pitangus las apaga y aplica solo las suyas: las rutas de tu configuración de detección de secretos, y lo que retiene ahí
se informa como excluido. Los archivos que los demás motores no leen por su nombre (carpetas ocultas como `.vscode/` o
`.pnpm/`, binarios, imágenes, mapas de código) también van a los escáneres de secretos. No se da por hecho que ninguno de
los dos lo haya leído todo: el propio registro de cada uno nombra cada archivo que leyó, y un archivo del repositorio que
no nombró figura como no analizado por ese motor, con el motivo (el motor lo pasó por alto sin leerlo: un binario, un
archivo demasiado pequeño para contener un secreto, lo que haya sido), así que un secreto que vio ahí antes no se da
por remediado. Lo que un motor leyó se juzga por los bytes, no solo por su registro: los motores comparan bytes, así que
un archivo que no es texto UTF-8 (UTF-16, una página de códigos EBCDIC, un binario) figura como no analizado
(`codificación`) aunque el registro lo nombre. Un texto en UTF-16 o UTF-32 (lo que usa PowerShell 5 por defecto) se lee
primero como UTF-8, así que sus secretos se encuentran como los de cualquier otro. Un archivo vacío no tiene nada que leer. Un comentario `gitleaks:allow` (o `betterleaks:allow`) en una
línea es una decisión tuya escrita en el código y se respeta, pero nunca en silencio: cada coincidencia que permite figura
en **Excluidos** con su archivo y línea (nunca su valor), se cuenta en el paso, en las limitaciones del análisis, en la CLI
y en `--format prompt`, y nunca se da por remediada. Lo mismo vale para las entradas de un `.gitleaksignore` o un
`.betterleaksignore` en la raíz del repositorio (huellas de Betterleaks, `ruta:regla:línea`): Pitangus las respeta y
lista cada coincidencia como excluida; Betterleaks nunca carga esos archivos por su cuenta. La misma regla vale para todos
los motores ([Lo que el repositorio les dice a los motores](#lo-que-el-repositorio-les-dice-a-los-motores)).
`PITANGUS_IGNORE_REPO_SUPPRESSIONS=1` ignora los comentarios y esos archivos.
Leer carpetas de dependencias subidas al repositorio lleva más tiempo: unos 35 segundos más para un `node_modules/` de
600 MB con 47.000 archivos, nada para un repositorio sin él.

Los manifiestos y lockfiles entran en la copia por nombre, sin el límite de 2 MB que aplica a los archivos de código
(un `package-lock.json` grande es normal), con un tope de seguridad de 64 MB.

Las dependencias se revisan a partir de lo que resuelve un lockfile (o un manifiesto que fija versiones exactas, como
`pom.xml`, `go.mod` o un `requirements.txt` con `==`). Un hallazgo de dependencias pertenece a la carpeta del proyecto
del archivo del que salió (y a la de cada otro archivo donde se vio), sea cual sea el gestor de paquetes: ninguna lista
de nombres de lockfile lo decide. Un motor examinó una carpeta en un análisis solo si obtuvo al menos un paquete de algún
archivo suyo, y solo da por desaparecido un hallazgo si obtuvo paquetes del mismo archivo del que salió. Así, borrar,
vaciar o reemplazar cualquier lockfile (el de Conan, el de sbt, `renv.lock`, un `requirements.txt` compilado desde
`requirements.in`, uno que nadie conoce) nunca da por remediado lo que se encontró en él mientras su carpeta siga en el
repositorio; borrar la carpeta entera, o actualizar el paquete donde está, sí. Cada motor que vio un hallazgo tiene que
haber vuelto a obtener ese archivo. Un manifiesto que no está vacío y no tiene al lado su lockfile aparece como **sin
examinar (sin lockfile)** en los pasos de Trivy y OSV-Scanner (**lockfile sin paquetes** si el lockfile no dio
ninguno), nunca como cero vulnerabilidades; ese texto nombra los gestores que Pitangus conoce, pero la regla de arriba
vale para todos. Un manifiesto con dependencias que quedaron sin versión resuelta (un POM padre que no se resolvió, un
requisito sin versión fija) tampoco queda examinado. Sube el lockfile y el siguiente análisis lo examina.

Los archivos de credenciales (`.env*`, `.npmrc`, `.pypirc`, `.netrc`, claves SSH con nombre `id_*`, `credentials`,
`.git-credentials`, `.dockercfg`, `.s3cfg`, `.boto`, `.htpasswd`), en cualquier parte del repositorio, nunca entran en la copia que comparten los demás motores: van a una copia aparte que solo leen
Betterleaks y el escáner de secretos de Trivy, y se borra en cuanto terminan. Sus valores no se guardan nunca. Uno
demasiado grande para copiarlo, o uno que un escáner de secretos no pudo leer, figura como no analizado, así que un
secreto visto ahí antes no se da por remediado.

Las contraseñas escritas en el código (la regla `generic-password` de Betterleaks) se revisan por defecto. Un valor
que solo tiene forma de contraseña se descarta: todo lo que está en pruebas, documentación, ejemplos o traducciones;
una referencia o plantilla (`${DB_PASSWORD}`, `{{ password }}`, `process.env.…`, `getenv(…)`); un texto con espacios;
un identificador (`label.password`, `newPassword`; una frase de contraseña como `correct-horse-battery-staple`,
cuatro palabras o más unidas por un mismo `-` o `_`, sí es una contraseña); un valor de relleno (`changeme`,
`postgres`, `xxxx`, `your_password`, un valor igual al nombre de su clave), y un valor débil (menos de 8 caracteres, o
un solo tipo de carácter y menos de 16: la mayúscula inicial no cuenta como tipo y las letras con tilde son letras, así
que `Contraseña2024!` es una contraseña y `Contraseña` no). Cada coincidencia se juzga por su archivo, su línea y su
valor, que se lee y se olvida, nunca se guarda. Lo descartado no es un hallazgo, pero nunca desaparece en silencio: el
paso de Betterleaks y las limitaciones del análisis lo cuentan por motivo. En 18 repositorios públicos el filtro dejó
1525 coincidencias en 23 y conservó las 12 que una revisión independiente marcó como reales; 18 de las 23 son
contraseñas reales o datos de prueba. La otra regla genérica, `generic-credential-uri` (cualquier URL con usuario y contraseña), sigue
apagada: se activa en **Políticas → Detección de secretos**.

Las demás reglas de secretos, de Betterleaks y de Trivy, solo descartan lo que por su forma no puede ser un secreto: una
clave pública por diseño (una clave anon de Supabase, cuyos claims dicen `"role": "anon"`, o una clave
`sb_publishable_`; una clave `service_role` nunca se descarta), un JWT sin firma (`"alg": "none"`), una referencia
(`${TOKEN}`, `<token>`), el nombre de una variable de entorno en lugar de su valor (`Bearer ACCESS_TOKEN`) y un valor de
relleno (`YOUR-ACCESS-TOKEN`, `example`, `...`, una racha de un mismo carácter como `XXXXXXXX` o `T00000000`, o una
secuencia como `12345678`). Un secreto en pruebas, documentación o ejemplos sigue siendo un hallazgo, con prioridad
**atender** en lugar de **actuar ya**: rara vez es el que usa producción, pero rótalo si es real. En el corpus público
(17 repositorios) las reglas por defecto pasaron de 246 coincidencias a 134 sin perder ningún secreto real; de esas 134,
solo 23 siguen en **actuar ya**.

### Lo que el repositorio les dice a los motores

Un repositorio puede pedirle a un motor que informe menos: con un comentario sobre el código que señala o con un archivo
que el motor carga. Pitangus respeta esa decisión, pero nunca en silencio. Cada resultado que alguno de ellos suprime
figura en **Excluidos** con su regla, su archivo y línea y qué lo suprimió (nunca el código), se cuenta en el paso, en
las limitaciones del análisis, en la CLI y en `--format prompt`, y nunca se da por remediado: se reabre si la supresión
desaparece.

| Motor | Comentarios | Archivos |
|---|---|---|
| Betterleaks, Trivy (secretos) | `gitleaks:allow`, `betterleaks:allow` | `.gitleaksignore`, `.betterleaksignore` |
| zizmor | `# zizmor: ignore[regla]` | `.github/zizmor.yml`, `zizmor.yml` (resultados ignorados y auditorías apagadas) |
| Trivy | `trivy:ignore:ID` (archivos de infraestructura) | `.trivyignore` o `.trivyignore.yaml` en la raíz (el YAML si están los dos) |
| Checkov | `checkov:skip=ID`, anotaciones `checkov.io/skip…` | `.checkov.yaml` / `.checkov.yml`: entradas `skip-check`, `check` y `skip-path` que sean rutas simples |
| OSV-Scanner | — | `osv-scanner.toml` en cada carpeta analizada |
| Opengrep | `nosemgrep` | ninguno: tu `.semgrepignore` se reemplaza por la lista propia de Pitangus |

Cómo sabe Pitangus qué se suprimió: zizmor, los comentarios de Checkov, los de Trivy y los archivos de OSV-Scanner se
ejecutan una segunda vez sin las supresiones (`--no-config --no-ignores` en zizmor, una copia de los archivos con los
comentarios desactivados, un `osv-scanner.toml` vacío de Pitangus), solo cuando el repositorio tiene alguna, y lo que
informa solo esa ejecución es lo que ocultaban. Trivy informa por sí mismo lo que suprimió su archivo de exclusiones
(`--show-suppressed`), y Opengrep lo que silencia un comentario `nosemgrep` (`--disable-nosem`). Checkov carga un
`.checkov.yaml` por su cuenta, digan lo que digan sus opciones, así que nunca ve el tuyo: Pitangus aplica él mismo sus
supresiones, y nunca ejecuta una expresión regular que venga del repositorio (un `skip-path` que no sea una ruta simple,
y las severidades, que necesitan la plataforma de Checkov, no suprimen nada). Si falla la ejecución que dice qué se
suprimió, el paso queda parcial y el análisis no da nada por remediado.

`PITANGUS_IGNORE_REPO_SUPPRESSIONS=1` (el nombre anterior, `PITANGUS_SECRETS_IGNORE_INLINE_ALLOW`, sigue funcionando)
hace que ninguno suprima nada: todo resultado se informa como hallazgo.

### Lo que el código escrito con un asistente de IA suele hacer mal

Además de las reglas habituales de inyección y criptografía, algunas reglas apuntan a los fallos más frecuentes del
código generado: una clave `service_role` de Supabase en el código (por lo que dice la clave, un JWT cuyos claims son
`service_role`, no por el nombre de su variable) o leída en un archivo `"use client"`; un secreto, una API key o un
token en una variable con prefijo público (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`…), que el bundler copia
al navegador (`VITE_OPENAI_API_KEY`; no las claves pensadas para el navegador, como la anon de Supabase, una publishable
o la configuración web de Firebase); CORS abierto
a cualquier origen con credenciales (Express, FastAPI, Flask); una ruta sin la autenticación que tienen sus vecinas del
mismo archivo (Express, FastAPI), y un JWT decodificado sin comprobar su firma.

Dos tipos de política de acceso que ningún motor de código lee pasan por un lector pequeño de Pitangus, que declara lo
que leyó como cualquier motor (un archivo que no pudo leer figura como no analizado, nunca como limpio):

- **Migraciones de Supabase** (`.sql` dentro de una carpeta `supabase/`), leídas en orden: una tabla de un esquema que
  sirve la API del proyecto (`public`, o lo que diga `[api] schemas` en su `config.toml`) que termina sin seguridad por
  filas es un hallazgo en su `create table`, identificado por la tabla, así que moverla no lo cambia. Cada carpeta
  `supabase/` es un proyecto aparte: en un monorepo, activar la seguridad por filas de `profiles` en una app nunca cubre
  la `profiles` de otra, y `api.items` no es `public.items`. El `alter table … enable row level security` cuenta desde
  cualquier migración posterior o archivo del mismo proyecto.
- **Reglas de seguridad de Firebase**: en los `.rules` de Firestore y Storage, un `allow` sin condición o con `if true`
  (abierto), solo con una fecha de caducidad (modo de prueba) o, sobre todos los documentos bajo un comodín recursivo
  (`{document=**}`, `{allPaths=**}`), solo con un usuario con sesión (`request.auth != null`, `request.auth.uid != null`
  o una función del archivo que devuelva eso); en los `*.rules.json` de Realtime Database, `.read` o `.write` a `true`,
  solo con una fecha (`now < …`) o, en la raíz, solo con `auth != null`. Las reglas se leen como las lee Firebase, no
  con patrones: el `;` opcional, los espacios, los comentarios y el orden de los bloques no cambian nada, y un
  `database.rules.json` con comentarios `//` se sigue leyendo. Un archivo de reglas cuyas llaves no cuadran, o un
  `*.rules.json` que aun así no es JSON, figura como no analizado (nunca como limpio).

### Varios motores, un hallazgo

**Checkov es opcional** y viene apagado: Trivy y zizmor ya cubren infraestructura y pipelines. Activado, añade casi el
doble de comprobaciones de Terraform y CloudFormation, comprobaciones de Dockerfile y pipelines distintos de GitHub
Actions (GitLab CI, Bitbucket, Azure Pipelines, CircleCI, Argo). Apagado, cada análisis lo muestra como **no ejecutado
(desactivado)**, nunca como limpio, y lo que encontró antes sigue abierto: un motor que no miró no remedia nada.

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
explotarla exige comprometer antes la acción de terceros. Ningún hallazgo guarda código, solo regla, archivo y
líneas: el código se lee del repositorio al abrir el hallazgo ([Tu código nunca se guarda](hallazgos.md#tu-código-nunca-se-guarda)).

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
- **Quién la trae, cuando es transitiva.** Trivy resuelve el grafo de dependencias del lockfile (npm, yarn, pnpm,
  Poetry, uv, Pipenv, Cargo, Go, Composer, NuGet, Bundler, Gradle y más), así que la guía de corrección dice qué
  paquete la requiere y qué dependencia directa está arriba de la cadena, sin importar qué motor reportó el aviso.
- **Si basta con actualizarla a ella.** Algunos lockfiles guardan además el rango que cada paquete acepta para lo que
  requiere (`poetry.lock`, `package-lock.json`, `yarn.lock`, `Gemfile.lock`), y el manifiesto de al lado, los rangos
  del propio proyecto. Se leen mientras el análisis tiene el repositorio y deciden la guía:
  - **El rango rechaza la versión corregida.** FastAPI 0.110.1 solo acepta `starlette>=0.37.2,<0.38.0`, así que
    `poetry update starlette` no cambia nada. La guía lo dice y ordena los comandos: `poetry add fastapi@latest`
    (reescribe el `^0.110.0` que declara `pyproject.toml`; lee las notas de versión de FastAPI), luego `poetry update
    starlette` y después `poetry show starlette` para ver la versión instalada. Con npm también se mueve primero la
    dependencia directa, y un `overrides` queda como último recurso, porque contradice lo que declara el paquete padre.
  - **El rango la acepta.** Basta con actualizar el paquete: `poetry update starlette` o `npm update qs`.
  - **El rango no se conoce** (Cargo, pnpm, uv, Go… o un lockfile que no lo guarda). La guía actualiza el paquete,
    muestra la versión instalada y, si se queda por debajo, actualiza la dependencia directa: por ejemplo `cargo update
    -p rustls-webpki --precise 0.103.13`, luego `cargo tree --invert rustls-webpki` y, si no subió, `cargo update -p
    reqwest`. Go, Maven y Gradle fijan solos la versión de una transitiva; npm, yarn y pnpm reciben un override que
    nombra a quién actualizar en su lugar.
  - **Sin grafo** para ese lockfile: la guía dice que no sabe qué dependencia la trae.

  La guía trabaja con tus lockfiles y los avisos, no con tu código: no puede saber si la nueva versión de la dependencia
  directa rompe algo ni adivinar una versión que aún no existe. Tus pruebas y **Reverificar** cierran el ciclo.
- **Un comando para comprobar el resultado.** `poetry show starlette`, `npm ls qs`, `bundle info rack`…: muestra qué
  versión quedó instalada, antes de que el siguiente análisis lo confirme.

Los paquetes maliciosos conocidos se marcan como **Malicioso**, críticos y Actuar ya, con la corrección real: quitar el
paquete y rotar los secretos de cada máquina donde se instaló. Un paquete es malicioso por el tipo de aviso, sea cual sea
la base de datos y el motor (OSV-Scanner, Trivy o, en imágenes, Grype): un aviso `MAL-*` de OpenSSF (los avisos de
malware del propio GitHub llegan a OSV por ahí) o uno que su base de datos tipifica como malware. Pero muchos avisos de
malware no llevan tipo: las versiones comprometidas anteriores a ese registro (`strong_password` 0.0.7, `bootstrap-sass`
3.2.0.3, `ultralytics` 8.3.41) son, en todas las bases, avisos con CWE-94 o sin CWE. Para esos tienen que coincidir dos
de tres señales: un CWE de código malicioso (CWE-506 y sus variantes), un título que dice que el paquete es malware y una
descripción que lo dice («included a code-execution backdoor», «contained malicious crypto miner software»). Una sola
nunca decide: GitHub etiqueta CWE-509 una fuga de credenciales, y «RCE via a malicious npm package» describe un fallo. En
las bases de OSV de diez ecosistemas (51.582 avisos además de los 239.439 `MAL-*`, octubre de 2026) esto encuentra 625
avisos de malware frente a los 606 de la regla por título que reemplaza: 23 más (gemas con puerta trasera, mineros,
ladrones de credenciales) y 4 menos (una fuga con CWE-509, dos crates retirados solo por su dueño y un aviso de RustSec
cuya descripción no dice lo que dice el título). Es un hallazgo propio, nunca se "actualiza" (no se ofrece versión
corregida).

Los avisos se fusionan como un grafo: sobre la misma versión de un paquete, dos informes que comparten algún nombre
(CVE, GHSA, PYSEC, MAL…) son un solo hallazgo, y también las cadenas de ellos (un PYSEC con alias en un GHSA con alias
en un CVE), sea cual sea el motor que informó cada uno y en el orden que sea. La versión de un paquete malicioso es un
solo hallazgo con todos sus avisos como alias: `ctx` 0.2.6, que OSV informa como `PYSEC-2022-199` y
`GHSA-67r3-h899-9w95` (sin ningún alias en común), es un hallazgo: quitarlo. Igual `ultralytics` 8.3.41, que Trivy
informa como `AQUA-2024-0001` y OSV como `PYSEC-2024-154`. El veredicto sobrevive a cada fusión.

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
- Los dos lados se agrupan en familias y se cuentan sus copias exactamente como lo hace el registro de hallazgos (la
  misma identidad, sea cual sea la versión de Pitangus que analizó la rama de destino), en todo el repositorio: el PR
  introduce tantas instancias como agrega. Pegar una vez más una línea vulnerable introduce una, en el mismo archivo
  o en otro; moverla (dentro de su archivo o a otro), renombrar su archivo, reformatearla o agregarle un comentario
  no introduce ninguna. Un archivo renombrado se empareja con su nombre en la rama de destino por el renombrado que
  informa GitHub (`git diff -M` en la línea de comandos), así que incluso un hallazgo que no lee código (una regla de
  configuración sin recurso) sigue siendo el mismo. El resto es **preexistente**: se reporta aparte y no cuenta
  contra el PR. Sin un análisis previo, cuenta todo lo que caiga en líneas cambiadas, y la revisión lo dice.
  `pitangus scan --base` compara de la misma forma, con la misma función. El registro sigue guardando cada hallazgo
  por archivo: una línea movida a otro archivo es una entrada nueva allí cuando se analiza la rama, y la anterior
  queda remediada.

El resultado es una ejecución más en el panel, con el triage compartido con la rama principal. En GitHub, Pitangus
publica **un solo comentario** que se reescribe en cada push (solo edita comentarios creados por esta App) y un
**estado de commit** `pitangus` que falla si el PR introduce algo en el umbral o por encima. Los secretos se citan
por regla y ubicación; su valor nunca se publica.

Los hallazgos de un PR entran en el registro del repositorio con origen «PR #n». Un commit posterior que lo elimine
lo marca como remediado; un PR cerrado sin merge retira sus hallazgos; un PR fusionado los deja para el siguiente
análisis completo. Una revisión nunca cambia los hallazgos de la rama principal, sus conteos ni sus copias: solo lo
hacen los análisis completos de la rama.

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

- **La capa SAST es la más delgada.** 66 reglas para sinks concretos, sin conocimiento específico de frameworks más
  allá de lo que cubren. Un motor comercial encuentra fallas de lógica que estas reglas no ven.
- **Sin flujo de datos entre archivos.** El seguimiento de datos se queda dentro de un archivo. Cada ejecución lo dice
  en sus limitaciones. Para un análisis profundo, ejecuta tú CodeQL o Semgrep y
  [trae sus resultados](integraciones.md#traer-resultados-de-otros-analizadores): reciben el mismo ciclo de vida.
- **Sin análisis de alcanzabilidad.** Una dependencia vulnerable se reporta tanto si tu código llama a la función
  vulnerable como si no.
- Ni el `.betterleaks.toml` ni el `.gitleaks.toml` del propio repositorio se aplican, para que un PR no pueda debilitar la detección de
  secretos. Las reglas de secretos se ajustan en **Políticas** y por repositorio en **Hallazgos**.

### Limitaciones conocidas en la 0.14

Medidas durante la validación de la versión y todavía sin resolver:

- **`appsec.js.route-without-auth`.** Da falsos positivos cuando un router se monta con autenticación en otro archivo,
  con `addHook('onRequest', …)` de Fastify y con `APIRouter(dependencies=[…])` de FastAPI; se le escapa
  `app.use('/admin', auth)` (autenticación montada en una ruta), y no cubre las rutas de Next.js ni de NestJS.
- **El lector de políticas.** Se le escapan las escrituras protegidas solo con validación de datos, condiciones como
  `if true || …`, las políticas `using (true)` / `with check (true)` y las vistas sobre `auth.users`; marca una tabla
  cuya seguridad por filas se activa dentro de un bloque `DO $$ … $$`.
- **`appsec.js.public-env-secret`.** Se le escapan los nombres `*_KEY` sin `API_`, `process.env["…"]` con corchetes y
  las variables desestructuradas.

## Errores frecuentes

| Lo que ves | Por qué | Qué hacer |
| --- | --- | --- |
| Docker no está disponible: sin SAST, y secretos solo con patrones internos | El worker no llega a Docker | Da acceso a Docker al worker, o usa la imagen del worker que trae los motores ([Contenedores](contenedores.md)). Hasta entonces el SAST no corre y solo corren los patrones de secretos; los pasos lo dicen y el análisis queda incompleto. |
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
