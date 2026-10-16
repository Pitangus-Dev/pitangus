[English](../findings.md) · Español

# Hallazgos, triage y corrección

Cada análisis, revisión de pull request e importación alimenta un **registro** por activo (un repositorio, una imagen
o un dominio verificado). El registro guarda el estado actual de cada hallazgo, decide por sí solo qué se corrigió y
qué volvió, y anota lo que tu equipo decidió sobre cada uno (el **triage**: confirmarlo, descartarlo como falso
positivo, aceptar el riesgo, marcarlo como remediado). Esta página explica cómo leer los resultados, cómo trabajarlos
y cómo exportarlos. Términos como huella, triage, KEV o SARIF están explicados en el [glosario](glosario.md).

## Requisitos previos

- Al menos un análisis terminado: de código ([Analiza tu código](analisis-de-codigo.md)), de una imagen
  ([Analiza imágenes de contenedor](analisis-de-imagenes.md)) o de un sitio ([Analiza un sitio web o una API](analisis-web.md)),
  o un SARIF importado de otra herramienta ([Integraciones](integraciones.md)).
- Cualquier usuario puede leer los hallazgos y hacer triage. Aceptar un riesgo, las rutas excluidas, los plazos y
  reverificar un hallazgo web quedan para los administradores.

## El tablero Resumen

**Resumen** (`#/overview`) reúne todos los activos de los últimos 7, 30 o 90 días o del último año. Sus cifras tienen
definiciones explícitas:

- **Abiertos**: lo que aparece en la última ejecución de cada activo.
- **Corregidos**: una huella que estaba en una ejecución anterior de ese activo y ya no aparece (con la tasa de
  corrección).
- **Tiempo de corrección**: desde la primera detección hasta que el hallazgo desaparece.
- **Fuera de plazo**: hallazgos abiertos que pasaron su [plazo de corrección](#plazos-de-corrección).
- **En CISA KEV**: hallazgos abiertos que se explotan activamente en algún lugar.
- **Puntuación**: un resumen que se muestra junto a su fórmula, `100·e^(−riesgo/150)`, donde el riesgo pondera los
  hallazgos abiertos por severidad, KEV y EPSS. Baja con lo abierto, más con críticos y KEV. No es una certificación.

Los paneles muestran los hallazgos nuevos por día según severidad, los abiertos por severidad, hallados frente a
corregidos, los tipos de debilidad (CWE) más comunes, la explotabilidad (hallazgos en KEV o con EPSS ≥ 10 %), los
activos más afectados, los hallazgos de mayor prioridad, las ejecuciones recientes y un año de actividad de análisis.
**Novedades en ciberseguridad** lista los CVE publicados en NVD en los últimos 7 y 30 días y las últimas altas en
CISA KEV; un CVE lleva la marca **te afecta** cuando nombra como producto afectado un paquete de tus hallazgos
abiertos, o es uno de sus CVE.

<!-- screenshot: overview | El tablero Resumen con la puntuación, los hallazgos abiertos y fuera de plazo, y gráficas de hallazgos nuevos y corregidos de los últimos 30 días -->

## Leer los hallazgos

**Hallazgos** (`#/findings`) abre un activo a la vez: elígelo arriba. Puedes ver su **Estado actual** (análisis, PR e
importaciones combinados) o una ejecución concreta. Las pestañas separan **Abiertos**, **Remediados** y
**Excluidos**.

- **Tarjetas**: fuera de plazo, críticas, altas, en CISA KEV y con corrección, contadas sobre los pendientes.
- **Filtros**: búsqueda (paquete, CVE, archivo…), severidad y **Más filtros**: estado, prioridad, origen
  (dependencias, código, infraestructura, pipelines de CI/CD, secretos, web) y plazo.
- **El detalle** de un hallazgo dice qué es, dónde está, cómo corregirlo (con un ejemplo de antes y después cuando
  lo hay), su prioridad y por qué, su ciclo de vida (cuándo se vio por primera y última vez, de dónde viene) y su
  historial de triage. Los de dependencias agregan la versión corregida, CVSS, EPSS y KEV
  ([Hallazgos de dependencias](analisis-de-codigo.md#hallazgos-de-dependencias)).

<!-- screenshot: findings | La tabla de hallazgos de un activo, con columnas de severidad, prioridad y plazo, y un problema web agrupado sobre varias URL -->

### Los hallazgos web se agrupan por problema

En los hallazgos de un sitio, el mismo problema en varias URL es una fila que se despliega en cada URL, y la tabla
dice, por ejemplo, «15 hallazgos en 8 problemas». Cada URL sigue siendo su propio hallazgo, con su triage y su
historial, y las cifras las cuentan una por una. Los informes técnicos (PDF y Markdown) agrupan igual; la evidencia
de auditoría mantiene una fila por URL. El detalle de un hallazgo web muestra además lo que reportaron las otras
herramientas que lo vieron (**También lo reportaron**). Consulta [Analiza un sitio web o una API](analisis-web.md).

## Cómo nace y muere un hallazgo

Cada hallazgo tiene una **huella** (fingerprint): un identificador estable construido a partir de qué es y dónde está,
para que el mismo problema en la siguiente ejecución se reconozca como el mismo hallazgo. El registro se actualiza
solo desde cuatro fuentes:

| Fuente | Qué hace |
| --- | --- |
| **Análisis completo** del activo | Lo que aparece queda abierto, y se reabre si estaba remediado. Lo que estaba abierto y ya no aparece queda **remediado automáticamente**. |
| **Revisión de PR** | Lo que introduce el PR queda abierto con origen «PR #n». Un commit posterior del PR que lo elimine lo remedia; un PR cerrado sin merge retira sus hallazgos; un PR fusionado los deja para el siguiente análisis completo. |
| **Importación de otra herramienta** (SARIF 2.1.0 de Semgrep, CodeQL, Snyk, Trivy, Strix, ZAP, Nuclei…) | Sus hallazgos se abren con el nombre de la herramienta como origen, en un activo que Pitangus ya conoce. Una importación **completa** posterior de la **misma herramienta** remedia lo que ya no reporta; una **parcial** solo abre y actualiza. Los análisis de Pitangus nunca remedian un hallazgo importado, y una importación nunca remedia los suyos. |
| **Triage** | Lo que decide tu equipo (siguiente sección). |

Las huellas están pensadas para resistir los cambios normales:

- Los secretos, los hallazgos de código de Opengrep y los de GitHub Actions de zizmor conservan su huella cuando se
  agregan líneas por encima, para que no parezcan remediados y nuevos a la vez. Un hallazgo en el historial de
  construcción de una imagen se reconoce por el comando del paso, no por su posición.
- Un secreto se identifica por su valor, leído donde dijo su motor y solo si todo lo que el motor dijo de él se
  cumple allí (Betterleaks: su coincidencia redactada, su longitud y la entropía del valor; Trivy: su posición desde el
  principio del archivo y el texto que enmascaró alrededor, línea a línea en una clave de varias líneas) y se cumple
  para un único valor. Las columnas de Betterleaks solo cuentan en un archivo que lee de una vez (hasta 100 KB): más allá
  puede contarlas desde la mitad de cualquier línea (un bundle minificado, un archivo largo), así que ahí el valor debe
  ser el único que encaja en toda su línea. Si el valor no se puede leer así, el secreto queda *sin enlace*: se nombra por su regla, su archivo y el
  contenido de sus líneas (con los saltos de línea normalizados), nunca solo por su regla y su sitio. El mismo
  contenido da el mismo nombre y cualquier cambio da otro; nunca hereda el triaje de lo que había antes, y no se marca
  como remediado mientras su motor siga encontrando en su archivo un secreto de la misma regla, u otro motor que lo vio
  encuentre allí uno (queda abierto, sin verificar). Tampoco un secreto nombrado por su valor mientras un motor que lo
  vio encuentre en su archivo uno cuyo valor no se pudo leer.
- Un aviso de dependencia tiene una sola huella, lo reporte el motor que lo reporte y lo nombre como lo nombre. Cuando
  un aviso conocido por su GHSA recibe un CVE, el hallazgo sigue siendo el mismo. Trivy y Grype coinciden en el nombre
  de un paquete en las imágenes (el `grupo:artefacto` de un paquete Java, el `go1.22.1` de una versión de Go), y dos
  reportes que antes eran hallazgos separados se unen en uno en vez de marcar uno de ellos como remediado.
- Los hallazgos de versiones que calculaban las huellas de otra forma conservan su estado, triage, issue de Jira y
  verificación pendiente en el siguiente análisis.

La identidad de un repositorio es su identidad en GitHub (su ID numérico): un repositorio renombrado sigue siendo el
mismo. Si GitHub deja de dar acceso a un repositorio (se borró o se quitó de la App), el panel lo avisa; si el acceso
no vuelve en 24 horas, sus hallazgos, triage y tickets enlazados se borran.

Un análisis en el que algún motor no corrió queda **incompleto**: no marca nada como remediado, porque «no visto» no
es «desaparecido». Por la misma razón, un análisis completo no remedia un hallazgo en un archivo que no analizó: uno que
quedó fuera de la copia por su tamaño, o uno que se saltó el motor que reporta el hallazgo (los archivos de más de 2 MB
para Opengrep, por ejemplo).

Una coincidencia de SAST silenciada en el código con un comentario `nosemgrep` aparece en **Excluidos** con ese motivo,
nunca como remediada. Se reabre si el comentario desaparece, y se remedia cuando ya no está el código que señalaba.
Una coincidencia de SAST en código de terceros copiado en el repositorio (una librería, un archivo minificado) queda
excluida igual, con ese motivo.

## Prueba antes de remediar

Un hallazgo se marca como remediado solo cuando el motor dueño probó, en un análisis que funcionó, que miró donde
estaba. `PITANGUS_COVERAGE_MODE` decide con qué rigor ([configuracion.md](configuracion.md)): `on` por defecto, que
aplica todas las reglas de abajo; `shadow` guarda lo que cambiarían y remedia como antes de 0.14.

- **El contrato de los motores.** Cada ejecución de un motor debe terminar con un código de salida que use para una
  ejecución que leyó lo que debía y una salida que sea el JSON que siempre escribe, con la marca que escribe cuando
  corrió. Cualquier otra cosa (un fallo, una salida vacía o truncada, `null`, un objeto de error, un timeout) significa
  que la ejecución no terminó, en cualquier modo: el motor no abre nada a partir de ella ni remedia nada de lo que vio
  antes.
- **Cobertura por archivo o página.** Cada motor dice qué unidades examinó y cuáles no, y por qué: un archivo en el que
  Opengrep agotó el tiempo, un lockfile o archivo de infraestructura que Trivy u OSV-Scanner no pudieron leer, un archivo
  que Checkov no pudo parsear, un workflow que zizmor no terminó, archivos de credenciales que un escáner de secretos no
  pudo leer, una página cuya propia herramienta recibió un estado que no prueba nada (cualquiera
  distinto de un 2xx, un 404 o un 410; para ZAP, distinto de un 2xx; para un hallazgo de nuclei sobre una ruta, distinto
  de un 404 o un 410). Solo esa unidad queda sin examinar; el resto de la ejecución del motor
  sigue contando, también cuando el motor terminó **parcial**. Solo un motor que falló o rompió su contrato queda ciego
  del todo. Un manifiesto cuyas dependencias Trivy no pudo resolver (un repositorio remoto que rechaza un `pom.xml`
  padre, lo que detiene toda la ejecución de Trivy) queda sin examinar solo en dependencias: Trivy vuelve a correr sin
  resolución remota, resuelve cada uno de esos manifiestos por separado, y sus archivos de infraestructura, sus secretos
  y los demás manifiestos siguen contando. También quedan sin examinar en dependencias, y el paso los nombra: un
  manifiesto cuyos paquetes salieron sin versión resuelta (un `pom.xml` padre o una propiedad que no se resolvió, que
  Trivy reporta con código de salida 0 y OSV-Scanner sin avisar, o un requisito sin versión fija con `==`, que ninguno
  revisa), con cada paquete contado; un manifiesto que no está vacío y no tiene al lado un lockfile que el motor lea
  (`build.gradle` sin `gradle.lockfile`, `package.json` sin lock o solo con el `bun.lockb` binario, `Pipfile`,
  `pyproject.toml`, `Gemfile`, `composer.json`, `Cargo.toml`…), declare lo que declare. Sea cual sea el gestor de
  paquetes, un hallazgo de dependencias vive en la carpeta del proyecto de cada archivo donde se vio: un motor examinó
  esa carpeta solo si obtuvo un paquete de algún archivo suyo en ese análisis, y solo da por desaparecido el hallazgo si
  obtuvo paquetes del archivo del que salió, así que un aviso reportado en un lockfile que se borró, se vació, se
  reemplazó o quedó sin paquetes nunca se remedia mientras su carpeta siga en el repositorio, y uno visto en varios
  lockfiles espera a todos; y un manifiesto o lockfile en una codificación que el motor no lee. Una carpeta que ya no
  está en el repositorio no tiene nada: lo que salió de ella se remedia.
- **Cada motor que vio un hallazgo tiene que volver a mirar.** Un hallazgo que reportaron dos motores (Betterleaks y
  Trivy, Trivy y OSV-Scanner, Trivy y Checkov) solo se remedia cuando los dos, y cualquier motor que lo vio en un
  análisis anterior, examinaron su archivo en este. Uno que no corrió, falló o pasó por alto el archivo lo deja abierto.
- **Lo que el commit tiene y la copia no.** Un archivo que `.gitattributes` marca como `export-ignore`, un objeto LFS que
  no se descargó, un submódulo, un enlace o un nombre con el que no se puede escribir un archivo figura como no analizado
  para todos los motores (ver [Análisis de código](analisis-de-codigo.md)): que el archivo del proveedor lo deje fuera
  no remedia nada de lo que se encontró ahí.
- **La configuración nunca remedia.** Cada análisis guarda qué motores estaban activos y qué reglas aplicó cada uno, con
  un resumen de lo que detecta cada regla. Un hallazgo solo se remedia en un análisis en el que corrió la regla que lo
  encontró, sin cambios desde la última vez que se vio, con su motor activo. Desactivar una regla (una regla opcional,
  una regla personalizada que se quita, las reglas de terceros), apagar un motor opcional (Checkov, Grype) o actualizar
  una regla deja lo que encontró como **Sin comprobar (configuración)**, con cualquier `PITANGUS_COVERAGE_MODE`; el
  detalle del hallazgo dice qué regla o qué motor. Un secreto que una entrada de la lista de permitidos o una regla
  desactivada empieza a filtrar queda excluido con ese motivo, nunca remediado. Los hallazgos guardados antes de la 0.14
  cuentan como vistos con las reglas de la 0.13.1.
- **Sin verificar.** Un hallazgo abierto que un análisis no pudo comprobar sigue abierto, marcado **Sin verificar desde**
  el primero de esos análisis, y no cuenta en ningún plazo ni indicador. Tras `PITANGUS_UNSEEN_WARN_SCANS` análisis la
  página del activo avisa (enseguida si el motivo es la configuración). Nunca se remedia solo; volver a verlo quita la
  marca.
- **La retención de remediados.** Un análisis que remediaría al menos `PITANGUS_FIX_HOLD_PERCENT` de los hallazgos
  abiertos de un activo, y al menos `PITANGUS_FIX_HOLD_MINIMUM`, retiene sus remediados y lo dice una vez en la página del
  activo, con el motivo: cuántos habría remediado de cuántos abiertos. El siguiente análisis completo que pruebe las
  mismas ausencias los aplica; quien administra puede marcarlos como remediados al momento (**Marcar como remediados**).
  Las aperturas nunca se retienen.
- **Nada sin probar sale fuera.** Jira recibe el comentario de remediado, y los canales de notificación un hallazgo,
  solo por lo que un análisis probó: un hallazgo retenido o sin verificar no envía nada.
- **Salud.** `GET /api/findings/health` cuenta lo que hace dudar de los remediados: hallazgos que vuelven antes de 30
  días, análisis que remediaron mucho más de lo habitual, hallazgos abiertos que varios motores reportan por separado,
  hallazgos sin verificar y la parte de motores ciegos en el último análisis de cada activo.

## Tu código nunca se guarda

**Pitangus no guarda el texto de tu código: guarda la ubicación, la regla y hashes; el fragmento se muestra al abrir el
hallazgo, leído del repositorio en ese momento y sin los secretos.**

- **Lo que se guarda** de un hallazgo de código, configuración, CI/CD o secretos: su ruta, sus líneas (y las columnas
  del valor de un secreto), el commit que leyó su análisis, su regla, metadatos estructurales (severidad, CWE, la
  dirección del recurso, los motores que lo vieron) y hashes (su huella e identidad, la identidad con clave de un
  secreto). Nunca un fragmento, ni el snippet o la región de contexto de un SARIF importado, ni el YAML al que apunta un
  hallazgo de zizmor, ni el mensaje de un motor que cita el código: una regla de Opengrep sin texto de corrección propio
  recibe una frase que nombra la regla, y una comprobación de configuración de Trivy se describe con su propia
  descripción, nunca con su mensaje.
- **Al abrir un hallazgo**, el panel pide su código (`GET /api/findings/code`, para quien puede leer el hallazgo):
  Pitangus lee el archivo del proveedor en el commit analizado, con la conexión que ya tiene (la GitHub App o el
  token), y devuelve las líneas de alrededor. En el servidor nunca se guarda, ni se cachea, ni se registra; el panel lo
  conserva solo mientras el detalle está abierto. Al lado, **Abrir en GitHub** enlaza al archivo en ese commit.
- **Los secretos siguen ocultos también ahí.** Cada sitio que un motor de secretos señaló en ese archivo se enmascara
  antes de que las líneas salgan del servidor: un valor con columnas conocidas para ese commit se sustituye y el resto de
  la línea se conserva; un secreto visto en otro commit, o sin columnas, oculta su línea entera, y una clave privada su
  bloque entero. El hallazgo de un secreto, o una debilidad cuyo código es una credencial (CWE-798, 259, 321, 522), no
  muestra código, solo dónde está.
- **Cuando el código no se puede mostrar**, el detalle dice por qué: el repositorio ya no es accesible con la conexión de
  Pitangus, el commit ya no tiene el archivo, el análisis no guardó su commit, o era una carpeta local (el servidor
  nunca lee una: abre el archivo en tu editor).
- **Lo que sale de Pitangus tampoco lleva código**: las incidencias de Jira y el informe Markdown enlazan al archivo en
  el commit analizado, los comentarios de pull request están sobre las líneas, las notificaciones y los informes PDF
  dan la ubicación, y la exportación SARIF no lleva fragmento.

Lo que las herramientas escriben sobre lo que leen sigue siendo texto, no código: el mensaje o el error de un motor, el
detalle de un paso, la evidencia de un escáner web (lo que respondió un sitio en vivo: no hay repositorio del que
leerlo después) y su ataque. Ese texto pasa por un único renderizador antes de guardarlo, mostrarlo o enviarlo. Conserva
la puntuación y las **palabras comunes** (de lenguajes de programación, del propio vocabulario de Pitangus en inglés y en
español, de la escritura de código y de seguridad, y las que se parten enteras en esas y en números de hasta tres
cifras, como `getConnection` o `admin123`) y cambia cualquier otra palabra por `***`, esté donde esté; una URL pierde
además la información de usuario y todos los valores de su query y de su fragmento. Así,
`# creds: admin / Winter2024Corp` se lee `# ***: admin / ***`. Toda URL guardada (la ubicación de un hallazgo web, el
objetivo de una ejecución, las referencias de un SARIF importado) se renderiza igual; la identidad de un hallazgo web lee
la página tal como era, mediante una clave de resúmenes, así que la misma página conserva su identidad. Los valores que
detectaron los motores de secretos se cambian además allí donde aparezcan, también en sus formas codificadas. Lo que
dicen el catálogo de reglas de Pitangus y los avisos públicos se muestra tal cual.

Las dos cosas están probadas como propiedades: un valor aleatorio puesto en cualquier parte del código analizado no
aparece en ninguna tabla de la base de datos, informe, SARIF, incidencia de Jira, notificación, prompt ni log, y el
endpoint del fragmento enmascara cada secreto señalado.

Al actualizar a 0.14.1 se borra el código que guardaron las versiones anteriores (migración de datos `drop_stored_code`:
ejecuciones, registro, SARIF e informes guardados, entradas pendientes de la bandeja de salida). La identidad de cada
hallazgo se calculó de su código antes de borrarlo, y ningún estado cambia.

## Arréglalo con tu propia IA

El detalle de cada hallazgo abierto tiene **Copiar prompt para tu IA**: un prompt listo para pegar en Claude, Cursor o
Copilot con la regla, dónde está, el código que abriste (sin sus secretos) y la corrección recomendada. El servidor arma
el prompt sin código, porque no guarda ninguno; el panel añade las líneas que estás viendo, en tu navegador, al
copiarlo. `pitangus scan --format prompt` hace lo mismo en la terminal a partir de la carpeta que analizó, leída en ese
momento y con el mismo enmascarado (solo cuando analizó la carpeta tal como está en disco, no con `--commit` ni
`--staged`). Un hallazgo de secreto y una credencial escrita en el código nunca llevan código. Pitangus no llama a
ninguna IA para esto: el asistente es tuyo.

## Una identidad por problema

Cómo se reconoce un hallazgo de un análisis al siguiente. `PITANGUS_IDENTITY_MODE` ([configuracion.md](configuracion.md))
vale `v2` por defecto: un hallazgo por problema, según la identidad de abajo. Con `shadow`, las huellas funcionan como
antes de 0.14 mientras cada hallazgo lleva su identidad canónica y cada análisis anota qué cambiaría agrupar por ella.

- **Por su contenido, nunca por su posición.** El código es su regla, su archivo y el código encontrado sin comentarios
  ni formato; un recurso configurado, su dirección (`aws_s3_bucket.data`); una dependencia, su aviso, su paquete como
  purl y su versión tal como la compara su ecosistema (`v0.3.7` y `0.3.7` son la misma versión de Go); un secreto, el
  HMAC de su valor con una clave derivada de la clave maestra (ni el valor ni el HMAC se guardan, se muestran ni se
  exportan nunca), sea cual sea la clave que lo guarda, el formato, con comillas o sin ellas, y el motor que lo encontró
  (`API_KEY = "…"` en un `.env` y `api_key: …` en YAML son el mismo secreto, y lo que reportan Betterleaks y Trivy de él
  es un solo hallazgo, igual que el de un SARIF importado; un secreto o una credencial escrita en el código que llega en
  un SARIF también se identifica por su valor, nunca por su fragmento; dos valores nunca son el mismo hallazgo, aunque
  estén en el mismo sitio: cambiar `TOKEN = "A"` por `TOKEN = "B"` remedia A y abre B, una PR que lo hace introduce B, y
  el triaje de A se queda en A; uno cuyo valor no se puede leer con certeza queda sin enlace, nombrado por el contenido
  de sus líneas, como arriba); un hallazgo web, la regla de la herramienta, el host, la plantilla de la ruta, la evidencia y el tipo
  de análisis que lo vio (un rastreo anónimo, uno con cabeceras guardadas, una definición de API o una comprobación de
  exposición: solo un análisis de ese tipo puede decir que ya no está, así que la misma alerta vista por dos tipos son
  dos hallazgos). Una línea añadida encima, un comentario de supresión, un reformateo o el orden en que un motor lista
  sus resultados no cambian nada.
- **Familias con contador.** Problemas idénticos (la misma línea pegada dos veces, el mismo secreto en dos archivos, una
  regla en muchas páginas de una plantilla) son un solo hallazgo con su número de copias y dónde está cada una. Una
  decisión de triage cubre las copias que había: una más lo devuelve a abierto con una nota. Una menos es una
  remediación parcial del mismo hallazgo, que queda remediado cuando no queda ninguna donde el análisis miró. Una copia
  en un archivo o página que el análisis no pudo comprobar sigue contando.
- **Cuando el motor no da contenido** (una mala configuración sin dirección, un resultado importado sin código), la
  familia es la regla en su archivo, y el contador distingue las copias.
- **Dos motores, un problema.** Los informes solo se unen por identidad, nunca adivinando por la línea; cuando una
  fusión anterior pliega uno en otro, la huella plegada queda entre los nombres anteriores del hallazgo.
- **El paso a `v2`.** `pitangus identity-gate` compara los dos últimos análisis completos de cada repositorio por huella
  y por identidad. Cambia cuando todos los repositorios analizados dos veces sobre el mismo commit den 0/0 de las dos
  formas; el primer análisis en `v2` mueve cada entrada, su triage y su issue a su familia por sus huellas anteriores,
  con la retención de remediados. `pitangus identity-gate --scan RUTA` hace lo mismo sin servidor: analiza la carpeta
  dos veces con esta versión y falla (código 3) si el segundo análisis abre o remedia algo, excluidos incluidos. La CI
  de Pitangus lo ejecuta.
- **Plegar nunca relaja el triage.** Cuando varias huellas se pliegan en un solo hallazgo (copias agrupadas en una
  familia, informes de dos motores unidos), las copias que coinciden conservan su decisión, con la caducidad más
  cercana; si difieren, o alguna nunca se revisó, el hallazgo vuelve a abierto para revisarlo. El historial de cada
  copia y todos los issues de Jira se conservan (los demás quedan enlazados bajo el primero).

## Triage

Selecciona uno o varios hallazgos (hasta 500 a la vez) y elige un estado. Cada cambio queda en el historial del
hallazgo con usuario, fecha y motivo.

| Estado | Acción | Qué significa | Motivo |
| --- | --- | --- | --- |
| Abierto | **Reabrir** | Vuelve a contar como pendiente en el panel, los tickets y el SARIF. | Opcional |
| En curso | **En curso** | Alguien está corrigiéndolo. Sigue contando como pendiente. | Opcional |
| Falso positivo | **Falso positivo** | Deja de contar como pendiente en este y en los siguientes análisis del activo. | Obligatorio |
| Riesgo aceptado | **Aceptar riesgo** | Asumes el riesgo hasta una fecha de vencimiento (un año como máximo); después se reabre solo. **Solo administradores.** | Obligatorio |
| Remediado | **Marcar remediado** | Lo marca como remediado sin esperar al siguiente análisis. Explica cómo (PR, parche, despliegue). Si un análisis posterior lo vuelve a encontrar, se reabre solo. | Obligatorio |

Un motivo obligatorio tiene al menos 10 caracteres. Las decisiones van atadas a la huella, no a una ejecución, así
que se mantienen entre análisis. Los hallazgos descartados (falsos positivos, riesgos aceptados) no cuentan como
abiertos, no van a Jira y figuran como tales en el VEX ([Evidencias de cumplimiento](cumplimiento.md)).

## Verificar una corrección: Reverificar y Volver a verificar

¿Ya lo corregiste? Abre el hallazgo y haz clic en **Reverificar**: Pitangus vuelve a analizar su activo y te dice si
sigue ahí. Después de un resultado, el botón pasa a **Volver a verificar**. El resultado es uno de estos:

- **Corregido**: el nuevo análisis completo ya no lo encuentra, y el registro lo marca como remediado.
- **Sigue presente**: todavía aparece.
- **Incompleto**: algún motor no corrió, así que el análisis no demuestra nada. Vuelve a intentarlo.
- **Falló**: el análisis falló. Vuelve a intentarlo.

Si ya hay un análisis de ese activo en cola o en curso, el hallazgo se suma a él en lugar de lanzar otro. Algunos
hallazgos se verifican de otra forma:

- **Hallazgos web**: Reverificar vuelve a hacer el análisis pasivo del dominio (solo administradores). Despliega la
  corrección antes.
- **De un PR abierto**: se verifican solos en cada push del PR.
- **Importados**: solo la herramienta que lo reportó puede decir si ya no está; importa un SARIF completo nuevo de
  esa herramienta.

## Rutas excluidas

Hay carpetas que no vale la pena revisar: ejemplos vulnerables a propósito, pruebas con datos falsos, código
generado. Un **administrador** las excluye por repositorio en **Hallazgos → Ajustes del repositorio → Rutas
excluidas**, un patrón por línea, con un motivo obligatorio que queda en el historial:

```text
fixtures
docs/*.md
**/testdata
```

Los patrones funcionan como `.gitignore`: un patrón que coincide con una carpeta excluye todo lo que contiene
(`fixtures` cubre `fixtures/a/b.py`), `*` no cruza carpetas y `**` sí. Se rechazan los patrones que excluirían todo
(`**`, `*/**`), las rutas absolutas y `..`. Mientras escribes, el diálogo comprueba los patrones como lo haría al
guardar y dice cuáles de los hallazgos actuales pasarían a **Excluidos** (o volverían a abiertos), con algunas de sus
rutas, antes de guardar nada. El diálogo también muestra ejemplos habituales, cada uno con lo que significa; al elegir
uno se añade su línea.

**Un falso positivo conocido en un lugar.** Escribe el ID de una regla después de la ruta, separado por un espacio, y
solo se excluyen los hallazgos de esa regla allí; todo lo demás bajo esa ruta sigue contando:

```text
tests/** generic-api-key
```

El ID es el que aparece bajo el título de cada hallazgo (un hallazgo que reportaron dos motores responde a la regla de
cualquiera de los dos). Una regla acota lo suficiente como para aceptar `** generic-api-key` (esa regla en todo el
repositorio). Para descartar un solo hallazgo, márcalo como falso positivo en el triage.

- Lo que cae bajo ellos no cuenta como abierto, no entra en el informe ni en el SARIF y **no bloquea PR**. No
  desaparece: queda en la pestaña **Excluidos**, y cada ejecución dice en sus limitaciones cuántos hallazgos quedaron
  fuera y por qué patrón.
- Excluir no es corregir: un hallazgo excluido nunca pasa a remediado. Si quitas la exclusión, vuelve a estar abierto.
- Las exclusiones viven en el servidor, **no en el repositorio**: un archivo en el repositorio permitiría que un PR
  se excluyera a sí mismo. Por la misma razón, no se aplican el `.betterleaks.toml` ni el `.gitleaks.toml` del repositorio.

Desde la terminal, `make scan DIR=../mi-repo ARGS="--exclude fixtures"` hace lo mismo para una ejecución ([CLI](cli.md)).

## Plazos de corrección

Cada hallazgo pendiente tiene una fecha límite según su severidad, contada desde la **primera detección** (reabrirlo
no reinicia el reloj). Por defecto: crítica 7 días, alta 30, media 90 y baja 180. Un **administrador** los cambia en
**Políticas → Plazos de corrección** (un número entero de días de 1 a 3650, o vacío para que esa severidad nunca
venza); aplican a todos los repositorios. Solo vencen los hallazgos abiertos o en curso: los remediados, excluidos,
falsos positivos y riesgos aceptados vigentes nunca vencen.

Se ven en **Hallazgos** (la tarjeta **Fuera de plazo**, una etiqueta «Vencido hace N días» o «Vence en N días», y el
filtro **Más filtros → Plazo**), en el **Resumen** (Fuera de plazo) y en el informe de evidencia de auditoría (la
política y los hallazgos vencidos ordenados por retraso, que es lo que SOC 2 e ISO 27001 piden como evidencia de
corrección a tiempo).

## Varios activos a la vez

El selector de alcance de arriba en **Hallazgos** (el mismo que en **Cumplimiento**) tiene cuatro opciones: **Uno**
(por defecto, con sus ejecuciones y ajustes), **Una organización** (sus repositorios), **Elegir varios**
(repositorios e imágenes) o **Todos**. Con un repositorio vienen las imágenes construidas desde él, salvo que lo
desactives.

El alcance queda en la dirección (`#/findings?scope=account&account=acme`), así que al recargar o compartir el enlace
se abre la misma vista. Combina el estado actual de cada activo:

- Las tarjetas suman todo el alcance, y la tabla gana una columna **Activo**.
- **Por activo** lista cada activo con sus hallazgos pendientes y críticos, los más críticos primero; haz clic en uno
  para abrirlo solo.
- El triage funciona por hallazgo o sobre una selección que abarca varios activos. Se guarda activo por activo; si
  alguno falla, el panel dice cuál y reintenta solo esos. Los issues de Jira y la evidencia de auditoría consolidada
  (hasta 500 activos) funcionan igual.
- Las rutas excluidas, las reglas de secretos, elegir una ejecución concreta y los archivos por activo (PDF, SARIF,
  SBOM…) necesitan un solo activo.
- Un alcance muy grande lista los 10.000 hallazgos más urgentes de la pestaña y lo dice; los recuentos siempre cubren
  todo.

## Cobertura OWASP

**Cobertura** (`#/coverage`) muestra, para el último análisis completo de un activo, qué categorías del OWASP Top 10
se revisaron: cuántas reglas de Pitangus apuntan a cada categoría (leídas de `rules/`), qué motores la cubrieron y
cuántos hallazgos produjo. Lo que un análisis de ese tipo no puede cubrir se declara con su motivo, no con una frase
genérica: en código, el diseño inseguro, el registro y las alertas, y las condiciones excepcionales requieren la
aplicación en marcha; un análisis de imagen solo lee paquetes y configuración; un análisis web pasivo no envía
ataques.

<!-- screenshot: coverage | La matriz de cobertura OWASP de una ejecución, con las categorías revisadas, los motores y reglas detrás de cada una, y las no cubiertas con su motivo -->

## Guía OWASP en cada hallazgo

Cada hallazgo enlaza las páginas de OWASP sobre su tipo de problema, bajo **Guía OWASP** en su detalle:

- la página de la [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) que explica cómo prevenirlo,
- su categoría del OWASP Top 10:2025,
- y, en hallazgos de código y web, el riesgo del OWASP API Security Top 10 2023 y la prueba de la Web Security
  Testing Guide (WSTG) que corresponden.

Los enlaces salen de una correspondencia curada y versionada en el repositorio
([`pitangus/modules/findings/references.yaml`](../../pitangus/modules/findings/references.yaml)): primero por regla
(cabeceras de seguridad, flags de cookies, CORS, HSTS, TLS, clickjacking, auditorías de GitHub Actions, revisiones de
imágenes…), luego por framework o archivo (Dockerfile, Kubernetes, Terraform, pipelines), luego por CWE y luego por
analizador. Un hallazgo cuyo motor no dio categoría OWASP recibe la que asigna la propia correspondencia CWE de OWASP.

Son solo enlaces; no se copia el texto de las páginas. Pitangus no escribe una corrección propia para reglas de
terceros, porque la corrección puede estar en un WAF, una CDN o la plataforma y no en el código: **primero va la guía
y las referencias de la herramienta, tal como se publicaron**, y después los enlaces de OWASP. El PDF técnico y el
informe Markdown los imprimen junto a las referencias de cada hallazgo. La API los entrega como `guidance` (`title`,
`url`, `kind`: `cheatsheet`, `top10`, `api_top10` o `wstg`), calculados al leer el hallazgo, así que los hallazgos de
ejecuciones antiguas también los reciben.

<!-- screenshot: finding-web-detail | El detalle de un hallazgo web: qué es, evidencia, cómo corregirlo, los enlaces de la guía OWASP y las otras herramientas que lo reportaron -->

## CVE tracker

**CVE tracker** (`#/cve-tracker`) busca en una copia local de NVD guardada en la base de datos, cruzada con CISA KEV
y EPSS: texto libre, CVE por prefijo, severidad, solo KEV, año, orden por fecha, CVSS o EPSS. Cada CVE muestra su
severidad y CVSS, EPSS, si está en KEV, su CWE, vector y referencias, y **cuáles de tus repositorios e imágenes lo
tienen** entre sus hallazgos. **Solo los que me afectan** limita la lista a los CVE abiertos en tus activos (sin lo
descartado en el triage). La búsqueda queda en la dirección, así que puedes compartirla o recargarla.

La copia se carga en segundo plano de lo más nuevo a lo más antiguo, se reanuda tras un reinicio y luego se mantiene
al día cada 2 horas. Sin clave de la API de NVD, NVD permite 5 peticiones cada 30 segundos y la carga completa (unos
400.000 CVE) tarda unas horas; con `PITANGUS_NVD_API_KEY` es unas 8 veces más rápida. `PITANGUS_CVE_SYNC=off` la
apaga ([Configuración](configuracion.md)). Cuando NVD no puntuó un CVE (desde 2026 solo enriquece algunos), la
puntuación viene de **EUVD** (la base de ENISA), consultada bajo demanda y guardada en caché, que además dice si se
explota activamente.

## Exportar hallazgos

Desde una ejecución o el estado actual de un activo: **Informe PDF** y, en **Más formatos**:

| Formato | Para qué |
| --- | --- |
| **Informe Markdown** | Pegarlo en una wiki, un issue o un PR. |
| **JSON completo** | Tus propios scripts. |
| **SARIF (code scanning)** | SARIF 2.1.0, el formato estándar de resultados de análisis estático, con `security-severity`, para el code scanning de GitHub y otras herramientas. |
| **Tickets para Jira (JSON)** | Un ticket por tarea de corrección, con la forma que usa el conector de Jira. |
| **SBOM · CycloneDX 1.6** y **VEX · OpenVEX (desde el triage)** | Consulta [Evidencias de cumplimiento](cumplimiento.md). |
| **Evidencia para auditoría (SOC 2, ISO, PCI…)** | Un PDF con alcance, método, hallazgos, excepciones y firmas, según el marco que elijas. Consulta [Evidencias de cumplimiento](cumplimiento.md). |

El estado actual exporta su registro acumulado por su propia ruta, para que nunca se confunda con una sola ejecución.
Los hallazgos excluidos quedan fuera. Los informes salen en inglés o en español. Los perfiles de cumplimiento
organizan evidencia técnica; no son una auditoría, una certificación ni una atestación.

**Jira.** **Crear en Jira** convierte una selección (hasta 50 hallazgos) en issues, uno por tarea de corrección, sin
duplicar los issues que ya existen; las reglas de enrutamiento también pueden crearlos solos tras un análisis. La
configuración y los detalles están en [Integraciones](integraciones.md).

## Errores frecuentes

| Lo que ves | Por qué | Qué hacer |
| --- | --- | --- |
| «Sin hallazgos en lo examinado» | Las reglas y dependencias cubiertas no produjeron avisos | Revisa la cobertura y las limitaciones de la ejecución: un resultado limpio no es una prueba. |
| Un hallazgo volvió después de marcarlo como remediado | Un análisis posterior lo encontró otra vez | Comprueba que la corrección esté desplegada o fusionada en la rama analizada. |
| No aparece **Aceptar riesgo** | Solo los administradores aceptan riesgos | Pídeselo a un administrador. |
| Reverificar dice que el análisis quedó incompleto | Algún motor no corrió | Resuelve el problema del motor ([Solución de problemas](solucion-problemas.md)) y vuelve a verificar. |
| Un aviso dice que GitHub ya no da acceso al repositorio | La App perdió el acceso (se borró o se quitó de la App) | Devuélvele el acceso a la App antes de 24 horas para conservar sus hallazgos. |

## Siguientes pasos

- [Evidencias de cumplimiento: SBOM, VEX, informes de auditoría y CRA](cumplimiento.md).
- [Integraciones](integraciones.md): Jira, Slack, Teams e importación de SARIF.
- [Modelado de amenazas](modelado-de-amenazas.md): relaciona las amenazas con la evidencia de tus hallazgos.
- [Conceptos](conceptos.md).
