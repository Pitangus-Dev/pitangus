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

- Los secretos y los hallazgos de código de Opengrep conservan su huella cuando se agregan líneas por encima, para
  que no parezcan remediados y nuevos a la vez.
- Un secreto se identifica por su regla, su archivo y lo que lo precede en su línea, nunca por su valor.
- Un aviso de dependencia tiene una sola huella, lo reporte el motor que lo reporte y lo nombre como lo nombre.
- Los hallazgos de versiones que calculaban las huellas de otra forma conservan su estado, triage, issue de Jira y
  verificación pendiente en el siguiente análisis.

La identidad de un repositorio es su identidad en GitHub (su ID numérico): un repositorio renombrado sigue siendo el
mismo. Si GitHub deja de dar acceso a un repositorio (se borró o se quitó de la App), el panel lo avisa; si el acceso
no vuelve en 24 horas, sus hallazgos, triage y tickets enlazados se borran.

Un análisis en el que algún motor no corrió queda **incompleto**: no marca nada como remediado, porque «no visto» no
es «desaparecido».

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
(`**`, `*/**`), las rutas absolutas y `..`.

- Lo que cae bajo ellos no cuenta como abierto, no entra en el informe ni en el SARIF y **no bloquea PR**. No
  desaparece: queda en la pestaña **Excluidos**, y cada ejecución dice en sus limitaciones cuántos hallazgos quedaron
  fuera y por qué patrón.
- Excluir no es corregir: un hallazgo excluido nunca pasa a remediado. Si quitas la exclusión, vuelve a estar abierto.
- Las exclusiones viven en el servidor, **no en el repositorio**: un archivo en el repositorio permitiría que un PR
  se excluyera a sí mismo. Por la misma razón, no se aplica el `.gitleaks.toml` del repositorio.

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
