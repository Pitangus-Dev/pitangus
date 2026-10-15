[English](../concepts.md) · Español

# Conceptos clave: ejecuciones, hallazgos, huellas y triage

Esta página explica las ideas en las que se apoya el resto de la documentación: qué tipo de pruebas hace Pitangus, qué
analiza, cómo queda registrado un análisis, cómo vive un hallazgo desde que aparece hasta que se remedia y quién puede
hacer qué. Los términos en negrita también están en el [glosario](glosario.md).

## Análisis, no pentest

Pitangus hace **análisis**. Lee código, dependencias, configuración e imágenes sin ejecutarlos, y lee las respuestas
de un sitio web sin atacarlo. Sus hallazgos son candidatos que tú confirmas.

Un **pentest** (prueba de penetración) es otra cosa: una persona o un agente intenta explotar fallos en un sistema en
marcha y demuestra el impacto. Pitangus no hace eso, y un informe de Pitangus no reemplaza el pentest que pueden exigir
SOC 2 o ISO 27001. Si corres por tu cuenta una herramienta de pentest (Strix, el escaneo activo de ZAP, Nuclei), puedes
[importar sus resultados](integraciones.md#trae-tu-propio-dast) para que tengan el mismo ciclo de vida.

## Análisis pasivos y activos

Un **análisis pasivo** solo envía lo que mandaría un visitante normal: peticiones `GET` y `HEAD`, un navegador que
sigue enlaces, saludos TLS. Lee las respuestas y señala lo que revelan (una cabecera de seguridad que falta, una
librería desactualizada, un archivo expuesto). Un **análisis activo** envía ataques, como inyecciones o fuzzing, para
ver si la aplicación falla.

Los análisis web de Pitangus son solo pasivos. Los activos están en desarrollo y, cuando lleguen, necesitarán la
autorización de quien administra, registrada en la ejecución. Ver [Analizar un sitio web o una API](analisis-web.md).

## Activos

Un **activo** es algo que Pitangus analiza y para lo que lleva un registro. Hay tres tipos:

| Activo | Se identifica por | Se analiza con |
| --- | --- | --- |
| Repositorio | Su identidad en GitHub (ID numérico), así que un repositorio renombrado sigue siendo el mismo; o una carpeta local en la CLI | Opengrep, Betterleaks, Trivy, OSV-Scanner, zizmor; Checkov si se activa. Ver [Analizar tu código](analisis-de-codigo.md). |
| Imagen de contenedor | Registro y repositorio, sin la etiqueta: `api:1.5` y `api:1.4` son el mismo activo | Trivy y reglas de Pitangus (Grype y Checkov si se activan), leída del registro, nunca ejecutada. Ver [Analizar imágenes de contenedor](analisis-de-imagenes.md). |
| Dominio | `domain:<host>`, una vez que quien administra demuestra que lo controla (**verificación del dominio**) | De forma pasiva: httpx, testssl.sh y nuclei en la comprobación de exposición, siempre disponible; ZAP, katana y subfinder en el análisis completo, experimental. Ver [Analizar un sitio web o una API](analisis-web.md). |

Los resultados importados de otra herramienta (SARIF) siempre entran en un activo que Pitangus ya conoce.

## Ejecuciones y pasos

Cada análisis, revisión de PR, importación SARIF o revisión diaria de avisos es una **ejecución**. Una ejecución
registra qué se analizó, cuándo, quién lo pidió y una lista de **pasos**: uno por motor o fase, cada uno con un estado y
un detalle en lenguaje claro.

| Estado del paso | Significa |
| --- | --- |
| **Completado** | El paso llegó al final. |
| **Parcial** | El paso corrió pero no lo cubrió todo: una herramienta falló a medias, no llegó a un host o un usuario de prueba no pudo iniciar sesión. |
| **Omitido** | El paso no aplicaba o no pudo arrancar, con el motivo (por ejemplo, la imagen de una herramienta web no está en el servidor). |
| **No probado** | El motor no corrió (Docker no accesible, falta la imagen o una opción apagada). No se afirma nada de lo que revisa. |
| **Inconcluso** | El motor corrió, pero su respuesta no se puede dar por completa, así que no demuestra nada. |

Una ejecución completa puede estar **En cola**, **Analizando…**, **Completada**, **Parcial**, **Incompleta**,
**Inconcluso** o **Fallida**. Cada ejecución también lista sus **limitaciones**: lo que el análisis no puede ver por
diseño (páginas detrás de un login a las que no llegó, flujo de datos entre archivos, ataques que no envió).

### Cobertura parcial

**Cobertura parcial** significa que una parte de lo que el análisis debía revisar no se revisó. De ahí salen dos
consecuencias, ambas a propósito:

- **Nada se da por limpio si una herramienta no corrió.** Pocos hallazgos, o ninguno, en una ejecución parcial no dicen
  nada de la parte que no se cubrió. La ejecución, sus informes y el panel lo dicen junto a los resultados.
- **Los hallazgos anteriores no se marcan remediados.** Si una herramienta no terminó o no llegó a un host, lo que solo
  ella había visto sigue abierto hasta que una ejecución que sí llegue deje de reportarlo.

<!-- screenshot: scan-progress | Una ejecución de análisis web con sus pasos completados, parciales y omitidos -->

## Hallazgos y huellas

Un **hallazgo** es un problema en un lugar: la versión vulnerable de un paquete, un secreto en una línea, una mala
configuración en un archivo, una cabecera que falta en una URL. Cada hallazgo tiene una severidad (crítica, alta,
media, baja, info), una prioridad con sus factores a la vista (**Actuar ya**, **Atender** o **Seguir**, según CVSS, KEV
y EPSS) y cómo corregirlo, hasta donde se sabe (un comando, un ejemplo para adaptar o el consejo de la propia
herramienta).

Cada hallazgo recibe además una **huella** (fingerprint): un identificador estable calculado a partir de qué es el
problema y dónde está, nunca del valor de un secreto. Con la huella, Pitangus reconoce el mismo problema en la siguiente
ejecución aunque se hayan añadido líneas encima, y el triage, las incidencias de Jira y el historial lo siguen. Cuando
dos motores reportan el mismo problema en el mismo lugar, quedan en un solo hallazgo que nombra a los dos.

## Ciclo de vida: abierto, remediado, reabierto

Cada activo tiene un **registro** con el estado actual de cada huella. Se actualiza solo:

- **Análisis completo.** Lo que aparece sigue abierto (o se reabre si estaba remediado). Lo que estaba abierto y ya no
  aparece queda **remediado automáticamente**.
- **Revisión de pull request.** Solo cuenta lo que introduce el PR. Un commit posterior del mismo PR que lo quita lo
  remedia; un PR cerrado sin merge retira sus hallazgos.
- **Importación de otra herramienta.** Una importación completa posterior de la misma herramienta remedia lo que ella ya
  no reporta. Los análisis propios de Pitangus nunca remedian un hallazgo importado, y una importación nunca remedia
  los de Pitangus.
- **Reverificar.** Después de subir o desplegar una corrección, **Reverificar** en un hallazgo vuelve a analizar ese
  repositorio, imagen o dominio. El hallazgo dice entonces **Corregido ✓ · ya no aparece en el análisis** o **Sigue
  presente en el análisis**. Si el análisis quedó incompleto, lo dice y no demuestra nada.

## Triage

El **triage** es registrar una decisión sobre un hallazgo:

| Estado | Quién | Necesita |
| --- | --- | --- |
| En curso | Cualquier miembro | Nada más |
| Falso positivo | Cualquier miembro | Un motivo |
| Riesgo aceptado | Solo administradores | Un motivo y una fecha de caducidad |
| Remediado (a mano) | Cualquier miembro | Un motivo; si reaparece en un análisis posterior, se reabre solo |

Cada decisión queda en el historial del hallazgo con el usuario y la fecha. Los hallazgos descartados en el triage no
cuentan como abiertos, no vencen y no se exportan a Jira, pero se conservan como evidencia. Las **rutas excluidas** (que
define quien administra por repositorio) son otra cosa: ocultan carpetas enteras, como datos de prueba, con un motivo.
Ver [Hallazgos](hallazgos.md).

## Roles: administrador y miembro

| Rol | Puede |
| --- | --- |
| **Miembro** | Lanza análisis, triagea y consulta resultados. |
| **Administrador** | Todo lo de un miembro, y además conecta proveedores, gestiona usuarios, acepta riesgos, añade y verifica dominios, lanza y programa análisis web, y define rutas excluidas y plazos de corrección. |

El segundo factor (TOTP) es obligatorio para los administradores por defecto (`PITANGUS_REQUIRE_TOTP`). La primera
cuenta, la que se crea con el código de configuración, es de administrador.

## Workers y análisis en segundo plano

Lanzar un análisis responde enseguida: el análisis queda en una cola en PostgreSQL y un **worker** lo toma. Cada worker
corre un análisis a la vez; para correr más a la vez, añade workers ([Escalar](escalar.md)). Mientras corre, su
ejecución existe con el estado **En cola** o **Analizando…** y un registro de progreso en vivo escrito para personas.
Al terminar, el panel muestra un aviso. Reiniciar el servidor marca como fallido cualquier análisis que haya quedado a
medias: vuelve a lanzarlo.

El trabajo periódico (vigilar pull requests, la revisión diaria de avisos, los análisis web programados, la copia
local de CVE) lo hace un worker elegido como líder.

## Idiomas

Todo lo que se guarda para que lo lean personas (hallazgos, progreso, limitaciones, errores) se guarda como un
**código de mensaje** con sus parámetros, no como una frase. Se muestra en el idioma de quien lo lee, así que quien lee
en inglés y quien lee en español ven el mismo hallazgo en su idioma, y cambiarlo nunca exige volver a analizar. El texto
de terceros, como el resumen de un aviso, se guarda y se muestra tal como se publicó.

## Siguientes pasos

- [Inicio rápido](inicio-rapido.md): todo esto sobre datos de demostración.
- [Hallazgos](hallazgos.md): filtros, triage, plazos y exportaciones en detalle.
- [Glosario](glosario.md).
