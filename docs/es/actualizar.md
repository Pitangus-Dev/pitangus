[English](../upgrading.md) · Español

# Actualizar Pitangus

Actualizar es llevar el código a una versión nueva, descargar (o reconstruir) sus imágenes y reiniciar. Tus datos se
quedan: la base de datos, `data/` y `config/` se conservan, y lo que cambie de formato se convierte al arrancar. Esta
página cubre el procedimiento general y lo que cambia al pasar a 0.14. Cada versión también lista sus cambios en
[CHANGELOG.md](../../CHANGELOG.md) y en la [página de Releases](https://github.com/Pitangus-Dev/pitangus/releases).

## Antes de actualizar

1. **Averigua qué versión tienes.** En la carpeta del repositorio:

   ```bash
   git describe --tags
   ```

   ```text
   v0.12.2
   ```

   La cabecera del panel también la muestra, junto a **Nuevo análisis** (**Autoalojado · v0.12.2**), y `/api/health`
   la responde.
2. **Lee las notas de versión** de cada versión entre la tuya y la nueva, sobre todo sus secciones **Breaking**.
3. **Comprueba que no haya nada en marcha.** Abre **Análisis** (`#/analyses`): ninguna ejecución debe estar **En
   cola** ni **Analizando…**. Un reinicio marca como fallido cualquier análisis en curso, y la copia de seguridad no
   corre mientras haya análisis en marcha.
4. **Guarda una copia de la clave maestra** (`config/master.key`, o tu `PITANGUS_MASTER_KEY`) en un lugar seguro,
   aparte de las copias de seguridad. Sin ella, los secretos guardados no se pueden descifrar.

## Actualizar paso a paso

### Si instalaste una versión

Si clonaste una etiqueta (`git clone --branch v0.14.x`, como en el [inicio rápido](inicio-rapido.md)), el repositorio
se queda en esa versión a propósito. Primero cambia a la nueva y luego actualiza:

```bash
git fetch --tags
git checkout v0.14.3      # la versión que quieras
make update
```

En una versión fija, `make update` lo dice y no trae código:

```text
On v0.14.3 (a fixed version): not pulling. Check out the version you want first.
```

Es lo esperado justo después de `git checkout`: el código ya está en la versión nueva.

### Si sigues main

Si clonaste sin `--branch`, `make update` trae solo el código más reciente:

```bash
make update
```

### Qué hace `make update`

1. Trae el código (solo si sigues una rama).
2. Hace una copia de seguridad con `make backup`, en `backups/<fecha>/`:

   ```text
   Backup in backups/20261010-091500/
     Restore with: make restore FROM=backups/20261010-091500 CONFIRM=restore
   ```

3. Descarga las imágenes publicadas (o las reconstruye si construyes desde el código) y reinicia con `make up`, que
   espera al panel, descarga las imágenes de motores que falten (`make engines`) y muestra la URL.
4. Al arrancar, las migraciones de la base de datos y las conversiones de datos corren una sola vez, tras guardar una
   copia de lo que tocan en `data/backups/`. No hay que hacer nada a mano.

Al terminar, abre el panel y comprueba la versión en la cabecera. Si algo no cuadra, ejecuta `make doctor` y
`make status`.

> [!CAUTION]
> No vuelvas a una versión anterior sobre una base de datos que ya migró una versión nueva. Para volver atrás, restaura
> la copia que hizo `make update`: `make restore FROM=backups/<fecha> CONFIRM=restore`, luego cambia a la versión
> anterior y ejecuta `make up`.

## Actualizar a 0.14

0.14 va de poder confiar en los resultados: un hallazgo solo se remedia con pruebas, el mismo problema conserva una sola
identidad de un análisis al siguiente, y un motor apagado o que no corrió nunca cuenta como remediación. A la mayoría de
las instalaciones les basta con `make update`, pero lee esta sección antes del primer análisis tras actualizar: no se
comporta como los anteriores.

### Identidad y cobertura activas por defecto

En 0.14, `PITANGUS_COVERAGE_MODE` vale `on` por defecto y `PITANGUS_IDENTITY_MODE`, `v2`. Un hallazgo se marca como
remediado solo cuando el motor dueño probó, en un análisis que funcionó, que miró donde estaba; y los problemas
idénticos son un solo hallazgo, una familia con su número de copias. Si quieres conservar el comportamiento de 0.13
mientras revisas tus repositorios, pon las dos en `shadow` en `.env` y reinicia: cada análisis anota entonces lo que
cambiarían las reglas nuevas sin aplicarlo, y `pitangus identity-gate` te dice cuándo el cambio ya no mueve nada en tus
repositorios (ver [Hallazgos](hallazgos.md#una-identidad-por-problema)).

### Qué esperar del primer análisis

El primer análisis con `PITANGUS_IDENTITY_MODE=v2` mueve cada hallazgo guardado, con su triage y su issue de Jira, a su
familia según sus huellas anteriores. El cambio de identidad, por sí solo, no abre ni remedia nada:

- **Familias con contador.** Donde 0.13 listaba el mismo problema varias veces (una línea pegada dos veces, el mismo
  secreto en dos archivos, una regla en muchas páginas de una plantilla), ahora ves un solo hallazgo con su número de
  copias y dónde está cada una. Los totales bajan, pero ningún problema desapareció.
- **El triage se conserva con prudencia.** Si todas las copias de una familia tenían la misma decisión, la familia la
  mantiene, con su fecha de caducidad y su ticket. Si las decisiones no coinciden, o alguna copia no tenía, la familia
  vuelve a pendiente con el historial de todas: decides una vez por todas ellas.
- **Las remediaciones masivas se retienen.** Un análisis que remediaría al menos el 30 % de los hallazgos abiertos de un
  activo, y al menos 10, no remedia ninguno: los retiene y lo indica en la página del activo. Solo los libera un segundo
  análisis que cubra esos mismos hallazgos y vuelva a confirmar que ya no están; quien administra puede aplicarlos al
  momento con **Marcar como remediados**. Las aperturas nunca se retienen. Los umbrales se cambian con
  `PITANGUS_FIX_HOLD_PERCENT` y `PITANGUS_FIX_HOLD_MINIMUM`.
- **Lo que un análisis no pudo comprobar sigue abierto.** Un hallazgo en un archivo donde un motor agotó el tiempo, en un
  manifiesto que no se pudo resolver o de un motor apagado queda **Sin verificar desde** ese análisis, fuera de plazos e
  indicadores, hasta que un análisis que vuelva a mirar pruebe que ya no está. Un hallazgo de dependencias pertenece a
  la carpeta del proyecto del archivo del que salió, sea cual sea su gestor de paquetes: una carpeta de la que el motor
  no listó ningún paquete, o un archivo del que dejó de listarlos mientras su carpeta sigue ahí, queda sin examinar, así
  que borrar o vaciar cualquier lockfile nunca remedia lo que se encontró en él. Cada motor que vio un hallazgo tiene
  que volver a mirar. Versiona el lockfile para que se examine.
- **Cambiar la configuración no remedia nada.** Apagar una regla o un motor, cambiar una lista de permitidos o actualizar
  el conjunto de reglas deja los hallazgos afectados como no comprobados (configuración), nunca remediados, y no manda
  nada a Jira ni a las notificaciones.

### Betterleaks en lugar de Gitleaks

Los secretos ahora los busca Betterleaks 1.9.0, de los mismos mantenedores de Gitleaks. Tu configuración de detección
de secretos se conserva: las reglas propias, las reglas integradas desactivadas y las listas de permitidos usan el mismo
formato, y una regla desactivada que Betterleaks no tiene se descarta. La identidad de un secreto es el HMAC de su valor,
no el nombre que le pone el motor, así que el cambio no remedia nada. La 0.13 guardaba los secretos sin la identidad de
su valor: cada uno pasa a ella, con su triaje y su incidencia de Jira, en el primer análisis que lee el valor, una sola
vez. A partir de ahí dos valores nunca son el mismo hallazgo. Si cambiaste el valor de un secreto entre tu último
análisis con la 0.13 y el primero con la 0.14, el valor nuevo se queda con el triaje de la entrada antigua: revisa los
secretos que habías aceptado o marcado como falsos positivos.

- **Cuenta con algunos hallazgos de secretos nuevos.** Betterleaks trae 463 reglas integradas frente a las 222 de
  Gitleaks, así que el primer análisis puede abrir secretos que Gitleaks no reconocía. Los marcadores y valores de
  ejemplo (`YOUR-ACCESS-TOKEN`) quedan fuera, y las claves públicas por diseño, como la clave anónima de Supabase, no se
  reportan como secretos filtrados.
- **Los motores de secretos leen lo que sus propias listas se saltaban.** Las listas internas de Betterleaks y Trivy
  están apagadas: ahora se buscan secretos en las carpetas `node_modules/` y `vendor/` versionadas, los lockfiles, los
  archivos minificados, las carpetas ocultas, las pruebas, los ejemplos y el Markdown, y un archivo que un motor aún
  se salta figura como no analizado por ese motor. Lo que permite un comentario `gitleaks:allow` aparece en
  **Excluidos** con su archivo y su línea, nunca como remediado (`PITANGUS_SECRETS_IGNORE_INLINE_ALLOW=1` ignora esos
  comentarios). El pase de secretos tarda más en un repositorio con carpetas de dependencias versionadas: unos 35
  segundos más para un `node_modules/` de 600 MB.
- **`generic-password` viene activa, con un filtro.** Omite rutas de traducciones, pruebas, documentación y ejemplos;
  plantillas y referencias (`${…}`, `{{…}}`, `process.env`, `getenv`…); textos de interfaz, identificadores y
  marcadores; valores iguales al nombre de su clave; y valores débiles (menos de 8 caracteres, o de un solo tipo de
  carácter y menos de 16). En un corpus de control pasó de 29 hallazgos a 5, todos reales.
- **`generic-credential-uri` sigue apagada**: marca más URLs de ejemplo y documentación que secretos. Actívala en
  **Políticas → Detección de secretos → Reglas desactivadas por defecto** si la quieres.

### Se analizan los archivos de credenciales

`.env*`, `.npmrc`, `.pypirc`, `.netrc`, las claves SSH (`id_*`), `credentials`, `.git-credentials`, `.dockercfg`,
`.s3cfg`, `.boto` y `.htpasswd` quedaban fuera de todos los análisis antes de 0.14. Ahora los leen los motores de
secretos, Betterleaks y el escáner de secretos de Trivy y ningún otro, desde una copia aparte que se borra en cuanto
terminan; sus valores nunca se guardan. Un `.env` versionado con claves reales aparece en el primer análisis: rota esas
claves y luego haz triage.

### Motores opcionales: Checkov y Grype

Checkov y Grype vienen apagados: Trivy y zizmor ya cubren infraestructura y pipelines, y Trivy los paquetes de las
imágenes. Apagado, un motor aparece como **no ejecutado (desactivado)** en el plan, en el análisis y en el informe, nunca
como limpio, y lo que encontró antes sigue abierto, sin verificar: apagar un motor no remedia nada. Si dependes de
ellos, pon `PITANGUS_CHECKOV_ENABLED=1` o `PITANGUS_GRYPE_ENABLED=1` en `.env` y ejecuta `make engines`, que solo
descarga las imágenes de los motores activos.

### Comprobación de exposición y análisis web completo experimental

- **La comprobación de exposición está siempre disponible** para un dominio verificado, sin activar nada: la raíz de
  cada host y rutas conocidas (archivos expuestos como `.git` o `.env`, consolas de depuración y de estado, TLS, cabeceras de
  respuesta) con httpx, testssl.sh y las plantillas de solo detección de nuclei. Es ligera: sin rastreo y sin ZAP.
  `make engines` descarga sus imágenes, y el botón de análisis de un dominio la abre.
- **El análisis web completo es experimental** y está apagado salvo con `PITANGUS_DAST_ENABLED=1`: ZAP, katana y
  subfinder rastrean el sitio. Si lo usabas en 0.13, deja la variable en `.env`. Apagarlo no remedia nada de lo que
  encontró: esos hallazgos siguen abiertos hasta que un análisis del mismo tipo pruebe que ya no están.

### Migraciones de la base de datos

Dos migraciones de Alembic y estas de datos corren solas al arrancar, en este orden (`make update` hace antes una copia
de seguridad):

| Migración | Qué hace |
| --- | --- |
| `0015_domain_session_check` | Añade la página de comprobación de sesión de un dominio: con cabeceras guardadas, el análisis la pide antes y después, y sin un 2xx queda incompleto. |
| `0016_registry_control` | Añade lo que el registro guarda por activo sobre cómo remedia sus hallazgos: los remediados retenidos y qué los libera, la última comparación en sombra y la versión de identidad que siguen sus huellas. |
| `registry_identities` (datos) | Pone la identidad canónica a los hallazgos de dependencias guardados. Los demás la reciben en su siguiente análisis. |
| `registry_rule_baseline` (datos) | Anota en los hallazgos guardados las reglas de la 0.13.1 con que se vieron, para que una regla que cambió en 0.14 nunca remedie en el primer análisis. |
| `mask_stored_secrets`, `mask_stored_credentials` (datos) | Sustituyen los valores que detectaron los motores de secretos dondequiera que se guardaran, y vuelven a generar el informe y el SARIF de cada ejecución afectada. |
| `secret_value_identities` (datos) | Marca los secretos guardados por la 0.14 con la identidad de su valor, para que a partir de ahí solo los nombres de ese valor los enlacen. |
| `registry_coverage_units` (datos) | Deriva de su ruta las unidades de cobertura de cada hallazgo guardado (las de una dependencia: la carpeta de su proyecto). |
| `dependency_project_units` (datos) | Declara como unidad de cada hallazgo de dependencias guardado (ejecuciones y registro) la carpeta del proyecto de cada fichero donde se vio, sea cual sea el gestor de paquetes. |
| `render_stored_texts` (datos) | Renderiza como estructura todo texto guardado (ejecuciones, registro, notificaciones pendientes); los hallazgos de zizmor conservan solo su ruta. Antes fija las identidades. |
| `render_stored_texts_lexicon` (datos) | Vuelve a renderizar todo texto guardado con el renderizador que conserva una palabra solo si es una palabra común, nunca por su posición (también los textos de las reglas de un SARIF importado). Antes fija las identidades. |
| `web_location_keys` (datos) | Renderiza toda URL guardada como cualquier otra (la ubicación de un hallazgo web y sus instancias, el objetivo de una ejecución, las páginas que lista un análisis web, las filas del listado de ejecuciones). Antes fija la clave de cada página web y la identidad de cada hallazgo web desde la URL tal como estaba guardada, así que ninguna identidad cambia. |

## Actualizar a 0.13

0.13 añade un análisis web pasivo completo, usuarios de prueba, un alcance guardado por dominio, análisis web
programados y la nueva identidad del panel. A la mayoría de las instalaciones les basta con `make update`. Lee esta
sección si activaste los análisis web o usas la API.

### Imágenes de motores para los análisis web

Si el servidor define `PITANGUS_DAST_ENABLED=1`, los análisis web ahora corren cinco herramientas más junto a ZAP:
subfinder, katana, nuclei, httpx y testssl.sh, cada una fijada por versión y digest. `make update` las descarga al final
(con `make engines`), pero solo si la variable está activa en `.env` o en el entorno de la terminal que ejecuta `make`.
Compruébalo con:

```bash
make engines
```

```text
Engines: all images are ready.
```

Si falta una imagen, el paso de esa herramienta en el análisis web queda **Omitido** con «La imagen de … no está en
este servidor: ejecuta make engines», y el resto del análisis sigue.

Las plantillas de nuclei (versión 10.4.9) no son una imagen: el worker descarga esa versión una sola vez, desde GitHub
(`codeload.github.com`), la primera vez que un análisis web corre nuclei, y comprueba su SHA-256 fijado. Un worker que
no llega a GitHub omite nuclei y la ejecución dice por qué. Ver [Qué sale de tu máquina](seguridad.md#qué-sale-de-tu-máquina).

### Migraciones de la base de datos

Las migraciones de Alembic `0010` a `0014` corren solas al arrancar:

| Migración | Qué hace |
| --- | --- |
| `0010_domain_registry` | Pasa los dominios de un documento de ajustes a su propia tabla (migración de datos `domains_to_table`). |
| `0011_domain_proof_and_schedule` | Añade el método de prueba (DNS, archivo, meta) y las columnas de la programación. |
| `0012_scan_schedule` | Añade las reglas de programación; la migración de datos `scan_schedule_rules` conserva las programaciones semanales existentes en el día y la hora de su próxima ejecución, en UTC. |
| `0013_domain_scope` | Añade los hosts relacionados y el alcance guardado por dominio. |
| `0014_domain_test_users` | Añade los usuarios de prueba por dominio, sellados con la clave maestra. |

### Cambios incompatibles en la API

Si llamas a la API directamente (scripts, tableros), actualiza esto:

- **`DomainRow.schedule` es un objeto** en `GET /api/domains`: `frequency`, `weekdays`, `month_days`, `time`,
  `timezone`, `next_run_at`, `last_run_at`, `last_run_id`, `note`, `test_users` y `use_headers`, o `null` si no hay
  análisis programado. Los campos planos `schedule_next_at`, `schedule_last_at`, `schedule_last_run` y
  `schedule_note` ya no existen.
- **`POST /api/domains/remove` responde `runs_kept`** en lugar de `runs_deleted`.
- **El `web_inventory` de una ejecución de análisis web** ahora es `{sources: {katana, robots, sitemap, openapi, zap},
  count, urls}`, sin `tool`.
- **Los hallazgos de testssl.sh cambian de huella una vez.** Los ids de regla pierden el sufijo del certificado y cada
  problema de certificado es un hallazgo por host. El siguiente análisis web marca remediados los hallazgos de
  certificado antiguos y abre los nuevos; el triage de los antiguos no pasa a los nuevos.

### Quitar un dominio conserva su historial

Antes de 0.13, quitar un dominio borraba lo que se había importado o analizado sobre él. Ahora **Desconectar dominio**
(al final de la pestaña **Resumen** del dominio) borra solo su configuración: cabeceras guardadas, usuarios de prueba,
hosts relacionados, alcance guardado y análisis programado. Sus ejecuciones, hallazgos, triage e incidencias de Jira se
quedan como evidencia, y se vuelven a enlazar si se añade de nuevo el mismo host.

### Ajuste nuevo: `PITANGUS_EGRESS_IPS`

Si tus sitios filtran por IP (un firewall o un WAF), define las direcciones públicas o rangos CIDR desde los que salen
los análisis de tu worker, separados por comas (16 como máximo):

```bash
PITANGUS_EGRESS_IPS=203.0.113.10, 2001:db8::/48
```

El paso de revisión de un análisis web las muestra, con un botón para copiar, a quien tenga que permitirlas. Un valor
inválido impide que el servidor arranque. Sin ella, quien administra puede pulsar **Detectar** una vez en ese paso. Ver
[Configuración](configuracion.md).

## Problemas al actualizar

| Síntoma | Causa | Solución |
| --- | --- | --- |
| `make update` se detiene con «N scans are running» | La copia de seguridad no corre mientras haya análisis en cola o en curso. | Espera a que terminen en **Análisis** y vuelve a ejecutar `make update`. `FORCE=1 make update` los marca como fallidos. |
| `make update` dice «a fixed version: not pulling» y nada cambia | Instalaste una versión y no cambiaste a la nueva. | `git fetch --tags && git checkout v<nueva> && make update`. |
| Una comprobación de exposición omite nuclei, testssl.sh o httpx | No se descargaron sus imágenes: la descarga falló. | Ejecuta `make engines`. |
| El análisis web completo omite ZAP, katana o subfinder, o no aparece | `PITANGUS_DAST_ENABLED` no está en `.env` (es experimental y viene apagado), o la descarga falló. | Añade `PITANGUS_DAST_ENABLED=1` a `.env` y ejecuta `make engines`. |
| El paso de Checkov o de Grype dice **no ejecutado (desactivado)** | Son opcionales y vienen apagados desde 0.14. | Pon `PITANGUS_CHECKOV_ENABLED=1` o `PITANGUS_GRYPE_ENABLED=1` en `.env` y ejecuta `make engines`. |
| Hallazgos de secretos nuevos tras el primer análisis | Betterleaks tiene más reglas que Gitleaks, `generic-password` viene activa y desde 0.14 se leen los archivos de credenciales, las carpetas de dependencias versionadas y los archivos ocultos. | Es lo esperado: rota los reales y haz triage del resto. |
| Menos hallazgos que antes, algunos con contador | Los problemas idénticos son una familia con su número de copias. | Es lo esperado; el contador y la lista de copias están en el hallazgo. |
| Un análisis dice que retuvo remediados | Habría remediado demasiado de golpe (la retención de remediados). | Vuelve a analizar: un segundo análisis con cobertura los libera. Quien administra puede **Marcar como remediados**. |
| El paso de nuclei dice que no se pudieron descargar las plantillas | El worker no llega a `codeload.github.com`, o un proxy alteró el archivo. | Permite ese host para el worker y vuelve a analizar; la descarga se hace una sola vez. |
| El servidor no arranca después de definir `PITANGUS_EGRESS_IPS` | El valor no es una lista de direcciones IP o rangos CIDR. | Corrige el valor en `.env` (separado por comas, 16 como máximo) y ejecuta `docker compose up -d`. |
| Se rompe un script que leía `schedule_next_at` o `runs_deleted` | Esos campos de la API cambiaron en 0.13. | Lee `schedule.next_run_at` y `runs_kept`. |
| Los hallazgos de certificado antiguos de testssl.sh salen remediados y aparecen otros nuevos | Sus huellas cambiaron una vez en 0.13. | Es lo esperado tras el primer análisis web; haz triage de los nuevos. |
| El panel se ve igual después de actualizar | El navegador conservó el panel anterior. | Recarga la página; las pestañas abiertas muestran **Recargar** cuando el servidor se actualizó. |

Más en [Solución de problemas](solucion-problemas.md).

## Siguientes pasos

- [CHANGELOG.md](../../CHANGELOG.md): cada cambio de cada versión.
- [Instalación](instalacion.md#copias-de-seguridad): copias de seguridad y restauración en detalle.
- [Hallazgos](hallazgos.md#prueba-antes-de-remediar): la prueba antes de remediar, la retención y la identidad en detalle.
- [Analizar un sitio web o una API](analisis-web.md): la comprobación de exposición y el análisis completo.
