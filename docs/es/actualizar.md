[English](../upgrading.md) · Español

# Actualizar Pitangus

Actualizar es llevar el código a una versión nueva, descargar (o reconstruir) sus imágenes y reiniciar. Tus datos se
quedan: la base de datos, `data/` y `config/` se conservan, y lo que cambie de formato se convierte al arrancar. Esta
página cubre el procedimiento general y lo que cambia al pasar a 0.13. Cada versión también lista sus cambios en
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

Si clonaste una etiqueta (`git clone --branch v0.13.x`, como en el [inicio rápido](inicio-rapido.md)), el repositorio
se queda en esa versión a propósito. Primero cambia a la nueva y luego actualiza:

```bash
git fetch --tags
git checkout v0.13.1      # la versión que quieras
make update
```

En una versión fija, `make update` lo dice y no trae código:

```text
On v0.13.1 (a fixed version): not pulling. Check out the version you want first.
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
| Tras actualizar, los análisis web omiten katana, nuclei, testssl.sh, httpx o subfinder | No se descargaron sus imágenes: `PITANGUS_DAST_ENABLED` no está en `.env`, o la descarga falló. | Añade `PITANGUS_DAST_ENABLED=1` a `.env` y ejecuta `make engines`. |
| El paso de nuclei dice que no se pudieron descargar las plantillas | El worker no llega a `codeload.github.com`, o un proxy alteró el archivo. | Permite ese host para el worker y vuelve a analizar; la descarga se hace una sola vez. |
| El servidor no arranca después de definir `PITANGUS_EGRESS_IPS` | El valor no es una lista de direcciones IP o rangos CIDR. | Corrige el valor en `.env` (separado por comas, 16 como máximo) y ejecuta `docker compose up -d`. |
| Se rompe un script que leía `schedule_next_at` o `runs_deleted` | Esos campos de la API cambiaron en 0.13. | Lee `schedule.next_run_at` y `runs_kept`. |
| Los hallazgos de certificado antiguos de testssl.sh salen remediados y aparecen otros nuevos | Sus huellas cambiaron una vez en 0.13. | Es lo esperado tras el primer análisis web; haz triage de los nuevos. |
| El panel se ve igual después de actualizar | El navegador conservó el panel anterior. | Recarga la página; las pestañas abiertas muestran **Recargar** cuando el servidor se actualizó. |

Más en [Solución de problemas](solucion-problemas.md).

## Siguientes pasos

- [CHANGELOG.md](../../CHANGELOG.md): cada cambio de cada versión.
- [Instalación](instalacion.md#copias-de-seguridad): copias de seguridad y restauración en detalle.
- [Analizar un sitio web o una API](analisis-web.md): el análisis web que 0.13 completa.
