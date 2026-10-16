[English](../configuration.md) · Español

# Configuración

Todas las variables son opcionales y se ponen en `.env` (copia de `.env.example`). Tras cambiarlas: `docker compose up -d`. `python -m pitangus check-config` (o `make cli ARGS=check-config`) las revisa todas; el servidor y el worker lo hacen al arrancar y se detienen con un mensaje claro si alguna no es válida. En otras plataformas, mira [despliegue.md](despliegue.md).


| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `PITANGUS_HOST_BIND` / `PITANGUS_HOST_PORT` | `127.0.0.1` / `8766` | Dónde se publica el panel en el host. |
| `PITANGUS_PUBLIC_URL` | `http://127.0.0.1:8766` | URL con la que se abre el panel; decide cookies `Secure`, HSTS y la Setup URL de la App. |
| `PITANGUS_ALLOWED_ORIGINS` | 127.0.0.1 y localhost | Orígenes aceptados (Host y CSRF). |
| `PITANGUS_DEFAULT_LOCALE` | `en` | `en` o `es`. Idioma de los comentarios en PRs, los avisos, las incidencias de Jira, los informes y la salida de la CLI cuando nadie pide uno en persona. El panel no lo usa: sigue el idioma del navegador y cada persona puede cambiarlo desde la barra lateral o la pantalla de inicio de sesión. |
| `PITANGUS_MASTER_KEY` | se genera en `config/` | Clave maestra (`openssl rand -base64 32`): cifra todos los secretos de la base. Obligatoria donde no hay disco persistente; la misma en la API y en cada worker. |
| `PITANGUS_PREVIOUS_MASTER_KEY` | — | La clave maestra que había antes de cambiarla, mientras los hallazgos de secretos pasan a la nueva. La identidad de un secreto es el HMAC de su valor con una clave derivada de la clave maestra: con esta variable, cada análisis la calcula también con la clave anterior, y cada secreto que lee conserva su entrada, su triaje y su incidencia de Jira. Sin ella, tras el cambio, los secretos encontrados se abren de nuevo con la clave nueva y sus entradas antiguas quedan abiertas sin verificar, nunca remediadas. Quítala cuando haya pasado un análisis completo de cada repositorio. No descifra los secretos guardados (integraciones, canales): esos necesitan la clave con la que se guardaron. |
| `PITANGUS_SESSION_KEY` | se genera, sellada en la base | Clave que firma las cookies de sesión (32 bytes en base64). Solo para fijarla desde un gestor de secretos. |
| `PITANGUS_REQUIRE_TOTP` | `admins` | `admins`, `all` o `none`. |
| `PITANGUS_NVD_API_KEY` | — | API key de NVD: descarga de CVE más rápida. Va en cabecera y nunca se registra. |
| `PITANGUS_DB_PASSWORD` | (generada) | Contraseña de PostgreSQL; `make setup` la crea en `.env`. |
| `PITANGUS_DATABASE_URL` | (compose) | Conexión a PostgreSQL. `compose.yaml` la arma con la contraseña; fuera de compose, p. ej. `postgresql://pitangus:…@localhost:5432/pitangus` (las URL `postgres://` que dan las bases gestionadas valen tal cual). |
| `PITANGUS_DATA_DIR` | `data` (CLI) o una carpeta temporal (ASGI) | Cachés reconstruibles, carpetas de trabajo y logs opcionales en archivo. Compose la fija en `/data`; el estado de la aplicación sigue en PostgreSQL. |
| `PITANGUS_CONFIG_DIR` | la carpeta de configuración del usuario en la plataforma | Carpeta de `master.key` cuando no defines `PITANGUS_MASTER_KEY`. Compose la fija en `/config`. |
| `PITANGUS_EMBEDDED_WORKER` | `1` | `1`: el servidor también ejecuta los análisis (un solo proceso). En compose el API usa `0` y el servicio `worker` los ejecuta. |
| `PITANGUS_BIND` | `127.0.0.1` | Interfaz que usa `pitangus serve`. Compose la cambia dentro del contenedor; usa `PITANGUS_HOST_BIND` para controlar la publicación en el host. |
| `PITANGUS_CVE_SYNC` | `on` | `off` desactiva la copia local de NVD. |
| `PITANGUS_EUVD` | `on` | `off` no consulta EUVD (ENISA) cuando NVD no puntúa un CVE. Solo sale el identificador del CVE. |
| `PITANGUS_PR_POLL_SECONDS` | `300` | Cada cuánto se consultan los PRs vigilados. |
| `PITANGUS_BRANCH_MIN_MINUTES` | `60` | Pausa mínima entre dos reanálisis automáticos de la rama principal de un mismo repositorio (mínimo 10). |
| `PITANGUS_ADVISORY_WATCH_HOURS` | `24` | Cada cuántas horas se contrastan las dependencias ya analizadas con los avisos nuevos (sin conexión). `0` lo apaga. |
| `PITANGUS_ALLOW_PRIVATE_WEBHOOKS` | vacío | `1` permite avisos a webhooks de la red interna (por defecto se bloquean: SSRF). |
| `PITANGUS_ALLOW_PRIVATE_REGISTRIES` | — | `1` permite analizar imágenes de registros con IP privada (tu red interna). Por defecto se bloquean para evitar SSRF. |
| `PITANGUS_<MOTOR>_ENABLED` | sin definir: decide el panel | Fija un motor de análisis encendido (`1`) o apagado (`0`) para todo el servidor, por encima de lo que eligió un administrador en **Ajustes → Motores de análisis**: ver [Motores de análisis](#motores-de-análisis). |
| `PITANGUS_COVERAGE_MODE` | `on` | Cómo prueba un análisis que miró antes de marcar nada como remediado ([hallazgos.md](hallazgos.md#prueba-antes-de-remediar)). `on` solo remedia lo que el motor dueño del hallazgo probó que ya no está donde miró, con la cobertura por archivo, los hallazgos sin verificar y la retención de remediados; `shadow` los calcula, guarda lo que cambiarían y remedia como antes de 0.14; `off` no los calcula. Una ejecución de un motor que no terminó no abre ni remedia nada en ningún modo. Lo leen el worker y la API. |
| `PITANGUS_IDENTITY_MODE` | `v2` | Cómo se identifican los hallazgos: `v2` guarda un hallazgo por familia de problemas idénticos, según su identidad canónica, con su contador; `shadow` mantiene las huellas de cada motor, calcula además la identidad canónica y guarda las diferencias; `v1` usa solo las huellas de cada motor. Si `pitangus identity-gate` no da 0/0 en un repositorio analizado dos veces sobre el mismo commit, pon `shadow` hasta que lo dé ([hallazgos.md](hallazgos.md#una-identidad-por-problema)). |
| `PITANGUS_SECRET_VALIDATION` | apagado | Betterleaks pregunta al proveedor de cada secreto si sigue activo: le envía el secreto ([seguridad.md](seguridad.md#qué-sale-de-tu-máquina)). Un secreto activo pasa a actuar primero, uno revocado a seguimiento; ninguno se oculta. |
| `PITANGUS_IGNORE_REPO_SUPPRESSIONS` | apagado | Lo que el repositorio analizado dice para suprimir resultados no suprime nada: comentarios en el código (`gitleaks:allow`, `# zizmor: ignore[…]`, `trivy:ignore`, `checkov:skip=`, `nosemgrep`) y archivos que un motor cargaría (`.gitleaksignore`, `.github/zizmor.yml`, `.trivyignore`, `.checkov.yaml`, `osv-scanner.toml`). Apagado, se respetan y cada resultado que suprimen figura en Excluidos con su regla, archivo y línea y qué lo suprimió ([analisis-de-codigo.md](analisis-de-codigo.md#lo-que-el-repositorio-les-dice-a-los-motores)). |
| `PITANGUS_SECRETS_IGNORE_INLINE_ALLOW` | apagado | Su nombre antes de la 0.14.1 (solo motores de secretos): se sigue leyendo, con el mismo significado que `PITANGUS_IGNORE_REPO_SUPPRESSIONS`. |
| `PITANGUS_THIRD_PARTY_RULES` | apagado | Añade a Opengrep 259 reglas de sast-rules de GitLab (solo MIT y Apache-2.0, procedencia comprobada archivo a archivo: [third_party/gitlab-sast-rules/NOTICE](../../third_party/gitlab-sast-rules/NOTICE)) junto a las de Pitangus: más cobertura de Java, Scala, C#, Go y Python, con los textos de las reglas en inglés. Apagado por defecto por su ruido: medidas sobre un corpus público de 18 aplicaciones, vulnerables a propósito y reales, ninguna regla llegó al 85% de precisión con al menos 3 coincidencias. Encendido, una coincidencia de GitLab en la misma línea que una de Pitangus y por la misma debilidad (CWE) se funde con ella: un solo hallazgo, con los textos y la severidad de Pitangus y la regla de GitLab entre sus reglas relacionadas. |
| `PITANGUS_SAST_OPT_IN_RULES` | vacío | Reglas de Opengrep de Pitangus desactivadas por defecto que quieres activar, separadas por comas: `appsec.js.dom-xss-sink` (3 de 18 coincidencias eran XSS en el corpus medido, [analisis-de-codigo.md](analisis-de-codigo.md#motores-de-análisis)). Mientras una regla está desactivada no informa nada, y lo que encontró antes aparece como no comprobado, nunca remediado. |
| `PITANGUS_FIX_HOLD_PERCENT` / `PITANGUS_FIX_HOLD_MINIMUM` | `30` / `10` | Con el contrato de cobertura activo, un análisis que remediaría al menos esta parte de los hallazgos abiertos de un activo, y al menos estos, retiene sus remediados hasta que el siguiente análisis completo los confirme. |
| `PITANGUS_UNSEEN_WARN_SCANS` | `3` | Tras estos análisis sin poder comprobar un hallazgo abierto, la página del activo avisa. |
| `PITANGUS_EGRESS_IPS` | vacío | Las direcciones IP públicas o rangos CIDR desde los que salen los análisis web (los del worker), separados por comas, 16 como máximo: `203.0.113.10, 2001:db8::/48`. La revisión de un análisis web se las muestra a quien tenga que permitirlas en un firewall o WAF. Un valor inválido impide que el servidor arranque. Vacía, quien administra puede detectar una vez desde el panel la dirección de la API (una petición a `api.ipify.org`, ver [seguridad.md](seguridad.md#qué-sale-de-tu-máquina)); defínela cuando el worker sale por otra dirección. |
| `PITANGUS_TLS_CERT` / `PITANGUS_TLS_KEY` | — | Archivos de certificado y clave privada para TLS sin proxy. Debes definir los dos. |
| `PITANGUS_ALLOW_INSECURE_HTTP` | vacío (apagado) | `1` deja arrancar el servidor cuando `PITANGUS_PUBLIC_URL` es `http://` en claro en una dirección que no sea `127.0.0.1`/`localhost`, algo que si no rechaza. Contraseñas, cookies de sesión y tokens viajan entonces sin cifrar por la red: solo en una red de confianza y bajo tu responsabilidad. Mejor usa HTTPS. |
| `PITANGUS_DOWNLOAD_TIMEOUT` | `900` | Segundos que puede tardar la descarga del archivo de un repositorio desde GitHub antes de que el análisis se rinda (mínimo 60). Súbelo para repositorios muy grandes o conexiones lentas. |
| `PITANGUS_API_MEMORY`, `PITANGUS_WORKER_MEMORY` | `1g`, `2g` (`4g` para el worker en `deploy/compose.yaml`, donde los motores corren dentro) | Topes de memoria de los contenedores de la API y del worker en Compose, para que un proceso desbocado no deje sin memoria al host ni a Postgres. Los contenedores de los motores tienen los suyos (3 GB, 2 CPU). |
| `DOCKER_SOCKET_GID` | lo detecta `make` | Grupo dueño del socket de Docker en Linux y en WSL con Docker nativo (`stat -Lc %g /var/run/docker.sock`), para que el worker pueda arrancar los motores. Lo lee Compose, no la app; ponlo solo si arrancas directamente con `docker compose`. No hace falta en Docker Desktop ni OrbStack (grupo `0`, que siempre se añade). |
| `GITHUB_APP_ID` + `GITHUB_APP_SLUG` + `GITHUB_APP_PRIVATE_KEY_FILE` | — | Alternativa al formulario: montar la App como secreto del despliegue. Manda sobre el almacén. |
| `GITHUB_TOKEN` / `GITLAB_TOKEN` | — | Tokens entregados por el despliegue para fuentes de código. La conexión por token de GitHub funciona; el proveedor de GitLab está declarado pero desactivado a propósito hasta que se pruebe, así que `GITLAB_TOKEN` no habilita GitLab hoy. Para GitHub, prefiere la GitHub App. |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | — | Claves que quien opera puede listar y validar con la CLI. El análisis con IA no está implementado y estas claves no reciben código ni hallazgos. |
| `PITANGUS_HOST_CONFIG_DIR` | `./config` | Carpeta del host para la clave maestra, cuando no se define `PITANGUS_MASTER_KEY`. |
| `PITANGUS_HOST_DATA_DIR` / `PITANGUS_HOST_RULES_DIR` | las detecta Compose | Rutas absolutas del host que se montan en los contenedores hermanos de los motores. Defínelas solo cuando la detección automática no pueda resolver los bind mounts. |
| `PITANGUS_FORWARDED_ALLOW_IPS` | vacío | Detrás de un proxy inverso que sea el único camino hasta la API: las direcciones del proxy cuyo `X-Forwarded-For` se cree (`*` = cualquiera). Sin ella, el límite de intentos de inicio de sesión y los logs ven la dirección del proxy para todo el mundo. `compose.prod.yaml` la pone para Caddy. |
| `PITANGUS_ENGINE_RUNNER` | `auto` | `docker`: cada motor en un contenedor hermano a través del socket de Docker. `local`: los motores instalados en la imagen del worker (`pitangus-worker`), sin socket. `auto`: Docker si responde; si no, los motores instalados. |
| `PITANGUS_PERIODIC` | `leader` | `leader`: un worker ejecuta las tareas periódicas con su propio reloj. `external`: las dispara un programador con `pitangus periodic` o `GET /api/cron` ([despliegue.md](despliegue.md#tareas-periódicas)). |
| `PITANGUS_CRON_TOKEN` / `CRON_SECRET` | vacío (apagado) | Token bearer para `GET /api/cron`, solo con `PITANGUS_PERIODIC=external`. Mínimo 32 caracteres. `CRON_SECRET` es el que envía Vercel Cron. |
| `PITANGUS_LOG_FORMAT` | `text` | `json`: un objeto JSON por línea en la salida del proceso. |
| `PITANGUS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` o `ERROR`. Los logs de depuración también pasan por el filtro de secretos. |
| `PITANGUS_LOG_FILE` | vacío (Compose: `logs/app.log`) | Escribe además los registros en JSON en este archivo, rotado a 10 MB × 5; una ruta relativa va dentro de la carpeta de datos. |
| `PITANGUS_METRICS_TOKEN` | vacío (apagado) | Activa `/api/metrics` (Prometheus) para peticiones con `Authorization: Bearer <token>`. Mínimo 32 caracteres: `openssl rand -hex 32`. |
| `PITANGUS_IMPORT_TOKEN` | vacío (apagado) | Activa `POST /api/ci/sarif`, con el que la CI importa el SARIF 2.1.0 de otra herramienta en un activo existente usando `Authorization: Bearer <token>` (sin sesión). Mínimo 32 caracteres: `openssl rand -hex 32`. También es lo que envía `pitangus import-sarif --server`, leído del entorno. |

## Motores de análisis

Un administrador enciende o apaga cada motor en **Ajustes → Motores de análisis**; el cambio aplica desde el próximo
análisis y queda registrado con quién lo hizo y cuándo. Las filas se agrupan por lo que revisan: código y dependencias
(Opengrep, Trivy, OSV-Scanner), secretos (Betterleaks), infraestructura y CI (Checkov, zizmor), imágenes (Grype) y web
(httpx, testssl.sh, nuclei, el análisis web completo y katana). Por defecto: todos encendidos menos Checkov, Grype y el
análisis web completo.

Apagar un motor no oculta nada. Su paso en cada análisis dice **no ejecutado (desactivado)**, con dónde volver a
activarlo, y lo que encontró antes sigue abierto y nunca se da por remediado (no miró). Si todos los motores de un tipo
de revisión están apagados (secretos, por ejemplo), el panel lo advierte y cada análisis dice que esa revisión no se hizo.

Una variable definida en el entorno del servidor manda sobre el panel y bloquea ese interruptor: el panel lo muestra
**Fijado por el servidor**, con el nombre de la variable, y el paso de un motor que mantiene apagado también la nombra.
Defínela para la API y para el worker. Sin definir (o vacía), aplica lo que eligió el panel.

| Variable | Motor |
| --- | --- |
| `PITANGUS_OPENGREP_ENABLED` | Opengrep (SAST con las reglas de Pitangus) |
| `PITANGUS_TRIVY_ENABLED` | Trivy (dependencias, infraestructura como código, secretos e imágenes) |
| `PITANGUS_OSV_SCANNER_ENABLED` | OSV-Scanner (dependencias contra OSV; también las vulnerabilidades conocidas de las versiones que ve un análisis web) |
| `PITANGUS_BETTERLEAKS_ENABLED` | Betterleaks (secretos) |
| `PITANGUS_CHECKOV_ENABLED` | Checkov, en código e imágenes: más comprobaciones de Terraform, CloudFormation y Dockerfile, y pipelines distintos de GitHub Actions. Apagado por defecto. |
| `PITANGUS_ZIZMOR_ENABLED` | zizmor (GitHub Actions) |
| `PITANGUS_GRYPE_ENABLED` | Grype, una segunda opinión sobre los paquetes de las imágenes junto a Trivy (discrepan sobre todo en correcciones retroportadas). Apagado por defecto. |
| `PITANGUS_HTTPX_ENABLED` / `PITANGUS_TESTSSL_ENABLED` / `PITANGUS_NUCLEI_ENABLED` | Las herramientas de la comprobación de exposición. Con las tres apagadas, la comprobación no arranca y dice por qué. |
| `PITANGUS_DAST_ENABLED` | El análisis web completo (experimental, apagado por defecto): análisis web y de API pasivos de dominios verificados con ZAP (spider o las operaciones GET y HEAD de una definición OpenAPI, y reglas pasivas, nunca un ataque), que lanza un administrador desde **Nuevo análisis → Análisis web completo**, los análisis que programa (la tarea periódica busca los pendientes cada 5 minutos) y la búsqueda de hosts relacionados con subfinder. Necesita el runner de Docker. La comprobación de exposición ligera no lo necesita. Ver [Analizar un sitio web o una API](analisis-web.md). |
| `PITANGUS_KATANA_ENABLED` | katana, el rastreador del análisis web completo (solo funciona con él). |

**Imágenes.** Cada fila dice si las imágenes del motor están en el servidor del worker. Un análisis que ejecuta el
servidor nunca descarga una que falta sobre la marcha: el motor queda como no ejecutado (se está preparando y correrá en
el próximo análisis), y lo que encontró antes sigue abierto. Un análisis puntual sin servidor detrás (`pitangus scan`,
la GitHub Action, el hook de pre-commit) descarga por digest la imagen que falta al empezar, y solo lo dice si la
descarga falla. Nadie tiene que acordarse de descargarla: activar un motor en el panel encola sus
imágenes al momento, y cada 5 minutos el worker encola las de todo motor activo (por el panel o por el entorno) cuya
imagen fijada falta, como tras una actualización que cambió un digest. El worker las descarga por digest en un carril
propio, así que los análisis en cola siguen corriendo, una preparación por motor a la vez; si falla (sin conexión, por
ejemplo), espera una hora antes de reintentar por su cuenta, y **Preparar motor** reintenta al momento. `make engines` solo lee el entorno y `.env`; el resto lo prepara el worker.
Con los motores instalados en la imagen del worker (`PITANGUS_ENGINE_RUNNER=local`) no hay nada que descargar.

**Servidor con dominio** ([despliegue-vps.md](despliegue-vps.md)). Las lee Compose, no la app; `make setup DOMAIN=… [PREBUILT=1] [SOCKET=1]` las escribe (`make setup PREBUILT=1`, sin dominio, solo `COMPOSE_FILE` y `PITANGUS_IMAGE`).

| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `PITANGUS_DOMAIN` | — | Dominio para el que Caddy pide el certificado (`compose.prod.yaml`). La URL pública y los orígenes permitidos pasan a ser `https://<dominio>`. |
| `COMPOSE_FILE` | `compose.yaml` | Ficheros de Compose que usan todos los comandos, p. ej. `compose.yaml:compose.prod.yaml:compose.no-socket.yaml:compose.images.yaml:compose.images.no-socket.yaml`. `make setup` conserva `compose.backup-age.yaml` si lo añadiste. |
| `PITANGUS_IMAGE` | — | Imagen publicada que se ejecuta en lugar de construirla (`compose.images.yaml`), p. ej. `ghcr.io/pitangus-dev/pitangus`. |
| `PITANGUS_IMAGE_TAG` | la versión del código | Etiqueta de esa imagen; admite digest (`0.15@sha256:…`). |
| `PITANGUS_WORKER_IMAGE_TAG` | la versión del código | Lo mismo para `<PITANGUS_IMAGE>-worker`, el worker con los motores dentro (sin socket). `make up` fija las dos al digest que comprobó. |
| `COMPOSE_PROFILES` | — | `backup` activa el servicio de copias programadas. |
| `PITANGUS_BACKUP_DIR` | `./backups` | Dónde escribe el servicio de copias. |
| `PITANGUS_BACKUP_INTERVAL_HOURS` / `_KEEP_DAYS` | `24` / `14` | Cada cuánto copia y cuántos días guarda sus propias copias. |
| `PITANGUS_BACKUP_AGE_RECIPIENT` | — | Claves públicas de age (`age1…` o `ssh-ed25519 …`, separadas por comas) con las que se cifra cada copia, clave maestra incluida; también la lee `make backup` (necesita `age` en el host). El servicio necesita `compose.backup-age.yaml` en `COMPOSE_FILE`. Vacía: sin cifrar y sin la clave maestra. |

**Concesión consciente:** con el `compose.yaml` del repositorio, para no instalar nada más que Docker, el worker lanza los motores como contenedores hermanos por el socket de Docker, y eso equivale a root en el host. En un servidor, `make setup DOMAIN=…` (`compose.no-socket.yaml`) y [`deploy/compose.yaml`](../../deploy/compose.yaml) usan en cambio la imagen del worker con los motores dentro, sin socket. [Qué aísla cada opción](despliegue-vps.md#los-motores-y-el-socket-de-docker).

