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

**Servidor con dominio** ([despliegue-vps.md](despliegue-vps.md)). Las lee Compose, no la app; `make setup DOMAIN=… [PREBUILT=1] [SOCKET=1]` las escribe (`make setup PREBUILT=1`, sin dominio, solo `COMPOSE_FILE` y `PITANGUS_IMAGE`).

| Variable | Por defecto | Para qué |
| --- | --- | --- |
| `PITANGUS_DOMAIN` | — | Dominio para el que Caddy pide el certificado (`compose.prod.yaml`). La URL pública y los orígenes permitidos pasan a ser `https://<dominio>`. |
| `COMPOSE_FILE` | `compose.yaml` | Ficheros de Compose que usan todos los comandos, p. ej. `compose.yaml:compose.prod.yaml:compose.no-socket.yaml:compose.images.yaml:compose.images.no-socket.yaml`. `make setup` conserva `compose.backup-age.yaml` si lo añadiste. |
| `PITANGUS_IMAGE` | — | Imagen publicada que se ejecuta en lugar de construirla (`compose.images.yaml`), p. ej. `ghcr.io/pitangus-dev/pitangus`. |
| `PITANGUS_IMAGE_TAG` | la versión del código | Etiqueta de esa imagen; admite digest (`0.12@sha256:…`). |
| `PITANGUS_WORKER_IMAGE_TAG` | la versión del código | Lo mismo para `<PITANGUS_IMAGE>-worker`, el worker con los motores dentro (sin socket). `make up` fija las dos al digest que comprobó. |
| `COMPOSE_PROFILES` | — | `backup` activa el servicio de copias programadas. |
| `PITANGUS_BACKUP_DIR` | `./backups` | Dónde escribe el servicio de copias. |
| `PITANGUS_BACKUP_INTERVAL_HOURS` / `_KEEP_DAYS` | `24` / `14` | Cada cuánto copia y cuántos días guarda sus propias copias. |
| `PITANGUS_BACKUP_AGE_RECIPIENT` | — | Claves públicas de age (`age1…` o `ssh-ed25519 …`, separadas por comas) con las que se cifra cada copia, clave maestra incluida; también la lee `make backup` (necesita `age` en el host). El servicio necesita `compose.backup-age.yaml` en `COMPOSE_FILE`. Vacía: sin cifrar y sin la clave maestra. |

**Concesión consciente:** con el `compose.yaml` del repositorio, para no instalar nada más que Docker, el worker lanza los motores como contenedores hermanos por el socket de Docker, y eso equivale a root en el host. En un servidor, `make setup DOMAIN=…` (`compose.no-socket.yaml`) y [`deploy/compose.yaml`](../../deploy/compose.yaml) usan en cambio la imagen del worker con los motores dentro, sin socket. [Qué aísla cada opción](despliegue-vps.md#los-motores-y-el-socket-de-docker).

