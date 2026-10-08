[English](../deploy-vps.md) · Español

# Desplegar en un VPS

Esta guía deja Pitangus en un servidor propio (Hetzner, DigitalOcean, Hostinger, OVH o cualquier VPS con Docker), con tu dominio, HTTPS, copias de seguridad y monitorización. Para usarlo en tu portátil sigue bastando `make up`: mira [instalacion.md](instalacion.md).

Con un servidor recién creado y un registro DNS que ya apunte a él, son cuatro comandos:

```bash
git clone https://github.com/Pitangus-Dev/pitangus.git && cd pitangus
git checkout v0.12.0                                   # la versión que quieras (ver Actualizar)
make setup DOMAIN=pitangus.example.com PREBUILT=1   # HTTPS con Caddy + imágenes publicadas
make up                                             # muestra https://pitangus.example.com y el código de configuración
```

El resto de la página cuenta qué preparar antes y qué hacer después.

## Cómo queda montado

```
internet ──443/80──▶ caddy ──red edge──▶ api (panel + API, sin puerto publicado)
                                            │
                                   red default ── postgres (sin puerto publicado)
                                            │
                                          worker (los motores dentro de su imagen; sin socket de Docker)
```

- `compose.prod.yaml` añade **Caddy**: pide y renueva el certificado de tu dominio (Let's Encrypt, y ZeroSSL si falla), redirige HTTP a HTTPS y es lo único que publica puertos. La api no publica ninguno; `PITANGUS_PUBLIC_URL` y `PITANGUS_ALLOWED_ORIGINS` pasan a ser `https://<dominio>`.
- `compose.images.yaml` (con `PREBUILT`) usa las imágenes publicadas en el registro de GitHub en lugar de construirlas en el servidor. Son multiarquitectura (amd64 y arm64), llevan SBOM y procedencia, y van firmadas con cosign.
- `compose.no-socket.yaml` arranca el worker desde la imagen que ya trae los motores (`pitangus-worker`): **ningún contenedor tiene el socket de Docker**, así que nada del stack llega al Docker del servidor. Más en [Los motores y el socket de Docker](#los-motores-y-el-socket-de-docker).
- `make setup DOMAIN=…` deja los overlays en `COMPOSE_FILE` dentro de `.env`: así los usan todos los comandos `make` y también `docker compose` a secas.

## 1. Elegir el servidor

| | Mínimo | Holgado |
| --- | --- | --- |
| CPU | 2 vCPU | 4 vCPU |
| Memoria | 4 GB (+2 GB de swap) | 8 GB |
| Disco | 40 GB SSD | 80 GB SSD |
| Arquitectura | amd64 o arm64 (Hetzner CAX, Graviton, Ampere) | |

En qué se va: cada análisis ejecuta un motor a la vez, con un tope de 2 CPU y 3 GB de memoria; la app y PostgreSQL ocupan unos 400 MB en reposo. En disco, las imágenes de los motores suman unos 2 GB, la base de Trivy ~1,3 GB, la de Grype ~2,1 GB (solo si analizas imágenes de contenedor), la copia local de NVD ~0,7 GB, y cada análisis guarda una instantánea del repositorio mientras corre. Deja sitio para las copias si pasan por el mismo disco antes de salir del servidor.

Usa un **servidor dedicado** a Pitangus, no uno compartido con otras aplicaciones ni con otras personas: mira [Endurecimiento](#endurecimiento).

## 2. Preparar el sistema

En Ubuntu 24.04 (en Debian es igual, cambiando `ubuntu` por `debian` en las URL de Docker). Como root, solo la primera vez:

```bash
# Un usuario para Pitangus, con tu clave SSH; después, nunca más entres como root.
adduser --disabled-password --gecos "" pitangus
mkdir -p /home/pitangus/.ssh && cp ~/.ssh/authorized_keys /home/pitangus/.ssh/
chown -R pitangus:pitangus /home/pitangus/.ssh && chmod 700 /home/pitangus/.ssh
usermod -aG sudo pitangus && passwd pitangus   # contraseña de sudo para el mantenimiento

# SSH: solo con clave y sin root. Un drop-in que se lee primero gana al de la imagen del proveedor (50-cloud-init.conf).
printf 'PasswordAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/10-pitangus.conf
sshd -t && systemctl restart ssh

# Actualizaciones de seguridad automáticas.
apt-get update && apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades

# Cortafuegos: solo SSH, HTTP y HTTPS.
ufw default deny incoming && ufw default allow outgoing
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp
ufw enable
```

Docker Engine, desde el repositorio oficial de Docker (el paquete `docker.io` de la distribución va con retraso y no trae Compose v2):

```bash
apt-get install -y ca-certificates curl make git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker pitangus
```

Pertenecer al grupo `docker` equivale a ser root en esta máquina: dáselo solo a quien administre el servidor.

**Docker y ufw.** Los puertos que publica Docker se saltan las reglas de ufw. Por eso Pitangus solo publica el 80 y el 443 (Caddy) y nada más: PostgreSQL y la API viven en redes internas. No añadas `ports:` a otros servicios. Si tu proveedor tiene cortafuegos en la nube (Hetzner Cloud Firewall, Cloud Firewalls de DigitalOcean, el cortafuegos del VPS de Hostinger), aplica ahí la misma regla: entrada por 22, 80 y 443; salida, todo.

## 3. Apuntar el dominio

Crea un registro **A** (y **AAAA** si el servidor tiene IPv6) con el nombre que vayas a usar, por ejemplo `pitangus.example.com`, hacia la IP pública del servidor. Compruébalo antes de arrancar, porque Caddy pide el certificado nada más empezar:

```bash
dig +short pitangus.example.com     # tiene que devolver la IP del servidor
```

Si quieres, un registro CAA `0 issue "letsencrypt.org"` limita quién puede emitir certificados para ese nombre. Si lo pones, permite también `sectigo.com` (ZeroSSL, la alternativa de Caddy) para no dejarle una sola opción.

## 4. Configurar

Con el usuario `pitangus`:

```bash
git clone https://github.com/Pitangus-Dev/pitangus.git && cd pitangus
git checkout v0.12.0
make setup DOMAIN=pitangus.example.com PREBUILT=1
make doctor
```

`make setup` crea `.env` con tu UID/GID y una contraseña aleatoria para la base de datos; en modo servidor escribe además:

| Variable | Valor | Para qué |
| --- | --- | --- |
| `PITANGUS_DOMAIN` | tu dominio | Certificado y sitio de Caddy. |
| `PITANGUS_PUBLIC_URL` / `PITANGUS_ALLOWED_ORIGINS` | `https://<dominio>` | Cookies `Secure`, HSTS, CSRF y `Host` permitido. El overlay los deriva del dominio de todas formas. |
| `COMPOSE_FILE` | `compose.yaml:compose.prod.yaml:compose.no-socket.yaml[:compose.images.yaml:compose.images.no-socket.yaml]` | Que todos los comandos usen los overlays. |
| `PITANGUS_IMAGE` | `ghcr.io/pitangus-dev/pitangus` | Solo con `PREBUILT`. Para un fork: `PREBUILT=ghcr.io/tu-usuario/pitangus`. |
| `PITANGUS_METRICS_TOKEN` | 64 caracteres aleatorios | Activa `/api/metrics` (mira [Monitorización](#monitorización)). |

Sin `PREBUILT`, el servidor construye las imágenes a partir del código (unos minutos, y más memoria mientras tanto). Las dos opciones ejecutan el mismo código.

Conviene revisar en `.env` antes del primer arranque (todas en [configuracion.md](configuracion.md)):

- `PITANGUS_REQUIRE_TOTP=all`: segundo factor para todo el mundo, no solo para administradores. Recomendado si está en internet.
- `PITANGUS_DEFAULT_LOCALE=es` si tu equipo trabaja en español (comentarios en PRs, avisos, informes).
- `PITANGUS_NVD_API_KEY`: la copia de CVE se descarga en minutos en vez de horas.
- `PITANGUS_MASTER_KEY`: por defecto la clave del almacén se genera en `config/master.key`. Si la defines aquí (o desde tu gestor de secretos), guarda una copia aparte: las copias nunca la llevan en claro.
- `COMPOSE_PROFILES=backup`: copias programadas (mira [Copias de seguridad](#copias-de-seguridad)).

Guarda una copia de `.env` en tu gestor de contraseñas: contiene la contraseña de la base de datos, el token de métricas y, si la pusiste, la clave maestra.

## 5. Arrancar y crear el administrador

Con las imágenes publicadas, instala antes [cosign](https://docs.sigstore.dev/cosign/system_config/installation/): así `make up` comprueba sus firmas antes de arrancar nada y fija en `.env` el digest comprobado, de modo que cada arranque posterior (también `docker compose up`) usa exactamente esa imagen. Sin cosign arranca igual y lo avisa en una línea. `make verify-images` hace la misma comprobación por separado.

```bash
make up    # Signature verified: ghcr.io/pitangus-dev/pitangus@sha256:…  Pinned in .env: PITANGUS_IMAGE_TAG=0.12@sha256:…
```

`make up` descarga (o construye) las imágenes, arranca todo, espera a que el panel responda, descarga los motores y muestra la URL y el **código de configuración**. Abre `https://<dominio>`, introduce el código y crea tu usuario administrador; después activa el segundo factor en **Cuenta**. Si la página no carga, `make logs SERVICE=caddy` te dice si se emitió el certificado (lo habitual: el DNS todavía no apunta aquí, o el puerto 80 está cerrado).

El código solo aparece en la consola del servidor: quien abra la URL antes que tú no puede quedarse con la instancia. `make setup-code` lo vuelve a mostrar mientras no haya administrador.

## 6. GitHub App con dominio público

Sigue [github-app.md](github-app.md) con estos valores:

| Campo | Valor |
| --- | --- |
| Homepage URL | `https://<dominio>` |
| Setup URL | `https://<dominio>/oauth/callback`, con **Redirect on update** |
| Callback URL | vacío |
| Webhook | inactivo: Pitangus consulta los pull requests por su cuenta, GitHub nunca necesita llegar a tu servidor |

## Copias de seguridad

Una instancia son tres cosas: la **base de datos** (ejecuciones, hallazgos, triage, usuarios y los secretos cifrados), la **clave maestra** (`config/master.key`, o `PITANGUS_MASTER_KEY` en `.env`) y **`.env`**. `data/` guarda cachés y registros: es útil, pero todo se regenera.

**Programadas, dentro de Compose.** Añade `COMPOSE_PROFILES=backup` a `.env` y ejecuta `make up`. El servicio `backup` escribe `backups/auto-<fecha>/` (database.dump, data.tgz) cada `PITANGUS_BACKUP_INTERVAL_HOURS` (24) y borra sus propias copias con más de `PITANGUS_BACKUP_KEEP_DAYS` días (14). No detiene la app (`pg_dump` ya es coherente por sí solo), recibe solo la contraseña de la base y monta `config/` y `data/` en solo lectura. Su healthcheck se pone en rojo si la última copia tiene más de dos intervalos. `PITANGUS_BACKUP_DIR` las lleva a otra carpeta (por ejemplo, un volumen montado).

**Con cron, desde el host.** `make backup` hace lo mismo, pero detiene la API unos segundos para que `data/` también sea coherente; se niega si hay análisis en curso (cron lo reintenta al día siguiente):

```cron
30 3 * * * cd /home/pitangus/pitangus && make backup >> backups/cron.log 2>&1
```

**La clave maestra se queda fuera.** Una copia nunca lleva la clave maestra en claro junto a los secretos que abre: las copias sin cifrar la dejan fuera y llevan `master-key.sha256`, que dice qué clave necesitan. Guarda `config/master.key` (o `PITANGUS_MASTER_KEY`) una vez en tu gestor de contraseñas, nunca con las copias. No cambia, así que basta con una.

**Cifradas con age.** Para que una copia no le sirva a quien se la lleve, cífralas con [age](https://github.com/FiloSottile/age) para una clave pública cuya mitad privada nunca pisa el servidor. Así la clave maestra sí entra (`config.tgz`), cifrada como el resto, y cada copia se restaura por sí sola.

1. En tu equipo: `age-keygen -o pitangus-backup.key`. Guarda ese archivo fuera de línea (gestor de contraseñas, un USB en un cajón); muestra la clave pública, `age1…`.
2. En `.env`: `PITANGUS_BACKUP_AGE_RECIPIENT=age1…` (varias, separadas por comas: un segundo administrador, una clave de recuperación; también valen claves `ssh-ed25519 …`).
3. `make backup` necesita age en el host: `apt install age` (Debian, Ubuntu 22.04+), `dnf install age` o `brew install age`.
4. La imagen por defecto del servicio no trae age: añade `:compose.backup-age.yaml` al final de `COMPOSE_FILE` en `.env` y ejecuta `make up`, que la construye una vez. `make setup` lo respeta.

Cada copia queda con `database.dump.age`, `data.tgz.age` y `config.tgz.age`. Si la variable está puesta pero falta age, la copia falla con un mensaje claro (el servicio se detiene y explica por qué en `make logs SERVICE=backup`) en lugar de escribir archivos sin cifrar. Sin la variable, las copias funcionan como antes y avisan.

**Fuera del servidor, siempre.** Una copia en el mismo disco no sobrevive al servidor. Cifradas con age, sirve cualquier copia (`rsync`, `rclone`, un bucket). Sin age, la copia externa la tiene que cifrar la herramienta que la envía, por ejemplo [restic](https://restic.net) a cualquier bucket compatible con S3 (Backblaze B2, Hetzner Object Storage, R2…):

```cron
0 4 * * * cd /home/pitangus/pitangus && restic backup backups/ --tag pitangus && restic forget --keep-daily 14 --keep-weekly 8 --prune
```

(`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE` y las credenciales del bucket en el entorno del crontab; la contraseña de restic, fuera del servidor.) En local basta con guardar unos días: `find backups -maxdepth 1 -name '20*' -mtime +7 -exec rm -rf {} +`.

**Restaurar.** Probado, en el mismo servidor o en uno nuevo:

```bash
make restore FROM=backups/<fecha> CONFIRM=restore
make up
```

Comprueba la copia antes de tocar nada, guarda el estado actual en `backups/pre-restore-<fecha>/` (así `make restore FROM=backups/pre-restore-<fecha> CONFIRM=restore` lo deshace), borra y recrea la base de datos a partir de `database.dump`, sustituye `config/` si la copia trae `config.tgz` (si no, conserva el actual) y extrae `data/`. Cada archivo solo puede traer su propia carpeta, con ficheros y carpetas normales: una ruta absoluta, `..`, un enlace o un dispositivo hacen que rechace la copia antes de parar nada. En un **servidor nuevo**: prepáralo como arriba, recupera tu `.env`, clona la misma versión, `make setup`, copia la carpeta de la copia dentro de `backups/` y ejecuta los dos comandos. Restaura sobre la misma versión de Pitangus que hizo la copia o una más nueva: la app migra los datos hacia delante al arrancar, nunca hacia atrás. Da por hecho que `config/` está en el repositorio (el valor por defecto de `PITANGUS_HOST_CONFIG_DIR`).

- **Copia sin cifrar en un servidor nuevo:** primero devuelve la clave maestra a `config/master.key` (o `PITANGUS_MASTER_KEY` en `.env`). `tr -d ' \r\n' < config/master.key | sha256sum` tiene que dar lo mismo que el `master-key.sha256` de la copia.
- **Copia cifrada:** descífrala primero donde esté la clave privada de age (tu equipo, y luego copias la carpeta al servidor; o llevas la clave al servidor solo para esto):

  ```bash
  cd backups/<fecha>
  for f in *.age; do age -d -i ~/pitangus-backup.key -o "${f%.age}" "$f"; done
  cd ../.. && make restore FROM=backups/<fecha> CONFIRM=restore
  rm backups/<fecha>/database.dump backups/<fecha>/*.tgz   # la copia en claro; los .age se quedan
  ```

  Si llevaste la clave privada al servidor, bórrala también.

Si se pierde `config/master.key` (o cambia `PITANGUS_MASTER_KEY`), los secretos no se pueden descifrar: tocaría volver a conectar la GitHub App y a introducir el token de Jira. No se pierde nada más.

## Actualizar

```bash
git fetch --tags && git checkout v0.12.1   # o quédate en main y deja que make update lo traiga
make update
```

`make update` trae el código (`git pull --ff-only` si estás en una rama; en una etiqueta mantiene la versión que elegiste), hace una copia con `make backup` (si hay análisis en marcha se detiene: vuelve a intentarlo luego), descarga las imágenes nuevas y reinicia; la app migra la base de datos al arrancar. Lee las notas de la versión antes de saltar de versión menor. Para volver atrás: vuelve a la etiqueta anterior y `make restore FROM=backups/<la copia que hizo make update> CONFIRM=restore`, y después `make up`.

Con `PREBUILT`, la etiqueta de la imagen sigue al código que tienes (`pitangus/version.py`), así que los ficheros de compose, las reglas y las imágenes siempre coinciden. `make up` fija esa etiqueta al digest que comprobó (`PITANGUS_IMAGE_TAG=0.12@sha256:…`) y lo mantiene mientras no cambie la versión; `make update` comprueba la imagen más reciente de la versión y vuelve a fijarla (a mano: `make verify-images REPIN=1`). Un `PITANGUS_IMAGE_TAG` puesto por ti (`0.12.1`, `0.12.1@sha256:…`) se comprueba pero nunca se sustituye. Sin socket, la imagen del worker se comprueba y se fija igual (`PITANGUS_WORKER_IMAGE_TAG`); con socket, la de Opengrep se comprueba por su etiqueta.

## Monitorización

**Healthchecks.** Docker vigila todos los servicios: `api` (`/api/health`), `worker` (su latido en la base de datos) y `backup`. `make status` los muestra, y si alguno cae se reinicia solo. Desde fuera, apunta un monitor de disponibilidad a `https://<dominio>/api/health`: responde `200 {"status": "ok"}` mientras la API esté arriba. A una persona con sesión iniciada le dice además `"status": "degraded"` cuando ningún worker ha dado señales de vida (no se analizaría nada), con cuántos workers hay y si llegan a Docker.

**Métricas.** `GET /api/metrics` en formato Prometheus, con `Authorization: Bearer <PITANGUS_METRICS_TOKEN>` (desactivado mientras la variable esté vacía; entonces responde 404). Solo agregados: ni nombres de repositorios, ni identificadores, ni hallazgos.

| Métrica | Qué mide |
| --- | --- |
| `pitangus_jobs{status}` | Trabajos de la cola por estado (`queued`, `running`, `done`, `failed`). |
| `pitangus_jobs_oldest_queued_age_seconds` | Cuánto lleva esperando el trabajo más antiguo de la cola. |
| `pitangus_jobs_failed_24h` | Trabajos que fallaron en las últimas 24 horas. |
| `pitangus_workers_alive` / `pitangus_workers_docker` | Workers con latido reciente / que pueden lanzar los motores. |
| `pitangus_worker_last_heartbeat_age_seconds` | Segundos desde el último latido. |
| `pitangus_runs_24h{type,status}` | Ejecuciones creadas en las últimas 24 horas. |
| `pitangus_run_duration_seconds_24h{type,status,quantile}` | Duración de las que terminaron: p50, p95 y el máximo (`quantile="1"`). |
| `pitangus_info{version}` | Versión que sirve el endpoint. |

```yaml
# prometheus.yml
scrape_configs:
  - job_name: pitangus
    scheme: https
    metrics_path: /api/metrics
    authorization: { credentials_file: /etc/prometheus/pitangus-token }
    static_configs: [{ targets: ["pitangus.example.com"] }]
```

Recógelas a través del dominio (la API solo acepta su `Host` público). Alertas que merecen la pena:

```yaml
- alert: PitangusNoWorker
  expr: pitangus_workers_alive == 0 or pitangus_workers_docker == 0
  for: 5m
- alert: PitangusQueueStuck
  expr: pitangus_jobs_oldest_queued_age_seconds > 3600
- alert: PitangusJobsFailing
  expr: pitangus_jobs_failed_24h > 5
```

**Logs.** `make logs` (API) y `make logs SERVICE=worker|caddy|backup`. Docker los rota (10 MB × 5 por servicio). El log de accesos de Caddy va en JSON y oculta las cookies y `Authorization`.

## Los motores y el socket de Docker

En un servidor, `make setup DOMAIN=…` ejecuta los motores **dentro de la propia imagen del worker**: Trivy, OSV-Scanner, Gitleaks, Grype, Checkov, zizmor y Opengrep, en las mismas versiones fijadas. Ningún contenedor monta el socket de Docker, que en la práctica equivale a ser root en el servidor.

La alternativa es lanzar cada motor en un contenedor hermano a través del socket, y hay que pedirla expresamente con `make setup DOMAIN=… SOCKET=1`. Esto es lo que aísla cada opción:

| | Sin socket (lo normal en un servidor) | Con socket (`SOCKET=1`; lo normal en un portátil) |
| --- | --- | --- |
| Si alguien toma el worker | Se queda con su contenedor: la base de datos y los secretos guardados, no el servidor | Maneja el Docker del servidor: es root |
| Si un repositorio hostil rompe un motor | El motor corre con el usuario del worker y dentro de su contenedor: consigue lo mismo que el worker (base de datos, clave maestra, tokens guardados), pero no el servidor | Queda encerrado en un contenedor de usar y tirar: solo lectura, sin red en los pasos que no la necesitan, y solo ve el código que analiza |
| Análisis de imágenes de un registro que no es Docker Hub | El motor resuelve el nombre del registro por su cuenta, después de que Pitangus lo compruebe | El nombre queda clavado a la dirección comprobada, así que no cabe un *DNS rebinding* |
| Recursos | Los motores comparten el techo del worker (`PITANGUS_WORKER_MEMORY`, 4 GB) | Cada motor tiene el suyo (3 GB, 2 CPU) |

Lo normal en un servidor sacrifica la segunda fila para ganar la primera. Para escapar de un motor hace falta un fallo en su parser. Con el socket, en cambio, cualquier cosa que logre ejecutar código en el worker se queda con el servidor. En ambos casos sigue haciendo falta una máquina dedicada, sin nada más instalado.

Los servidores que ya estaban montados siguen como estaban. Para pasarlos al modo sin socket, `make setup DOMAIN=… SOCKET=0` y después `make up`. Para volver al socket, `SOCKET=1`.

## Endurecimiento

- **Sin socket de Docker por defecto.** Lo tienes [arriba](#los-motores-y-el-socket-de-docker). Con `SOCKET=1`, el socket equivale a root: quien se haga con el worker controla el servidor. La API nunca lo tiene, pero entonces la frontera de verdad es la máquina: una **VM dedicada**, sin otras aplicaciones ni otros inquilinos, y solo con los administradores en el grupo `docker`.
- **PostgreSQL con lo justo.** Su contenedor conserva solo las capacidades que su entrypoint necesita para adueñarse de la carpeta de datos y pasar al usuario `postgres` (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`), con `no-new-privileges`.
- **Segundo factor para todos** (`PITANGUS_REQUIRE_TOTP=all`), y da de baja a quien se vaya.
- **Acota quién llega** si tu equipo tiene direcciones fijas: permite el 443 solo desde ellas en el cortafuegos del proveedor.
- **La dirección real del cliente.** Detrás de Caddy, la API se fía de `X-Forwarded-For` (`PITANGUS_FORWARDED_ALLOW_IPS`, que pone el overlay) porque solo Caddy, el worker y PostgreSQL llegan a ella, y Caddy sustituye cualquier `X-Forwarded-For` que mande un cliente. Así, el límite de intentos de inicio de sesión y el log de auditoría ven la dirección de cada persona y no la del proxy.
- **Lo que añade el proxy.** Redirección de HTTP a HTTPS, HTTP/2 y HTTP/3, un límite de 2 MB por petición (el de la app es 1 MB), tiempos máximos para cabeceras y cuerpo, compresión solo para los ficheros estáticos del panel, y sin cabeceras `Server` ni `Via`. Las cabeceras de seguridad (CSP, HSTS, nosniff, frame, referrer) siguen siendo las de la app, así que hay un único juego coherente.
- **Imágenes.** Todo lo de terceros va fijado por digest; las imágenes publicadas están firmadas y llevan SBOM y procedencia SLSA (`docker buildx imagetools inspect ghcr.io/pitangus-dev/pitangus:0.9 --format '{{json .SBOM}}'`).

## Coolify y Dokploy

Las dos plataformas ponen delante su propio proxy (Traefik) y sus certificados, así que Caddy sobra: despliega **solo `compose.yaml`** como aplicación Docker Compose desde el repositorio Git y deja que la plataforma lleve tu dominio al **servicio `api`, puerto 8766**. Estas notas siguen el comportamiento documentado de cada plataforma; todavía no hemos probado Pitangus en ellas.

Variables que hay que definir en la plataforma (las escribe en `.env`, que es lo que leen los servicios):

```bash
PITANGUS_DB_PASSWORD=<openssl rand -hex 24>
PITANGUS_PUBLIC_URL=https://pitangus.example.com
PITANGUS_ALLOWED_ORIGINS=https://pitangus.example.com
PITANGUS_FORWARDED_ALLOW_IPS=*              # solo el proxy de la plataforma llega a la api
PITANGUS_METRICS_TOKEN=<openssl rand -hex 32>
PITANGUS_UID=1000
PITANGUS_GID=1000
DOCKER_SOCKET_GID=<stat -c %g /var/run/docker.sock, en el servidor>
```

A tener en cuenta en las dos:

- El worker monta `/var/run/docker.sock` y lanza contenedores hermanos que montan carpetas por su ruta **en el host**. El worker averigua esas rutas inspeccionándose a sí mismo, así que los montajes tienen que ser carpetas reales del host (no volúmenes con nombre).
- `config/` tiene que sobrevivir a los redespliegues: pon en `PITANGUS_HOST_CONFIG_DIR` una ruta absoluta del servidor (por ejemplo `/srv/pitangus/config`, del usuario `PITANGUS_UID`). Perderla obliga a volver a introducir todos los secretos. `data/` solo guarda cachés y logs.
- El servicio `opengrep` construye la imagen del motor y termina: es lo esperado, no un despliegue fallido.
- La plataforma construye las imágenes a partir del repositorio (allí no se usa `compose.images.yaml`). El primer despliegue tarda unos minutos.
- **Coolify:** recurso de tipo *Docker Compose*, ubicación del compose `/compose.yaml`. Coolify conserva los montajes `./data` en la carpeta de la aplicación entre despliegues.
- **Dokploy:** servicio de tipo *Compose*, ruta `./compose.yaml`. Cada despliegue vuelve a clonar el código, así que lleva `PITANGUS_HOST_CONFIG_DIR` fuera del clon (Dokploy sugiere `../files/`).
- Los consejos de endurecimiento siguen valiendo: un PaaS que en el mismo servidor también ejecuta aplicaciones de otras personas es justo lo que el socket de Docker vuelve arriesgado.

Si algo falla, [solucion-problemas.md](solucion-problemas.md) recoge las causas habituales; para problemas del proxy, `make logs SERVICE=caddy`.
