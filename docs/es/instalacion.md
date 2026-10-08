[English](../installation.md) · Español

# Instalación

## Requisitos

| | Mínimo | Notas |
| --- | --- | --- |
| Sistema | Linux, macOS o Windows con WSL2 | amd64 o arm64 (Apple Silicon incluido). |
| Docker | Engine 24+ y Compose v2.24+ | Docker Desktop, OrbStack o Docker Engine. |
| make y git | cualquiera | `make` ya viene en macOS; en Debian/Ubuntu `sudo apt install make git`. En Windows, dentro de WSL2. |
| Memoria | 4 GB libres | La app usa ~200 MB en reposo; cada análisis lanza un motor a la vez, limitado a 3 GB. |
| Disco | 8 GB libres | Imágenes (~1 GB), bases de vulnerabilidades de Trivy (~1,3 GB) y de Grype (~2,1 GB, solo si analizas imágenes de contenedor), copia local de NVD (~0,7 GB) y tus ejecuciones. |
| Red de salida | HTTPS a GitHub, NVD, CISA y EPSS | Detalle en [seguridad.md](seguridad.md#qué-sale-de-tu-máquina). No hace falta ninguna entrada desde internet. |
| Cuenta | GitHub (personal u organización que administres) | Para crear tu GitHub App. |

No hace falta instalar Python, Node ni los motores de análisis: todo va en contenedores. **`make doctor`** comprueba los requisitos y dice cómo arreglar lo que falte.

## Primera instalación

```bash
git clone https://github.com/pitangus-dev/pitangus.git
cd pitangus
make up
```

`make up` crea `.env` desde `.env.example` con tu usuario del host (`PITANGUS_UID`/`PITANGUS_GID`, para que `data/` y `config/` sean tuyas y no de root), construye, arranca y espera a que el panel responda. Sin `make`: `sh scripts/init-env.sh && docker compose up --build -d`.

La primera construcción tarda unos minutos: compila el panel, descarga el binario de Opengrep y comprueba su SHA-256. Verás cuatro servicios: `api` (el contenedor `pitangus`, con el panel y la API), `worker` (ejecuta los análisis) y `postgres` (el contenedor `pitangus-postgres`, la base de datos) se quedan en marcha; `opengrep` solo construye la imagen del motor y **termina enseguida**: es normal.

Si prefieres no construir nada, ejecuta `make setup PREBUILT=1` antes de `make up`: descarga las imágenes publicadas y firmadas de la versión que tienes (`pitangus/version.py`) en lugar de construirlas. Sigue siendo una instalación local en <http://127.0.0.1:8766>; con [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) instalado, `make up` comprueba antes sus firmas y fija en `.env` el digest comprobado (sin cosign arranca igual y lo avisa).

Al terminar muestra el **código de configuración** (también con `make setup-code`, o en los logs):

```
================================================================
  Primer arranque: crea el administrador en el panel con este código
      ABCD-EFGH-JKLM
  (solo sirve una vez y solo mientras no haya usuarios)
================================================================
```

Abre <http://127.0.0.1:8766>, escribe ese código y crea tu usuario administrador. El código demuestra que eres quien controla el servidor: sin él, el primero que abriera la URL podría quedarse con la instancia. Si reinicias antes de usarlo, sale uno nuevo.

El panel sigue el idioma de tu navegador; puedes cambiarlo desde la barra lateral o la pantalla de inicio de sesión. Lo que Pitangus escribe sin que nadie lo pida en persona (comentarios en PRs, avisos, Jira, informes y salida de la CLI) usa `PITANGUS_DEFAULT_LOCALE` (`en` o `es`, por defecto `en`): ponlo en `es` en `.env` si tu equipo trabaja en español. Ver [configuracion.md](configuracion.md).

Luego:

1. **Cuenta → Segundo factor**: activa TOTP con tu app de autenticación y guarda los códigos de respaldo. Es obligatorio para administradores.
2. **Integraciones**: crea y conecta tu GitHub App con la guía del panel (también en [github-app.md](github-app.md)).
3. **Repositorios**: elige uno y pulsa **Analizar**.

La copia local de NVD para el CVE tracker se descarga sola en segundo plano: unas horas sin API key, mucho menos con `PITANGUS_NVD_API_KEY` (gratuita en <https://nvd.nist.gov/developers/request-an-api-key>). Todo lo demás funciona mientras tanto.

## Actualizar

```bash
make update
```

`make update` hace antes una copia (`make backup`), trae el código y reinicia. `data/`, `config/` y la base de datos se conservan. Si la versión nueva cambia el formato de algún dato, lo convierte sola al arrancar, una sola vez y tras guardar una copia de lo que toca en `data/backups/`: no hay que hacer nada a mano. Antes de actualizar conviene hacer una copia (ver abajo) y comprobar que no hay análisis en marcha en **Análisis**: un reinicio marca como fallidos los que estuvieran corriendo.

## Copias de seguridad

| Carpeta | Qué contiene | Cómo tratarla |
| --- | --- | --- |
| Base de datos (volumen `pitangus-pg`) | Ejecuciones, registro de hallazgos y triage (PostgreSQL) | `make backup` la vuelca con `pg_dump` en `database.dump`. |
| `data/` | Usuarios (contraseñas con scrypt), ajustes, logs, copia de NVD y cachés | Sin secretos en claro. Se pueden excluir `data/feeds/`, `data/trivy-cache/` y `data/grype-cache/`: se vuelven a descargar. |
| `config/` | `master.key` (salvo que definas `PITANGUS_MASTER_KEY`) | **Es la llave de tus credenciales**, que se guardan cifradas en la base. `make backup` la deja fuera salvo que la copia vaya cifrada: guarda una copia en tu gestor de contraseñas, nunca con las copias. |

```bash
make backup        # backups/<fecha>/database.dump, data.tgz y master-key.sha256 (qué clave necesita)
```

La app se detiene unos segundos para que la copia sea coherente, y el comando se niega si hay análisis en curso (`FORCE=1` para forzarlo). La clave maestra no va en la copia, así que una copia suelta no revela ningún secreto; en una máquina nueva, devuelve `config/master.key` a su sitio antes de restaurar. Para sacar las copias de la máquina, cífralas con age (`PITANGUS_BACKUP_AGE_RECIPIENT`, [despliegue-vps.md](despliegue-vps.md#copias-de-seguridad)): entonces la clave también entra, cifrada. Para restaurar:

```bash
make restore FROM=backups/<fecha> CONFIRM=restore   # antes guarda el estado actual en backups/pre-restore-<fecha>/
make up
```

Copias programadas (un servicio de Compose con retención), cron y copias fuera del servidor: [despliegue-vps.md](despliegue-vps.md#copias-de-seguridad).

Si pierdes `config/master.key` (o cambias `PITANGUS_MASTER_KEY`), los secretos guardados no se pueden descifrar: tendrás que volver a conectar la GitHub App y el token de Jira. El resto de datos no se pierde.

## Exponerlo en tu red o en internet

Por defecto el puerto solo se publica en `127.0.0.1`. Para abrirlo desde otras máquinas necesitas HTTPS: el servidor **se niega a arrancar** si `PITANGUS_PUBLIC_URL` no es loopback y no empieza por `https://`. En un servidor con dominio, `make setup DOMAIN=pitangus.example.com` añade Caddy con certificados automáticos: la guía completa (dimensionado, cortafuegos, copias, actualizaciones, monitorización, Coolify y Dokploy) está en [despliegue-vps.md](despliegue-vps.md).

En un portátil, el worker maneja Docker a través de su socket, lo que equivale a root en el host. En modo servidor (`DOMAIN=…`) los motores corren dentro del worker. En cualquier caso, expón el panel solo a personas de confianza.

## Desinstalar

```bash
make clean                   # contenedores e imágenes; conserva data/ y config/
make purge CONFIRM=delete    # además borra datos y secretos: solo si ya no los necesitas
```

Borra también tu GitHub App en GitHub (*Settings → Developer settings → GitHub Apps → tu App → Advanced → Delete*), o al menos revoca su clave privada.
