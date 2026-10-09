[English](../security.md) · Español

# Seguridad

Pitangus lee el código de tus repositorios y guarda credenciales de GitHub y Jira. Este documento explica cómo protege esa información, qué sale de tu máquina y qué concesiones hace. Para reportar una vulnerabilidad, ve a [SECURITY.es.md](../../.github/SECURITY.es.md).

## Secretos

| Secreto | Dónde vive | Quién lo ve |
| --- | --- | --- |
| Clave privada de la GitHub App | tabla `vault_entries`, cifrada | Solo el proceso del servidor. A GitHub va un JWT firmado, nunca la clave. |
| Claves de OpenAI / Anthropic | tabla `vault_entries`, cifradas | Solo el servidor; se validan contra el proveedor antes de guardarse. El panel muestra los 4 últimos caracteres. |
| Token de Jira | tabla `vault_entries`, cifrado | Igual que las anteriores. |
| Tokens de registros de contenedores | tabla `vault_entries`, cifrados | Solo el servidor. Llegan a Trivy y Grype por variable de entorno (`-e NOMBRE` sin valor en la orden), nunca en la línea de comandos. |
| Tokens de instalación de GitHub | Memoria, 1 h | Se renuevan solos; nunca se escriben en disco. |
| Clave maestra | `config/master.key` (0400) o `PITANGUS_MASTER_KEY` | Quien administra el servidor. |
| Contraseñas de usuarios | Tabla `users` de PostgreSQL, solo hash scrypt | Nadie: no son recuperables. |
| Cookies de sesión | Tabla `sessions`, solo su hash; firmadas con una clave sellada en el almacén (o `PITANGUS_SESSION_KEY`) | Copiar la base no da acceso. |

**Cifrado.** AES-256-GCM, un nonce aleatorio por secreto y el nombre del secreto como dato asociado: un valor cifrado no se puede mover a otra entrada sin que falle el descifrado, y cualquier manipulación se detecta. Si la clave maestra no descifra, el servidor lo dice en lugar de usar datos corruptos.

**Separación.** Los secretos cifrados viven en la base de datos, la clave maestra fuera de ella (`PITANGUS_MASTER_KEY` o `config/master.key`), y `data/` solo guarda cachés y registros, así que no lleva ningún secreto. Un volcado de la base sin la clave maestra no revela nada. En cualquier plataforma con gestor de secretos, define ahí `PITANGUS_MASTER_KEY`: es el único valor que nunca debe vivir junto a las copias de la base. `make backup` y el servicio de copias lo respetan: dejan la clave fuera, o cifran la copia entera, clave incluida, con age para una clave pública cuya mitad privada se queda fuera del servidor (`PITANGUS_BACKUP_AGE_RECIPIENT`).

**Logs.** No se registran cuerpos de petición, cabeceras, contraseñas, códigos TOTP ni cookies. Además, todo mensaje pasa por un filtro que tacha:

- patrones conocidos: `ghp_`, `ghs_`, `github_pat_`, `sk-…`, `xox…`, `AKIA…`, `ATATT…`, JWT, `Bearer …`, `Basic …` y bloques `-----BEGIN … PRIVATE KEY-----`;
- literalmente, cualquier valor guardado en el almacén, aunque no siga ningún patrón.

**Navegador.** Ningún secreto vuelve al navegador. La clave `.pem` se lee en tu navegador y viaja una sola vez al servidor al conectarla; el panel no la conserva.

## Acceso al panel

- **Primer administrador** con un código de un solo uso que solo aparece en la consola del servidor: quien abra la URL antes que tú no puede quedarse con la instancia.
- **Contraseñas** con scrypt (N=2¹⁵, r=8, p=1), mínimo 12 caracteres. Un usuario inexistente cuesta lo mismo que uno real, así que el tiempo de respuesta no delata cuáles existen.
- **Segundo factor** TOTP (RFC 6238) obligatorio para administradores por defecto, con 8 códigos de respaldo de un solo uso. Un código ya usado no vale dos veces.
- **Sesiones** del lado del servidor, con cookie `HttpOnly`, `SameSite=Strict` y `Secure` con HTTPS. Cambiar la contraseña, activar TOTP o que un administrador restablezca credenciales cierra las demás sesiones.
- **Límite de intentos** por usuario y por dirección: tras 5 fallos, bloqueo progresivo de 30 s a 15 min. También en el alta inicial y en la vuelta de GitHub. Detrás de un proxy inverso, la dirección sale de `X-Forwarded-For` solo si la petición llega de un proxy de `PITANGUS_FORWARDED_ALLOW_IPS` (`compose.prod.yaml` la pone para Caddy); si no, todo el mundo compartiría la dirección del proxy.
- **CSRF**: cada POST exige un `Origin` permitido y una cabecera de acción propia de su ruta.
- **Roles**: `admin` conecta integraciones, gestiona usuarios y acepta riesgos; `member` analiza y triagea.

## Transporte

- El puerto se publica solo en `127.0.0.1` por defecto.
- Si `PITANGUS_PUBLIC_URL` apunta fuera de esta máquina y no es HTTPS, **el servidor no arranca**. Solo `PITANGUS_ALLOW_INSECURE_HTTP=1` lo permite, bajo tu responsabilidad.
- Con HTTPS: HSTS (1 año) y cookies `Secure`. TLS 1.2 como mínimo si el propio servidor sirve TLS.
- Todas las respuestas llevan `Content-Security-Policy` estricta (sin scripts ni estilos en línea), `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` y `Permissions-Policy`.
- Las llamadas salientes van por HTTPS con verificación de certificado y **no siguen redirecciones**, para que una credencial nunca acabe en un destino distinto del previsto.

## Qué sale de tu máquina

| Destino | Qué se envía | Cuándo |
| --- | --- | --- |
| `api.github.com` | JWT de tu App, peticiones de repositorios y PRs; comentarios y estados de commit en tus PRs | Al conectar, analizar y revisar PRs. El código se **descarga** de GitHub; no se sube a ningún otro sitio. |
| `services.nvd.nist.gov` | Rangos de índices y de fechas | Copia local de CVE, en segundo plano. |
| `www.cisa.gov`, `epss.empiricalsecurity.com` | Nada: descarga de feeds públicos completos | Una vez al día. Se descargan enteros para no revelar qué CVE te interesan. |
| Registro de imágenes y base de Trivy | Nada propio | Al construir y cuando Trivy actualiza su base. |
| Registros de contenedores (Docker Hub, GHCR, ECR…) | Petición de la imagen que pides analizar, con tu token si lo guardaste | Al analizar una imagen. Los registros con IP privada se bloquean salvo `PITANGUS_ALLOW_PRIVATE_REGISTRIES=1`, para que el formulario no sirva de puente a tu red interna (SSRF). La comprobación se repite al empezar el análisis, y el contenedor del motor recibe la dirección comprobada para el nombre del registro, así que una respuesta que cambie entre medias (DNS rebinding) no se sigue. |
| `api.osv.dev` | Nombres y versiones de tus dependencias | **Solo si lo autorizas** en cada análisis. Por defecto no se usa. |
| Tu sitio de Jira | Los campos que asignas a cada incidencia (por defecto título, descripción, prioridad, etiquetas y plazo de corrección) y comentarios cuando se verifica la corrección de un hallazgo o reaparece | Solo si conectas Jira: cuando alguien exporta, o por su cuenta con reglas de enrutamiento automáticas. |
| `api.openai.com`, `api.anthropic.com` | La clave del servidor, para comprobar que es válida | Solo cuando un operador la prueba (`ai-check`). La IA aún no se usa: no recibe código ni hallazgos. |
| Tus dominios | Una consulta DNS TXT de `_pitangus.<host>` y un `HEAD` HTTPS al dominio cuando una persona administradora lo sondea antes de añadirlo | Cuando quien administra verifica un dominio, una vez al día por cada dominio verificado (se vuelve a comprobar la prueba) y cuando el formulario de añadir dominio sondea uno alcanzable. El `HEAD` va a la dirección ya resuelta y solo si todas las direcciones son públicas; no se siguen redirecciones. No se escanea nada. |

No hay telemetría.

## Análisis del código

- El código de los repositorios **nunca se ejecuta**: se analiza una instantánea en solo lectura.
- Los motores corren en contenedores efímeros con el sistema de ficheros en solo lectura (solo escriben en un `/tmp` en memoria de 1 GB y en las carpetas que se les montan), `--cap-drop ALL`, `no-new-privileges` y límites de memoria, CPU y procesos. Gitleaks, Opengrep, Checkov y zizmor no tienen red; Trivy y Grype solo la usan para su base de vulnerabilidades y, al analizar una imagen, para leerla del registro.
- Las imágenes de contenedor que analizas **no se ejecutan ni se construyen**: los motores leen el manifiesto y las capas.
- Las imágenes de Trivy, OSV-Scanner, Gitleaks, Grype, Checkov y zizmor van fijadas por digest. La de Opengrep se construye con el binario oficial comprobado contra su SHA-256.
- Los valores de los secretos encontrados en tu código se redactan: en los hallazgos queda la ubicación y el tipo, no el valor.

## Concesiones conocidas

- **Socket de Docker.** Los motores se lanzan a través de `/var/run/docker.sock`, lo que equivale a root en el host. Solo lo monta el servicio `worker`, que no expone ningún puerto; el servicio que atiende las peticiones (`api`) no lo tiene. Es el precio de no instalar nada más que Docker, y lo que se usa por defecto en un portátil. En un servidor, `make setup DOMAIN=…` y `deploy/compose.yaml` usan en su lugar la imagen del worker con los motores dentro (`PITANGUS_ENGINE_RUNNER=local`), y el socket pasa a ser opcional (`SOCKET=1`).
- **Motores dentro del worker** (`PITANGUS_ENGINE_RUNNER=local`). Sin socket de Docker, pero tampoco con un contenedor por motor: cada motor corre como un proceso del worker, con una carpeta personal nueva, solo el `PATH` del entorno del worker (no se le pasan ni la URL de la base ni la clave maestra), sin volcados de memoria, y al vencer su plazo se mata todo su grupo de procesos. Los motores que no necesitan red (Gitleaks, Opengrep, Checkov, zizmor) corren en un espacio de nombres de red vacío (`unshare --user --net`) donde la plataforma lo permite: en un servidor o una VM, sí; en un contenedor con el perfil seccomp por defecto de Docker, no, y el worker lo deja en su log (`local_engines_share_the_network`). Si no, corren con sus opciones sin conexión allí donde las tienen. La frontera es el contenedor del worker, no el motor. Si un repositorio hostil rompe un motor, ese motor corre con el usuario del worker y puede leer lo mismo que él (`/proc/1/environ`, `config/master.key`), aunque no llega al servidor. La comparación con el socket está en [despliegue-vps.md](despliegue-vps.md#los-motores-y-el-socket-de-docker).
- **Cola de trabajos.** Los análisis pendientes viven en PostgreSQL. Los tokens de código que acompañan a un análisis van sellados con la clave maestra (AES-GCM): la base nunca los guarda en claro.
- **Semillas TOTP** selladas también con la clave maestra: un volcado de la base no basta para generar códigos. Si
  pierdes la clave maestra, además de volver a introducir los secretos del almacén tendrás que restablecer los segundos
  factores (`make cli ARGS="user reset-totp --username <nombre>"`).
- **Clave maestra en el mismo servidor** si no defines `PITANGUS_MASTER_KEY`. Protege frente a una copia suelta de la base, no frente a alguien con acceso completo al servidor.
- **Un solo workspace** por instalación: todos los usuarios ven todos los repositorios conectados.
- **Token de registro visible para root.** Mientras dura el análisis de una imagen privada, el token está en la configuración del contenedor del motor: lo puede leer quien tenga acceso a Docker en el host (que ya es root). Usa tokens de solo lectura.
- **No se comprueban las redirecciones del registro.** Los registros sirven las capas de la imagen desde otros hosts (una CDN, un bucket), así que Trivy y Grype siguen sus redirecciones. Un registro que pidas analizar podría mandarlos a una dirección interna. Solo hacen la petición, y lo que vuelve no se muestra. Analiza imágenes de registros de confianza, o corre los motores en una red sin acceso a la interna.

## Recomendaciones

1. Mantén el panel en `127.0.0.1` salvo que necesites acceso remoto, y entonces usa HTTPS.
2. Activa TOTP para todos (`PITANGUS_REQUIRE_TOTP=all`) si varias personas lo usan.
3. Instala la App solo en los repositorios que quieras analizar (**Only select repositories**).
4. Guarda la clave maestra aparte de las copias, y cifra las copias con age antes de que salgan del servidor (`PITANGUS_BACKUP_AGE_RECIPIENT`).
5. Si una clave de la App se filtra: revócala en GitHub (*Private keys → Delete*), genera otra y vuelve a conectarla en **Integraciones**.

## Exclusiones y supresiones

- Las rutas excluidas las decide un administrador en el panel y se guardan en el servidor con autor, fecha y motivo. Un PR no puede excluir su propio código ni cambiar las reglas: ni `.pitangus-ignore`, ni `.gitleaks.toml`, ni configuración de los motores dentro del repositorio.
- Lo excluido se cuenta en cada ejecución y se puede consultar; nunca se borra en silencio.
- Las supresiones en el código (`# nosemgrep: <regla>`) sí viajan con el repositorio y se ven en la revisión del PR; úsalas con una justificación al lado.
