[English](../troubleshooting.md) · Español

# Solución de problemas de Pitangus

Problemas frecuentes, agrupados según dónde aparecen, cada uno con su causa probable y la solución. Si el tuyo no está
aquí, los comandos de abajo suelen señalarlo.

## Empieza aquí

```bash
make doctor     # requisitos, permisos, puerto y motores
make status     # contenedores e imágenes de los motores
make logs       # sigue los logs de la app (Ctrl+C para salir)
```

`make doctor` imprime una línea por comprobación y un resumen (en inglés):

```text
Pitangus · environment check

Tools
  ✓ docker installed (27.3.1)
  ✓ Docker daemon running (27.3.1)
  ✓ docker compose 2.29.7
...
Result: 14 passed, 0 warnings, 0 errors
```

Una línea con `✗` dice qué está mal y, en la línea de abajo, qué hacer. Los logs de la app no contienen contraseñas,
tokens ni claves: puedes compartirlos al pedir ayuda. Aun así, revísalos antes por si incluyen nombres de repositorios
o dominios que prefieras no publicar.

## Instalación y Docker

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `make doctor`: *the Docker daemon is not responding* | Docker no está corriendo o tu usuario no llega a él. | Arranca Docker Desktop u OrbStack; en Linux, `sudo systemctl start docker` y añade tu usuario al grupo `docker`. |
| `make doctor`: *docker compose … is too old* o *Docker Engine … is too old* | Pitangus necesita Docker Engine 24+ y Compose v2.24+. | Actualiza Docker. |
| `opengrep` aparece como *Exited* | Es su comportamiento: solo construye la imagen del motor y comprueba que arranca. | Nada. |
| La construcción falla en `sha256sum -c` | El binario de Opengrep descargado no coincide con el hash fijado. | No continúes: reintenta más tarde y, si persiste, abre un issue. Nunca quites la comprobación. |
| `make up` construye las imágenes (`Building`, `pnpm install`, `pip install`) aunque querías las publicadas | `.env` no tiene `compose.images.yaml` en `COMPOSE_FILE` (por ejemplo, se corrió `make up` antes de `make setup PREBUILT=1`). | `make setup PREBUILT=1` y luego `make up`. `grep COMPOSE_FILE .env` debe mostrar `compose.images.yaml`. |
| El panel no abre en `127.0.0.1:8766` | Otro servicio usa el puerto o el contenedor no arrancó. | Cambia `PITANGUS_HOST_PORT` y también `PITANGUS_PUBLIC_URL` y `PITANGUS_ALLOWED_ORIGINS` en `.env`. `make logs` muestra por qué se paró el contenedor. |
| *Host no permitido* (403) | Abres el panel con una URL que no está en `PITANGUS_ALLOWED_ORIGINS`. | Añádela en `.env` y reinicia: `docker compose up -d`. |
| El contenedor se para con *expone el panel por HTTP en claro* | `PITANGUS_PUBLIC_URL` apunta fuera de esta máquina sin HTTPS. | Pon HTTPS delante ([Desplegar en un VPS](despliegue-vps.md)) o vuelve a `http://127.0.0.1:8766`. |
| `Permission denied` en `data/` o `config/` | Las carpetas las creó Docker como root. | `sudo chown -R $(id -u):$(id -g) data config`; si tu `.env` tiene otro UID/GID, bórralo y ejecuta `make setup`. |
| *No se pudo descifrar un secreto* | Cambió `PITANGUS_MASTER_KEY` o se perdió `config/master.key`. | Restaura la clave; si no es posible, *Olvidar la App* y vuelve a conectar GitHub y Jira. |
| Un análisis quedó *Fallido* tras reiniciar | Al arrancar se marcan como fallidos los que estaban a medias. | Vuelve a lanzarlo. |
| El CVE tracker va lento al empezar | La copia local de NVD se está descargando (se ve el progreso arriba). | Espera, o añade `PITANGUS_NVD_API_KEY`. |

## Windows y WSL

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| Todo va muy lento en WSL2 | El repositorio está en el disco de Windows (`/mnt/c/...`), que WSL2 lee mucho más despacio. | Clónalo dentro de Linux: `cd ~ && git clone --branch v0.15.1 https://github.com/Pitangus-Dev/pitangus.git`. |
| `Permission denied` en `data/` con WSL2 | Las carpetas se crearon desde Windows o las creó Docker como root. | Clona dentro de Linux como arriba y ejecuta ahí `make setup` antes de `make up`. |

## VPN y proxy

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| El primer `make up` tarda mucho más que unos minutos | Los ~800 MB de imágenes pasan por una VPN o un proxy corporativo que frena o inspecciona el registro de contenedores (`ghcr.io`, cuyas capas salen de `pkg-containers.githubusercontent.com`). Medido: más de 25 minutos con la VPN de una empresa, 3 sin ella. | Haz el primer `make up` sin la VPN, o pide a quien lleve la red que exceptúe esos dos dominios de la inspección. Solo pasa una vez: los arranques siguientes reutilizan las imágenes. |
| `make engines` se detiene con *Pulling … failed* | Tu red no llega al registro (Docker Hub o `ghcr.io`). | Revisa la conexión o el proxy y vuelve a ejecutar `make engines`: sigue con lo que falte. |

## Motores sin descargar o no probados

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| Un motor sale como *No probado* en una ejecución | Docker no es accesible desde el worker o falta la imagen del motor. | `make status` lista las imágenes que faltan: `make build` para Opengrep y `make engines` para el resto. Luego vuelve a analizar. |
| `make doctor`: *missing …* en *Analysis engines* | Las imágenes aún no se descargaron. | `make engines` (también se descargan en el primer análisis). |
| Las dependencias salen como *No probado*, mencionando OSV | Los motores de dependencias (Trivy, OSV-Scanner) no corrieron, casi siempre porque Docker no es accesible, y la alternativa en línea está apagada: solo envía nombres y versiones de paquetes a `api.osv.dev` si lo permites. | Haz que los motores corran (`make status`, `make engines`) y vuelve a analizar. O, si quien es dueño del código lo permite, marca **Consultar dependencias en línea con OSV** en la revisión del análisis. |
| Linux: análisis sin hallazgos que no cuadran, o cachés `trivy-cache-<uid>` nuevas | Antes del 23-sep-2026 se lanzaban los motores como root sin capacidades, que en Linux no puede leer las carpetas privadas de la app y devolvía cero hallazgos sin avisar. Ahora corren con el UID de la app; si una caché antigua la creó root, se usa una nueva a su lado. | Vuelve a lanzar los análisis hechos en Linux antes de actualizar. Las cachés viejas (`data/trivy-cache`, `data/grype-cache`) se pueden borrar con `sudo rm -rf` si ya existe la versión con sufijo. |

## Análisis web

Ver [Analizar un sitio web o una API](analisis-web.md) para saber cómo funcionan.

### Análisis web completo aparece en gris en Nuevo análisis

**Síntoma.** En **Nuevo análisis**, **Análisis web completo** dice *No está activado en este servidor*, o una ejecución
falla con «Los análisis web están apagados en este servidor».

**Causa.** El análisis web completo es experimental y está apagado salvo que el servidor defina
`PITANGUS_DAST_ENABLED=1`. La leen la API y el worker. La **Comprobación de exposición** no necesita nada y sigue
disponible.

**Solución.**

```bash
echo 'PITANGUS_DAST_ENABLED=1' >> .env
make up          # reinicia y descarga los motores web
```

### La ejecución dice que los análisis web necesitan el runner de Docker

**Causa.** El worker corre sin socket de Docker (la imagen de servidor de `deploy/compose.yaml` y de las plataformas).
Esa imagen no incluye ZAP ni las demás herramientas web.

**Solución.** Corre el worker que analiza sitios con el runner de Docker (la instalación de portátil, o un worker con el
socket montado). Ver [Dónde desplegar](despliegue.md).

### El paso de una herramienta sale Omitido: «La imagen de … no está en este servidor»

**Causa.** No se descargó la imagen de katana, nuclei, testssl.sh, httpx, subfinder o ZAP: falló su descarga o (para
ZAP, katana y subfinder) `PITANGUS_DAST_ENABLED` se activó después del último `make up`.

**Solución.**

```bash
make engines
```

```text
Engines: 5 images missing; the first time can take a while depending on your connection.
→ projectdiscovery/katana
...
Engines: ready.
```

### La verificación del dominio falla: «No se encontró el TXT de verificación»

**Causa.** El nombre o el valor del registro no coinciden, o todavía no se propagó. Pitangus pregunta primero a los
servidores de nombres de la propia zona, así que la propagación suele ser rápida.

**Solución.** El registro es `_pitangus.<host>` con el valor `pitangus-verify=<token>`; el panel muestra los dos con
botones para copiar. Comprueba lo que ve el mundo:

```bash
dig +short TXT _pitangus.app.example.com
```

```text
"pitangus-verify=…"
```

Si no responde nada, corrige el registro en tu proveedor de DNS y pulsa **Verificar** otra vez. Los intentos repetidos
tienen límite: «Demasiados intentos con este dominio» significa esperar los segundos que indica.

### Prueba por archivo o meta: «respondió con una redirección»

**Causa.** El archivo (`https://<host>/.well-known/pitangus-verify.txt`) o la página principal con la etiqueta meta se
piden una sola vez, sin seguir redirecciones. Una redirección (a `www.`, a `/es/`, a una página de login) hace fallar
la comprobación.

**Solución.** Sirve la prueba desde ese mismo host y ruta, respondiendo 200:

```bash
curl -sI https://app.example.com/.well-known/pitangus-verify.txt
```

```text
HTTP/2 200
```

Para la prueba meta, la etiqueta tiene que estar en el HTML de `https://<host>/` mismo. Si tu página principal siempre
redirige, usa la prueba DNS o la de archivo. Solo la prueba DNS cubre los subdominios.

### «El dominio resuelve a una dirección privada o reservada»

**Causa.** Pitangus solo sondea y analiza direcciones públicas. Un nombre que resuelve a una dirección privada, de
loopback, link-local o de metadatos de la nube (un sitio de intranet, un entorno de pruebas detrás de una VPN) se
rechaza, y no se le envía nada.

**Solución.** No hay un ajuste para permitir direcciones privadas en los análisis web. Analiza un despliegue accesible
públicamente, o corre tu propio escáner dentro de esa red e [importa su SARIF](integraciones.md#trae-tu-propio-dast)
sobre un dominio verificado.

### Un usuario de prueba no pudo iniciar sesión

**Síntoma.** La ejecución dice «No pudo iniciar sesión como «nombre»» con un motivo, el paso **Inicio de sesión con
usuarios de prueba** queda parcial y la cobertura de la ejecución es parcial.

**Causa.** ZAP inicia sesión con un navegador sin interfaz y luego pide la página de comprobación del usuario. Cualquier
cosa distinta de un 200 ahí (una redirección al login, un 401, un 403) cuenta como inicio de sesión fallido. Motivos
habituales: contraseña o clave TOTP equivocadas, una URL de login que no es la página con el formulario, una página de
comprobación que también ven los visitantes o que redirige, una página de login o de comprobación fuera del alcance
del análisis, o un paso que un navegador no puede completar solo (un CAPTCHA, un código enviado por correo).

**Solución.** En la pestaña **Usuarios de prueba** del dominio, revisa el usuario, la contraseña y la clave TOTP (la
clave base32 que muestra la app de autenticación), pon como página de login la que tiene el formulario y como página de
comprobación una que solo vea quien inició sesión (como `/account`). Asegúrate de que las dos estén en un host del
alcance. Luego vuelve a analizar. Lo que vería ese usuario figura como no analizado hasta que un inicio de sesión
funcione.

### Pasos de herramientas parciales u omitidos

**Causa.** El paso de cada herramienta dice por qué. «No pudo revisar … (no hubo respuesta o se rechazó la dirección)»
significa que la herramienta no recibió respuesta de ese host; «no terminó» o «se detuvo tras N minutos» significa que
falló o llegó a su límite de tiempo; un paso omitido nombra el motivo (sin imagen, sin runner de Docker).

**Solución.** Corrige el motivo que nombra el paso y vuelve a analizar. Hasta que un análisis llegue a ese host con esa
herramienta, sus hallazgos anteriores ahí no se marcan remediados y la cobertura de la ejecución sigue parcial: pocos
hallazgos ahí no demuestran nada.

### Un firewall o un WAF bloquea el análisis

**Síntoma.** Los hallazgos de ZAP hablan sobre todo de una página de bloqueo, las herramientas no llegan al host o
todas las peticiones reciben un 403.

**Causa.** El sitio filtra por IP o bloquea el tráfico automatizado, y la dirección del servidor no está permitida.

**Solución.** Permite la dirección de salida del análisis. El paso de revisión de un análisis web la muestra bajo «Si tu
sitio filtra por IP, permite:», con un botón para copiar. Defínela explícitamente cuando el worker sale por otra
dirección que la API:

```bash
echo 'PITANGUS_EGRESS_IPS=203.0.113.10' >> .env
docker compose up -d
```

Sin la variable, quien administra puede pulsar **Detectar** una vez en ese paso: el servidor le pregunta a
`api.ipify.org` desde qué dirección se le ve.

### «Ya hay un análisis web en cola o en curso»

**Causa.** Corre un análisis web a la vez por instalación.

**Solución.** Espera a que termine en **Análisis**. Los análisis programados que se topan con esto se reintentan en la
siguiente ronda.

## Cuentas y acceso

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| No encuentro el código de configuración | Salió al terminar `make up` y en los logs del primer arranque. | `make setup-code`. Si ya hay un usuario creado, el código no existe: entra con ese usuario. |
| No se abre nada hasta activar el segundo factor | El TOTP es obligatorio para los administradores (`PITANGUS_REQUIRE_TOTP`). | Actívalo con tu app de autenticación y guarda los códigos de respaldo. |
| Perdí el segundo factor | — | Otro administrador lo quita en **Usuarios**, o por CLI: `make cli ARGS="user reset-totp --username tu-usuario"`. |
| Olvidé la contraseña | — | **Usuarios → Enviar enlace de contraseña**, o `make cli ARGS="user reset-password --username tu-usuario"`. |
| Un botón dice que solo un administrador puede hacerlo | Los miembros no conectan proveedores, no aceptan riesgos, no gestionan dominios ni lanzan análisis web. | Pídeselo a un administrador, o que te cambie el rol en **Usuarios**. |

## Problemas al actualizar

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `make update` se detiene con «N scans are running» | La copia de seguridad no corre mientras haya análisis en cola o en curso. | Espera a que terminen en **Análisis** y vuelve a ejecutar `make update`. |
| `make update` dice «a fixed version: not pulling» | Instalaste una versión y no cambiaste a la nueva. | `git fetch --tags && git checkout v<nueva> && make update`. |
| Tras actualizar a 0.13, los análisis web omiten herramientas | No se descargaron las imágenes nuevas de los motores web. | `make engines` con `PITANGUS_DAST_ENABLED=1` en `.env`. |

La lista completa de cada versión está en [Actualizar Pitangus](actualizar.md#problemas-al-actualizar).

## Idioma

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| El panel, un informe o un comentario de PR sale en otro idioma | El panel sigue al navegador; todo lo demás usa `PITANGUS_DEFAULT_LOCALE`. | Usa el selector de idioma de la cabecera (o de la pantalla de inicio de sesión); para informes, comentarios en PRs, avisos, Jira y la CLI, pon `PITANGUS_DEFAULT_LOCALE=es` o `en` en `.env` y ejecuta `docker compose up -d`. |
| El resumen de un aviso sigue en inglés con el panel en español | El texto de terceros (NVD, OSV, GHSA) se muestra tal como se publicó, nunca con traducción automática. | Es lo esperado. |

## Siguientes pasos

- [Instalación](instalacion.md): requisitos y primer arranque.
- [Actualizar Pitangus](actualizar.md).
- [Preguntas frecuentes](preguntas-frecuentes.md).
