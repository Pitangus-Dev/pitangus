[English](../scanning-web.md) · Español

# Analizar un sitio web o una API (DAST pasivo)

Pitangus puede revisar un sitio web o una API en funcionamiento que controles y reportar lo que le muestra a cualquier
visitante: cabeceras de seguridad que faltan, cookies débiles, archivos expuestos, fugas de información, una
configuración TLS anticuada, librerías con vulnerabilidades conocidas. Esto es **DAST** (pruebas dinámicas de seguridad
de aplicaciones: revisar la aplicación mientras corre, desde fuera), y en Pitangus es **pasivo**: las herramientas
navegan y leen respuestas, nunca atacan. Cada resultado es un [hallazgo](glosario.md) que confirmas antes de actuar.

Esta página cubre el camino completo: activar los análisis web, añadir y verificar un dominio, elegir qué analizar,
iniciar sesión con usuarios de prueba, lanzar o programar un análisis y leer lo que devuelve.

## Pasivo, no activo: qué hace un análisis y qué no

Un análisis **pasivo** envía el mismo tipo de peticiones que envía un navegador cuando alguien visita el sitio: sigue
enlaces, carga páginas y lee las respuestas. Un análisis **activo** envía ataques (inyecciones, fuzzing, envíos de
formularios manipulados) para ver si algo se rompe. Hoy Pitangus solo hace análisis pasivos.

| Un análisis web pasivo en Pitangus | Lo que no hace |
| --- | --- |
| Sigue enlaces con un crawler y un navegador headless | Enviar formularios (salvo el de login de un [usuario de prueba](#usuarios-de-prueba) que elegiste) |
| Lee cabeceras, cookies, el contenido de las páginas y la configuración TLS | Pulsar botones, escribir datos al azar ni adivinar contraseñas |
| Pide rutas conocidas que delatan archivos expuestos (`.git`, `.env`, copias de seguridad) | Enviar inyecciones, payloads ni fuzzing |
| Pide las operaciones GET y HEAD de una definición de API | Enviar peticiones POST, PUT, PATCH ni DELETE |

Es un *análisis*, no un *pentest*. Un pentest (prueba de penetración) intenta explotar los fallos y demuestra su
impacto; un informe de Pitangus no reemplaza el pentest que piden SOC 2 o ISO 27001. Como no se ataca nada, pocos
hallazgos no significan que la aplicación sea segura: no se prueban inyecciones, control de acceso roto ni fallos de
lógica de negocio. Cada análisis lista lo que dejó fuera.

> [!WARNING]
> Verificar un dominio prueba el control técnico de la zona o del sitio, no el permiso para probar la aplicación.
> Lanza análisis solo contra sitios que tengas permiso de probar.

## Antes de empezar

Necesitas:

- **Una cuenta de administración.** Los miembros ven los dominios, su estado, su alcance y sus hallazgos; solo quien
  administra los añade, verifica, cambia, elimina o analiza, y solo esa persona ve el token de verificación y las
  cabeceras guardadas.
- **El runner de Docker.** Las herramientas corren en contenedores. La imagen del worker sin socket de Docker
  (`pitangus-worker`, ver [contenedores.md](contenedores.md)) no las incluye, y el análisis lo indica.
- **Los análisis web activados** con `PITANGUS_DAST_ENABLED=1`. La leen la API y el worker, así que defínela en los
  dos (en `.env` con la instalación por defecto). Ver [configuracion.md](configuracion.md).
- **Las imágenes de los motores.** `make engines` (que también ejecuta `make up`) descarga las que faltan. Con los
  análisis web activados añade ZAP, katana, nuclei, testssl.sh, httpx y subfinder, cada una fijada por versión y
  digest. Solo ZAP ocupa unos 1,2 GB; las demás herramientas web, cerca de 1 GB en total.
- **Un sitio HTTPS público** en el puerto 443, con un certificado válido y un nombre DNS público. Las direcciones
  privadas o internas nunca se analizan.

Activa los análisis web y descarga las imágenes:

```bash
echo 'PITANGUS_DAST_ENABLED=1' >> .env
make up
make engines
```

La primera vez, `make engines` muestra cada imagen que descarga, por ejemplo:

```text
Engines: 6 images missing; the first time can take a while depending on your connection.
→ ghcr.io/zaproxy/zaproxy:2.17.0
→ projectdiscovery/subfinder:v2.16.0
→ projectdiscovery/katana:v1.7.0
→ projectdiscovery/nuclei:v3.11.1
→ ghcr.io/testssl/testssl.sh:3.2
→ projectdiscovery/httpx:v1.12.0
Engines: ready.
```

Cuando ya están todas, imprime `Engines: all images are ready.` El primer análisis descarga además, una sola vez y
desde GitHub, la versión de las plantillas de nuclei (con su SHA-256 fijado).

## Añadir un dominio

1. Abre **Escaneo → Dominios y APIs** (`#/domains`) y pulsa **Añadir dominio**.
2. Escribe la dirección del sitio, por ejemplo `https://app.example.com`: HTTPS, un dominio público, sin puerto,
   query, fragmento ni usuario. Mientras escribes, el panel lo sondea y dice si responde (**Responde · HTTPS 200**) o
   aún no. Puedes añadirlo en cualquier caso.
3. Elige un **Tipo**: **Aplicación web**, **API** o **Solo inventario** (se lista, nunca se analiza). Si quieres,
   añade un **Contexto** (qué hace, cómo inician sesión, qué datos maneja); aparece en los informes.
4. Pulsa **Añadir dominio**. A continuación se abre el diálogo de verificación.

El sondeo comprueba que el nombre resuelve solo a direcciones públicas (si no, no se envía nada) y manda un `HEAD` por
HTTPS a la dirección recién resuelta, con certificado válido y sin redirecciones. Añadir, sondear y verificar no
prueban nada. Un espacio de trabajo guarda como máximo 20 dominios.

Con los análisis web activados, añadir un dominio también inicia la búsqueda de
[hosts relacionados](#elegir-el-alcance-subdominios-y-hosts-relacionados).

## Verificar que lo controlas

Un dominio no se puede analizar hasta que pruebes que lo controlas. Hay tres métodos, todos con el mismo token. El
diálogo de verificación muestra los valores exactos que debes copiar para cada uno (pestañas **Registro DNS**,
**Archivo** y **Meta**).

| Método | Qué publicas | Qué cubre |
| --- | --- | --- |
| DNS (recomendado) | Un registro TXT llamado `_pitangus.<host>` con el valor `pitangus-verify=<token>` | El host **y sus subdominios** |
| Archivo | `https://<host>/.well-known/pitangus-verify.txt`, que responda 200 con el token en el cuerpo | Ese host exacto |
| Meta | `<meta name="pitangus-verify" content="<token>">` en el `<head>` de `https://<host>/` | Ese host exacto |

Solo una prueba DNS permite que los análisis incluyan subdominios: quien controla la zona los controla.

### Registro DNS

Añade el registro TXT en tu proveedor de DNS. Para `app.example.com`, en formato de archivo de zona, se ve así:

```text
_pitangus.app.example.com.  300  IN  TXT  "pitangus-verify=3q2-7wEXAMPLEtokenVALUE0abcd1234"
```

Comprueba que está publicado antes de pulsar **Verificar ahora**:

```bash
dig +short TXT _pitangus.app.example.com
```

```text
"pitangus-verify=3q2-7wEXAMPLEtokenVALUE0abcd1234"
```

Pitangus pregunta primero a los servidores de nombres autoritativos de la zona, así que un resolver que guardó en caché
«ese registro no existe» no te frena; si la red solo permite DNS a través del resolver local, recurre a él.

### Archivo o etiqueta meta

Publica el archivo (el diálogo tiene **Descargar archivo**) o añade la etiqueta a la página de inicio, y compruébalo
desde fuera:

```bash
curl -sS https://app.example.com/.well-known/pitangus-verify.txt
```

Pitangus pide el archivo o la página de inicio una vez, desde la dirección pública ya comprobada del host (nunca una
privada), por HTTPS con certificado válido, **sin seguir redirecciones**, con 10 segundos y 64 KB como máximo. Sirve la
prueba desde ese host exacto: una redirección a `www.` o a una página de login hace fallar la comprobación.

### Cuánto dura

Una prueba vale **90 días**. Cada día Pitangus vuelve a pedir la misma prueba (la del método que lo verificó):

- Sigue ahí: los 90 días empiezan de nuevo.
- Ya no está: el dominio deja de estar verificado en el acto, los análisis programados se pausan y alguien tiene que
  verificarlo otra vez.
- El DNS o el host no responden: nada cambia hasta que se cumplan los 90 días.

El worker también comprueba la prueba justo antes de cada análisis.

### Cuando la verificación falla

| Mensaje | Qué hacer |
| --- | --- |
| Aún no aparece el registro TXT en `_pitangus.<host>` | Revisa el nombre del registro (algunos proveedores añaden el dominio por ti y queda `_pitangus.app.example.com.example.com`), su valor y espera la propagación; reintenta en unos minutos. |
| No se pudo consultar DNS | El servidor no llegó al DNS. Revisa su red y reintenta; no cambia nada. |
| `<url>` respondió con una redirección | Sirve el archivo o la etiqueta desde ese host exacto, sin redirigir. |
| `<url>` no contiene el token de este dominio | Publica el archivo con el token y comprueba que responda 200. |
| La página principal de `<host>` no tiene la etiqueta meta pitangus-verify | Añade la etiqueta al `<head>` de la página de inicio (no de otra página). |
| No se pudo llegar a `<host>` por HTTPS | El sitio debe responder en el puerto 443 con un certificado válido. |
| Demasiados intentos con este dominio | Espera los segundos que indica antes de reintentar. |

<!-- screenshot: domain | La pestaña Resumen de un dominio verificado, con su verificación, último análisis, tecnologías y cabeceras de acceso -->

## Elegir el alcance: subdominios y hosts relacionados

El **alcance** es el conjunto de hosts a los que puede llegar un análisis. Por defecto, el propio host del dominio. Con
una prueba DNS vigente puedes añadir subdominios.

### Hosts relacionados que Pitangus encuentra

Al añadir un dominio (y cuando pulsas **Buscar de nuevo** en su pestaña **Alcance**), Pitangus ejecuta **subfinder**,
una herramienta que busca nombres bajo el dominio solo en fuentes públicas: registros de transparencia de
certificados, DNS pasivo y archivos históricos. No usa claves de API y se detiene al minuto. No se envía nada a tus
hosts; el nombre de tu dominio sí va a esas fuentes públicas, y por eso la búsqueda solo corre con
`PITANGUS_DAST_ENABLED=1`.

Cada nombre encontrado debe ser un host válido bajo el dominio y resolver solo a direcciones públicas (ni privadas, ni
de loopback, ni link-local, ni de metadatos de la nube); el resto se descarta y se cuenta. Los hosts nuevos empiezan
**excluidos**.

### Marcar qué analizar

En la pestaña **Alcance** del dominio (`#/domain?id=…&tab=scope`), o con **Incluir subdominios** en un análisis nuevo,
quien administra marca cada host como **Analizar** o **Excluir**, o añade uno a mano con **Añadir host**. La elección
se guarda con el dominio, y cada análisis que usa el alcance guardado la lee al empezar: los hosts analizados se
recorren y los excluidos quedan fuera del contexto de ZAP.

| Límite | Valor |
| --- | --- |
| Hosts analizados además del dominio | 20 |
| Hosts relacionados listados por dominio | 100 |
| Prueba necesaria para incluir cualquier subdominio | Una prueba DNS vigente |

Sin prueba DNS, los hosts se listan pero desactivados, y los análisis llegan solo al host del dominio. Si faltan
Docker, la imagen de subfinder o la conexión, la pestaña dice por qué.

Desde la API, un análisis puede listar en su lugar subdominios solo para ese análisis (`hosts`: hasta 20 nombres o
comodines `*.`). Un comodín solo amplía el contexto de ZAP: los hosts a los que se llega por él no se resuelven, así que
no se analizan. Lista un host por su nombre para incluirlo.

<!-- screenshot: domain-scope | La pestaña Alcance de un dominio, con hosts relacionados marcados como Analizar o Excluir -->

## Llegar a páginas detrás de un login

Sin credenciales, un análisis solo ve las páginas públicas. Puedes darle acceso de dos formas, ambas opcionales.

### Cabeceras de petición

Quien administra puede guardar hasta **10 cabeceras** por dominio (una API key, un bearer token, una cookie de sesión)
en **Acceso**, dentro del **Resumen** del dominio. Se guardan cifradas y no se vuelven a mostrar: el panel lista sus
nombres, los últimos cuatro caracteres de los valores largos y cuándo se guardaron.

- Un análisis las envía solo si se lo pides (**Enviar las cabeceras guardadas**), y solo a los hosts del alcance.
- Las envían ZAP, katana y nuclei; testssl.sh y httpx no.
- Los nombres siguen las reglas de token de HTTP; se rechazan `Host`, `Content-Length` y las cabeceras hop-by-hop. Los
  valores son una línea de ASCII imprimible, de 4096 caracteres como máximo.
- Los valores nunca llegan al análisis, a su progreso, a los logs, a los hallazgos ni a un archivo en disco.

Pitangus no comprueba que una cabecera autentique de verdad; el análisis lo indica en sus limitaciones.

### Usuarios de prueba

Un **usuario de prueba** es una cuenta de tu aplicación con la que el análisis inicia sesión para ver lo que ve un
usuario con sesión. Usa cuentas de prueba dedicadas, no las de personas reales.

En la pestaña **Usuarios de prueba** del dominio (`#/domain?id=…&tab=users`), pulsa **Añadir usuario** y completa:

| Campo | Notas |
| --- | --- |
| **Nombre** | Cómo lo vas a reconocer, por ejemplo «Usuario administrador». |
| Método | **Usuario y contraseña**, o **App de autenticación (TOTP)** para cuentas con segundo factor. |
| **Usuario o correo**, **Contraseña** | Cifrados; la contraseña no se puede volver a leer, solo reemplazar. |
| **Clave de la app de autenticación (secreto TOTP)** | La clave en base32 que aparece al configurar la app (16 caracteres como mínimo); 6 a 8 dígitos, 15 a 120 segundos, SHA1, SHA256 o SHA512. |
| **URL de login (opcional)** | Donde empieza el inicio de sesión. En blanco, el análisis abre la página de inicio del host y sigue el enlace de login que encuentre. |
| **Comprobar con (opcional)** | Una página que solo ve quien inició sesión, como `/account`. |
| **Se aplica a** | El host al que pertenece la cuenta: el dominio o uno de sus subdominios. |
| **Notas (opcional)** | Texto libre. |

Un dominio guarda hasta **10 usuarios de prueba** y un análisis inicia sesión con **3** como máximo. No se admiten
códigos por correo ni enlaces mágicos: nadie lee ese buzón. Se rechaza una contraseña, clave o URL que contenga `${`.

<!-- screenshot: domain-test-users | La pestaña Usuarios de prueba de un dominio, con las cuentas guardadas, su método y su último uso -->

#### Cómo se comprueba el inicio de sesión

Antes de recorrer el sitio, cada usuario de prueba elegido inicia sesión por separado, en un ZAP propio, a través de un
Firefox headless (la autenticación por navegador de ZAP; con TOTP, el código va en el campo que sigue a la
contraseña). Después:

- Con **Comprobar con**, ZAP pide esa página como ese usuario. Cualquier respuesta distinta de 200 (una redirección al
  login, un 401, un 403) es un inicio de sesión fallido.
- Sin ella, decide el informe de autenticación del propio ZAP.

El análisis dice entonces **Sesión iniciada como «nombre»** o **No pudo iniciar sesión como «nombre»** con el motivo
(en palabras de ZAP cuando las dio).

#### Cuando falla el inicio de sesión

No se recorre el sitio como un usuario que no pudo iniciar sesión. El análisis sigue con los demás y de forma anónima,
y queda marcado como incompleto con **cobertura parcial**, junto a sus resultados, en sus limitaciones y en sus
informes. Así, pocos o ningún hallazgo detrás de ese login nunca se leen como «limpio». Cada usuario que sí inició
sesión tiene su propio recorrido (2 minutos, más 2 de spider AJAX).

Solo ZAP inicia sesión. katana, nuclei, testssl.sh y httpx revisan el sitio de forma anónima.

Los secretos nunca llegan a ZAP por su plan, por una línea de comandos, por un archivo en el host ni por
`docker inspect`: viajan por la entrada estándar del contenedor y se limpian de lo que devuelve ZAP.

## Lanzar un análisis

1. Pulsa **Nuevo análisis** (`#/new`) y elige **Aplicación web o API**. Si dice **No está activado en este servidor**,
   mira [Errores frecuentes](#errores-frecuentes).
2. **Objetivo**: elige un dominio verificado. Activa **Incluir subdominios** para usar el alcance guardado (los hosts
   que marques aquí como **Analizar** se guardan para sus próximos análisis). Para una API, añade su **Documentación de
   la API** (ver [Modo API](#modo-api)).
3. **Acceso**: elige hasta 3 usuarios de prueba y, si el dominio las tiene, **Enviar las cabeceras guardadas**. No
   puedes elegir un usuario de prueba que inicia sesión en un host fuera del alcance de este análisis. Sin ninguno de
   los dos, Pitangus te pide confirmar **Solo páginas públicas**.
4. **Revisar y lanzar**: revisa el tipo, el objetivo, el alcance y el acceso; si quieres, activa **Programar** (ver
   [Programarlo](#programarlo)); copia las IP de salida si tu sitio filtra por IP. Pulsa **Iniciar análisis** (o
   **Programar análisis**).

El análisis queda en cola y su progreso aparece en **Análisis** (`#/analyses`). Solo corre un análisis web a la vez por
instalación; uno nuevo espera a que termine el anterior.

<!-- screenshot: new-scan | El flujo guiado de Nuevo análisis en su primer paso, con Código, Imagen de contenedor y Aplicación web o API -->

<!-- screenshot: new-scan-review | El paso de revisión de un análisis web, con la opción de programarlo y las IP de salida que hay que permitir -->

### Modo API

Una API tiene pocos enlaces que seguir, así que dale a Pitangus su definición: un archivo **OpenAPI 3.x o Swagger
2.0** (JSON o YAML, hasta 5 MB), subido con **Subir archivo OpenAPI** o como URL en un host del alcance.

- Solo se piden sus operaciones **GET y HEAD**, 2000 como máximo. POST, PUT, PATCH y DELETE se quitan antes de que ZAP
  vea la definición, así que no se crea, cambia ni borra nada.
- Las peticiones van al host del dominio (los `servers` de la definición se reemplazan).
- Se rechazan las referencias a otros documentos (`$ref` fuera del archivo) y los anclajes de YAML: empaqueta la
  definición antes.
- Una URL se descarga una vez desde la dirección comprobada del host, sin redirecciones.
- El análisis guarda solo el SHA-256 de la definición y su número de operaciones.
- La definición añade los endpoints documentados al recorrido; no lo reemplaza. Con usuarios de prueba, se importa como
  cada uno de los que iniciaron sesión.

Los análisis programados recorren el sitio y no usan la definición de la API.

## Qué hace cada herramienta

Un análisis ejecuta estas herramientas en este orden. Cada una tiene su paso en el análisis, con un estado
(**Completado**, **Parcial** u **Omitido**) y el motivo.

| Herramienta | Versión | Qué hace | Límite fijo |
| --- | --- | --- | --- |
| katana | 1.7 | Recorre los hosts del alcance con un navegador headless para encontrar URL | Unos 5 minutos |
| robots.txt y sitemaps | Pitangus | Lee el robots.txt y los sitemaps de cada host para sumar URL | 2 minutos para todos los hosts |
| ZAP | 2.17 | Spider, spider AJAX y reglas pasivas sobre cada respuesta | 15 minutos más extras ([Límites](#límites-y-tiempos)) |
| nuclei | 3.11 | Plantillas de solo detección en cada host y en las páginas recorridas | 15 minutos |
| testssl.sh | 3.2 | Protocolos TLS, cifrados, certificado y HSTS de los 3 primeros hosts | 5 minutos por host |
| httpx | 1.12 | Identifica las tecnologías con las que responde cada host | 2 minutos |
| httpx + OSV | OSV-Scanner 2.6 | Busca sin conexión las versiones expuestas de paquetes conocidos | 10 minutos |

Cada herramienta corre en un contenedor endurecido que solo llega a los hosts del alcance, en las direcciones
comprobadas justo antes del análisis, con 10 peticiones por segundo como máximo.

### ZAP: recorrido y reglas pasivas

ZAP recorre el dominio hasta 2 minutos (un minuto más por cada host adicional) y luego su **spider AJAX** abre el sitio
en un Firefox headless hasta 2 minutos (5 niveles, 100 estados de página). El spider AJAX solo hace clic en enlaces
(`<a>`), nunca en botones ni campos de formulario, se queda dentro del alcance y evita los enlaces de cierre de sesión.
Ambos vuelven a correr como cada usuario de prueba que inició sesión.

Después, las **reglas pasivas** de ZAP leen cada respuesta: cabeceras de seguridad, cookies, fugas de información, datos
personales (PII), librerías JavaScript desactualizadas, cabeceras que revelan versiones, errores de depuración,
comentarios sospechosos y más. Solo se aplican a los hosts del alcance. Estas reglas se fijan explícitamente para que
una actualización de la imagen no las apague: divulgación de PII (10062), mensajes de error de depuración (10023),
información sensible en URL (10024) y en el Referer (10025), comentarios sospechosos (10027), librerías JavaScript
vulnerables (10003), banners en la página (10009), las cabeceras `Server`, `X-Powered-By`, `X-Backend-Server`,
`X-AspNet-Version` y de depuración que revelan versiones (10036, 10037, 10039, 10061, 10052, 10056), direcciones IP
privadas (2), IDs de sesión en URL (3), divulgación de hashes (10097) y aplicación web moderna (10109). Los conjuntos de
reglas beta y alpha de la imagen no se instalan.

### katana y el inventario de URL

**katana** recorre los hosts del alcance con un navegador headless (3 niveles, 2 minutos, sin formularios). Pitangus
suma las URL del robots.txt y los sitemaps de cada host (sin redirecciones, con tamaño limitado; se rechaza el XML que
declara un DOCTYPE o entidades), las rutas GET de la definición de la API y lo que alcanza el spider de ZAP. Todo junto
forma el **inventario de URL** del análisis: solo hosts del alcance, sin query strings, hasta 500 URL, con cuántas aportó
cada fuente. ZAP pide hasta 200 de ellas antes de su spider, y nuclei también las lee.

### nuclei: plantillas de detección

**nuclei** ejecuta las plantillas de solo detección de nuclei-templates 10.4.9 (unas 2400: archivos expuestos,
configuraciones incorrectas, versiones, takeovers, TLS) en la raíz de cada host, y las de página en hasta 100 páginas
del inventario. Pitangus conserva solo las plantillas que envían GET o HEAD sin cuerpo, sin payloads y sin fuzzing, sin
marcas de ataque en sus rutas y sin etiquetas de ataque o de login. Una plantilla de CVE se conserva solo si lee rutas
fijas, así que detecta una versión o un archivo expuesto y nunca explota. Corre sin actualizaciones y sin servidor
out-of-band.

Pitangus añade sus propias plantillas (ids `pitangus-…`), que pasan el mismo filtro: un listado de directorio abierto y
credenciales en una respuesta JSON en cada página del inventario, y en cada host una lista fija de 26 rutas sensibles
(carpetas de copias de seguridad y configuración, actuator de Spring Boot, métricas, server-status, phpinfo, archivos de
credenciales…), descripciones de API expuestas y archivos de metadatos de desarrollo. Cada una prueba el contenido, no
solo un 200. Un `security.txt` publicado aparece junto a las tecnologías del dominio.

El texto propio de nuclei (descripción, remediación, referencias, CWE y CVE) se muestra tal como se publicó.

### testssl.sh: TLS

**testssl.sh** lee el TLS de los 3 primeros hosts del alcance: protocolos, cifrados, certificado, forward secrecy, HSTS
y otras cabeceras. Sus comprobaciones de vulnerabilidades no corren. Solo lo que califica como bajo o peor se convierte
en hallazgo. Sus comprobaciones del certificado (cadena de confianza, revocación, caducidad, vigencia, nombre) son un
hallazgo por host con cada comprobación como evidencia. testssl.sh no da texto de remediación, así que sus hallazgos
dicen solo lo que reportó.

### httpx: tecnologías y versiones expuestas

**httpx** identifica las tecnologías con las que responde cada host (frameworks, servidores, librerías). Aparecen en
**Tecnologías**, en la página del dominio; la versión de un servidor es una tecnología ahí, no un hallazgo.

Cuando httpx lee una versión (al menos mayor y menor) de un paquete conocido, OSV-Scanner la busca **sin conexión** en
las mismas bases de OSV que usan los análisis de dependencias: Flask, Django, Werkzeug, Tornado, Gunicorn, aiohttp,
Express, Next.js, Nuxt, jQuery, jQuery UI, jQuery Migrate, Bootstrap, AngularJS, Lodash, Moment.js, Underscore,
Handlebars, DOMPurify, Vue, React y Axios. Para esto no se envía nada al sitio ni a internet.

Cada producto y versión con avisos se convierte en un hallazgo, como «Flask 2.2.3 tiene vulnerabilidades conocidas»
(herramienta `httpx + OSV`), con cada CVE, la peor severidad, la versión que los corrige todos, KEV y EPSS. Su
confianza es menor: la versión sale de lo que muestra el sitio, y un parche aplicado por backport conserva el número
antiguo, así que confírmala en el servidor. Una librería JavaScript que ZAP ya reportó en esa versión no se repite. Los
servidores web y runtimes (Apache httpd, nginx, OpenSSL, PHP, IIS…) no se buscan, y el paso los lista como no
buscados.

## Leer los resultados

### Progreso y cobertura parcial

El análisis muestra un paso por herramienta, además de la comprobación del inicio de sesión, el inventario de URL y la
unión de duplicados.

- **Completado**: la herramienta hizo su parte.
- **Parcial**: falló, se pasó del tiempo o no llegó a un host. El análisis sigue, y lo que solo esa herramienta había
  visto no se marca como remediado.
- **Omitido**: no corrió (falta la imagen, no hay Docker), con el motivo.

Nada se da por limpio si una herramienta no llegó a un host. Si nuclei descarta un host por no responder, katana o
httpx no obtienen respuesta, o testssl.sh no logra conectar, el paso nombra el host y dice que no encontrar nada ahí no
prueba nada.

<!-- screenshot: scan-progress | Un análisis web con los pasos de sus herramientas marcados como completados, parciales u omitidos -->

### Un hallazgo por problema

Cuando ZAP, nuclei o testssl.sh reportan el mismo problema en la misma URL, Pitangus guarda un solo hallazgo que lista
cada herramienta que lo vio y qué vio cada una (**También lo reportaron**, en el detalle). Solo cuentan equivalencias
explícitas: cabeceras de seguridad que faltan, atributos de cookies, HSTS, TLS obsoleto y cifrados débiles, problemas
del certificado, un `.git` o un `.env` expuestos. Nada se une solo por título o por CWE.

En **Hallazgos** y en el informe técnico, el mismo problema en varias URL es una fila que se abre en cada URL, por
ejemplo «15 hallazgos en 8 problemas». Cada URL conserva su propio triage e historial, y las cifras las cuentan una a
una. El detalle de cada hallazgo muestra primero la guía de la herramienta y luego la **Guía OWASP**. Ver
[hallazgos.md](hallazgos.md).

<!-- screenshot: finding-web-detail | El detalle de un hallazgo web con su evidencia, la guía OWASP y las otras herramientas que lo reportaron -->

### Cuándo se marca remediado un hallazgo web

El siguiente análisis web marca como remediado lo que ya no aparece, pero solo entre lo que había visto **un análisis
como él**: mismo modo, misma definición de API, mismo uso de cabeceras y de usuarios de prueba, en un host que de verdad
revisó. Un recorrido anónimo no responde por lo que se encontró con sesión iniciada; un recorrido no responde por los
endpoints de una definición de API; ningún análisis responde por un host al que no llegó ni por una herramienta que
terminó parcial.

Los hallazgos web usan las mismas huellas que una importación del SARIF de ZAP, así que importar tu propio análisis de
ZAP del mismo sitio no duplica nada. Solo se guardan el método, el parámetro y una evidencia breve y redactada, nunca la
petición ni la respuesta completas. Volver a verificar un hallazgo web lanza un análisis web nuevo (solo quien
administra).

## Programarlo

Quien administra puede repetir un análisis pasivo por dominio: desde el paso de revisión (**Programar**, con **También
ahora**) o desde la página del dominio.

| Ajuste | Opciones |
| --- | --- |
| **Frecuencia** | **Diaria**, **Semanal** (eliges días de la semana) o **Mensual** (días 1 a 28) |
| **Hora** y **Zona horaria** | Una hora del día en una zona horaria IANA; por defecto, la de tu navegador |
| Acceso | Hasta 3 usuarios de prueba y las cabeceras guardadas |

La página describe la regla con palabras («Cada lunes a las 09:00 (America/Bogota)») y muestra el próximo análisis.
Pitangus busca los análisis pendientes cada 5 minutos y analiza un dominio como máximo una vez al día: si ya se analizó
ese día local, la programación pasa a su siguiente fecha. Los análisis programados cubren el host del dominio y su
alcance guardado, de uno en uno.

Lo que queda fuera cuando corre un análisis programado:

- Un usuario de prueba borrado desde entonces se quita de la programación.
- Un usuario de prueba que ahora inicia sesión fuera del alcance guardado se deja fuera de ese análisis.
- Las cabeceras que ya no están guardadas no se envían.
- La definición de la API no se usa.
- Un dominio cuya prueba caducó se omite con el motivo (**En pausa**) hasta que se verifique de nuevo.

El análisis y la página del dominio dicen qué quedó fuera.

## Sitios que filtran por IP

Si un firewall o un WAF delante de tu sitio solo deja pasar direcciones conocidas, permite la dirección desde la que
analiza Pitangus. El paso de revisión la muestra en **Si tu sitio filtra por IP, permite:** con un botón **Copiar**.

- Defínela con `PITANGUS_EGRESS_IPS` (direcciones IP o rangos CIDR separados por comas, 16 como máximo; ver
  [configuracion.md](configuracion.md)).
- Sin ella, quien administra puede pulsar **Detectar** una vez: el servidor le pregunta a `https://api.ipify.org` desde
  qué dirección lo ve y guarda la respuesta (ver [seguridad.md](seguridad.md#qué-sale-de-tu-máquina)). Esa es la
  dirección de la API: si el worker corre en otra máquina, define la variable con la dirección del worker.
- Los miembros, cuando no hay dirección, ven una nota para pedírsela a quien administra.

## Desconectar un dominio

**Desconectar dominio**, al final del **Resumen** del dominio, borra su configuración: cabeceras guardadas, usuarios de
prueba (con sus contraseñas y claves TOTP), hosts relacionados y alcance guardado, y su análisis programado. Las
credenciales borradas no se pueden recuperar.

Lo que se analizó o importó contra él (análisis, hallazgos, triage, tickets) se queda en **Análisis** y **Hallazgos**
como evidencia, y se vuelve a enlazar si añades el mismo host otra vez.

## Límites y tiempos

| Qué | Límite |
| --- | --- |
| Análisis web a la vez | 1 por instalación |
| ZAP | 15 minutos, más 1 por host adicional, 3 por el recorrido de cada usuario de prueba, 3 por cada spider AJAX (el anónimo y uno por usuario de prueba) y 2 segundos por URL del inventario que pide; contenedor con 3 GB y 2 CPU. Comprobación del inicio de sesión: unos 2,5 minutos por usuario de prueba, antes del análisis |
| katana / nuclei / testssl.sh / httpx / versiones expuestas | unos 5 / 15 / 5 por host (3 hosts) / 2 / 10 minutos |
| Peticiones por segundo (katana, nuclei, httpx) | 10 |
| Dominios por espacio de trabajo | 20 |
| Hosts en el alcance además del dominio | 20 (100 listados) |
| Cabeceras / usuarios de prueba por dominio | 10 / 10 |
| Usuarios de prueba por análisis | 3 |
| Definición de API | 5 MB, 2000 operaciones GET y HEAD |
| Inventario de URL | 500 URL |

La mayoría de los análisis tardan entre 15 y 25 minutos.

## Referencia de la API

Todas las rutas reciben y devuelven JSON. Las lecturas están abiertas a cualquier usuario con sesión; toda escritura
requiere a quien administra.

| Ruta | Qué hace |
| --- | --- |
| `GET /api/domains` | Lista los dominios con su prueba, programación, último análisis, tecnologías, `dast` y `egress` |
| `POST /api/domains` | Añade un dominio (`url`, `kind`, `context`) |
| `POST /api/domains/probe` | Sondea una URL antes de añadirla (`/api/domains/check` es un alias) |
| `POST /api/domains/verify` | Pide la prueba una vez (`method`: `dns`, `file` o `meta`) |
| `GET /api/domains/scope` / `POST /api/domains/scope` | Lee o guarda el alcance (`set`, `add`, `remove`, `exclude_all`); 409 sin prueba DNS |
| `POST /api/domains/discover` | Vuelve a buscar hosts relacionados (202) |
| `POST /api/domains/headers` | Guarda o quita una cabecera |
| `POST /api/domains/test-users` | Guarda o quita un usuario de prueba |
| `POST /api/domains/scans` | Pone en cola un análisis (`mode`, `use_scope` o `hosts`, `use_headers`, `test_users`, `spec` o `spec_url`); 202 con `run_id` |
| `POST /api/domains/schedule` | Define o quita la programación (`frequency`, `weekdays`, `month_days`, `time`, `timezone`, `test_users`, `use_headers`) |
| `POST /api/domains/egress` | Detecta una vez la dirección de salida |
| `POST /api/domains/remove` | Desconecta un dominio (responde `runs_kept`) |

## Errores frecuentes

| Lo que ves | Por qué | Cómo resolverlo |
| --- | --- | --- |
| **No está activado en este servidor**, o «Los análisis web están apagados en este servidor» | `PITANGUS_DAST_ENABLED` no está definida para la API o el worker | Define `PITANGUS_DAST_ENABLED=1` en los dos y reinicia (`make up`). |
| «La imagen de ZAP no está en este servidor: ejecuta make engines» (u otra herramienta) | No se descargó la imagen | Ejecuta `make engines`. Un paso marcado **Omitido** dice cuál. |
| «Los análisis web necesitan el runner de Docker» | El worker no tiene socket de Docker | Usa el runner de Docker ([contenedores.md](contenedores.md)). |
| Aún no aparece el registro TXT | Nombre o valor incorrectos, o el DNS no se ha propagado | Compruébalo con `dig +short TXT _pitangus.<host>`, espera unos minutos y verifica de nuevo. |
| El archivo o la etiqueta «respondió con una redirección» | La prueba se sirve a través de una redirección | Sírvela desde ese host exacto, sin redirección. |
| El dominio resuelve a una dirección privada o reservada | El nombre apunta a una IP interna | Solo se analizan sitios públicos. Usa el nombre público. |
| `<host>` no tiene una prueba DNS vigente | Los subdominios necesitan una prueba DNS | Verifica con el registro TXT. |
| No pudo iniciar sesión como «nombre» | Credenciales incorrectas, un login que el navegador no logra completar, una página de comprobación que no responde 200 | Lee el motivo, corrige el usuario de prueba (URL de login y de comprobación, clave TOTP) y vuelve a analizar. Mientras tanto, el análisis tiene cobertura parcial. |
| Un paso de herramienta queda **Parcial** u **Omitido** | La herramienta falló, se pasó del tiempo, no llegó a un host o falta su imagen | Lee el motivo del paso. Lo que solo ella había visto no se marca como remediado. |
| Los pasos no llegan a los hosts, pocas URL, muchos 403 | Un WAF o un firewall bloquea el análisis | Permite las IP de salida del paso de revisión ([Sitios que filtran por IP](#sitios-que-filtran-por-ip)). |
| «Ya hay un análisis web en cola o en curso» | Solo corre un análisis web a la vez | Espera a que termine. |

Más en [solucion-problemas.md](solucion-problemas.md).

## Próximos pasos

- [hallazgos.md](hallazgos.md): triage, plazos de corrección y el ciclo de vida de lo que encuentra un análisis.
- [integraciones.md](integraciones.md#trae-tu-propio-dast): importa el SARIF de tus propios análisis con ZAP, nuclei o
  Strix contra un dominio verificado.
- [seguridad.md](seguridad.md): qué sale de tu servidor y cómo se aíslan los contenedores de análisis.
- [solucion-problemas.md](solucion-problemas.md): cuando algo no funciona.
- [glosario.md](glosario.md): los términos de esta página.
