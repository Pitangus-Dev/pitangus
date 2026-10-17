[English](README.md) · Español

# Demo pública

Un Pitangus de solo lectura que cualquiera puede abrir, con datos inventados: **Lapis Labs**, la organización ficticia
que `pitangus demo --full` construye sin conexión a partir de salidas de motores grabadas en este repositorio (cinco
repositorios con un mes de análisis, la revisión de un pull request, una imagen, dos dominios, miembros y un modelo de
amenazas). Quien la visita recorre hallazgos, evidencia, guías de corrección, modelos de amenazas e informes; no puede
cambiar nada, y el servidor no abre ninguna conexión hacia fuera.

## Cómo se mantiene de solo lectura

Lo impone el servidor con `PITANGUS_PUBLIC_DEMO=1` ([docs/es/configuracion.md](../../docs/es/configuracion.md)), no el
panel escondiendo botones:

- Rechaza toda petición que no sea de lectura (403, `code: public_demo`, con el mensaje en el idioma de quien lee) antes
  de cualquier ruta, comprobación de sesión o lectura del cuerpo, para cualquier cuenta y rol. Se permite: entrar, salir
  y los dos PDF de evidencia de auditoría (se generan para quien los pide; no se guarda nada). Lecturas rechazadas: los
  endpoints de cron y métricas y las direcciones de retorno de GitHub.
- Solo la cuenta demo puede iniciar sesión; cualquier otra sesión no cuenta. Su contraseña es pública, así que los
  intentos fallidos bloquean la dirección de quien los hace, nunca la cuenta, y guarda como mucho 500 sesiones.
- Sin worker ni tareas periódicas; `pitangus worker` y `pitangus periodic` se niegan a arrancar. El proceso de la API no
  puede abrir conexiones de red ni resolver otro nombre que el de la base de datos. No arranca si hay credenciales de
  integraciones, ni con EUVD, la sincronización de NVD, la validación de secretos o el worker embebido activos.
- En este compose, la API, el job de carga y PostgreSQL están en una red interna sin salida a internet; solo
  `cloudflared` sale, hacia Cloudflare. El servidor no publica ningún puerto.

## Qué necesitas

- Un servidor Linux pequeño con Docker Engine y Compose v2: bastan 1 vCPU, 2 GB de RAM y 10 GB de disco (la demo usa
  como mucho unos 1,3 GB). Sirve cualquier proveedor: desde fuera solo llega el túnel.
- Una cuenta de Cloudflare con el dominio (aquí `pitangus.dev`) y Cloudflare Tunnel (gratis).

## Ponerla en marcha

1. En el servidor, deja abierto solo SSH en el firewall (el túnel no necesita puertos de entrada) y clona una versión:
   `git clone --branch v0.16.0 https://github.com/Pitangus-Dev/pitangus /opt/pitangus` (la primera con el modo demo;
   hasta entonces, esta rama).
2. En Cloudflare: Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared, llámalo `pitangus-demo` y copia el
   token del comando de instalación (no ejecutes ese comando: cloudflared lo arranca el compose). Añade un public
   hostname: `demo.pitangus.dev` → servicio `HTTP` → `api:8766`. Cloudflare crea solo el registro DNS con proxy.
3. `cp deploy/demo/demo.env.example deploy/demo/.env`, rellena `PITANGUS_DEMO_DOMAIN` y `CLOUDFLARE_TUNNEL_TOKEN`, y
   `chmod 600 deploy/demo/.env`.
4. `sh deploy/demo/reset.sh`. La primera vez construye la imagen (unos minutos); después carga los datos, arranca la demo
   y espera a que el panel responda.
5. Reiníciala cada día desde el crontab del operador (`crontab -e`):
   `15 4 * * * sh /opt/pitangus/deploy/demo/reset.sh >> $HOME/pitangus-demo.log 2>&1`
   Cada reinicio genera una contraseña demo y una clave maestra nuevas y rehace la base desde cero (PostgreSQL vive en
   memoria), así las fechas de los análisis siguen siendo recientes. Quien esté dentro en ese momento sale de la sesión;
   tarda alrededor de un minuto.

### Ajustes en Cloudflare

- SSL/TLS: *Always Use HTTPS* activado, TLS mínimo 1.2. El panel ya envía sus propias cabeceras de seguridad (CSP, HSTS,
  `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`), igual que cualquier
  otra instalación: no las repitas con Transform Rules.
- Security → WAF → Rate limiting rules (el plan gratuito tiene una regla, con periodo de 10 segundos): que coincida con
  `http.request.uri.path in {"/api/auth/login" "/api/reports/audit" "/api/evidence/portfolio"} or ends_with(http.request.uri.path, ".pdf")`,
  5 peticiones cada 10 segundos por IP, acción *Block* (si tu plan no acepta la parte de `ends_with`, deja las tres
  rutas). Iniciar sesión y generar PDF es lo que cuesta CPU.
- Caché: nada que hacer (todas las respuestas dicen `no-store`).

### Comprobarla

```sh
curl -sI https://demo.pitangus.dev/ | grep -i -E 'content-security-policy|strict-transport|x-frame'
curl -s -X POST https://demo.pitangus.dev/api/repositories/scans -H 'Origin: https://demo.pitangus.dev' \
  -H 'X-Pitangus-Action: scan-repository' -H 'Content-Type: application/json' -d '{}'
# → 403 {"error": "This is a public read-only demo …", "code": "public_demo"}
```

## Credenciales

- La cuenta de quien visita es `demo` (rol *miembro*). Su contraseña se genera en cada reinicio, aparece en la pantalla
  de inicio de sesión y ya viene escrita: es pública a propósito, así que enlaza la demo y di «las credenciales están en
  la pantalla de inicio de sesión» en vez de copiar una contraseña que cambia cada día. Nunca es la contraseña de una
  persona real.
- La carga también crea un administrador, `operator`, con una contraseña aleatoria que nadie ve. Existe para que nadie
  pueda reclamar el servidor con un código de configuración; en modo demo no puede iniciar sesión.
- `deploy/demo/generated.env` (lo escribe `reset.sh`, solo legible por su dueño) guarda la contraseña demo, la clave
  maestra y la contraseña de la base. Solo protegen datos inventados y cambian cada día. No hay tokens reales en ninguna
  parte.

## Actualizar

`git -C /opt/pitangus fetch --tags && git -C /opt/pitangus checkout v<nueva>`, luego
`docker compose -f deploy/demo/compose.yaml --env-file deploy/demo/.env --env-file deploy/demo/generated.env build`
y `sh deploy/demo/reset.sh`. Con una imagen publicada que ya tenga el modo demo, define `PITANGUS_DEMO_IMAGE` en `.env`
en lugar de construir.

## En Render

Encaja, con diferencias; un VPS pequeño es más simple y más barato. Un web service con la imagen publicada
(`ghcr.io/pitangus-dev/pitangus:<versión>`, Starter, unos 7 USD/mes) con el entorno del servicio `api` de arriba
(`PITANGUS_PUBLIC_DEMO=1`, `PITANGUS_EUVD=0`, `PITANGUS_CVE_SYNC=0`, `PITANGUS_EMBEDDED_WORKER=0`, `PITANGUS_BIND=0.0.0.0`,
`PITANGUS_FORWARDED_ALLOW_IPS=*`, y `PITANGUS_PUBLIC_DEMO_PASSWORD` y `PITANGUS_MASTER_KEY` generadas) y un PostgreSQL de
Render (unos 6–7 USD/mes), con el dominio con proxy de Cloudflare. Lo que cambia: Render no tiene una red solo interna,
así que el control de red es únicamente el del código (el proceso de la API no abre conexiones); la imagen no lleva las
grabaciones, así que la carga necesita una imagen que añada `fixtures/`, `tests/fixtures`, `tests/engine-outputs` y
`web/src/examples/threat-models`; y el reinicio diario es un Cron Job de Render (desde 1 USD/mes) que vacía la base,
ejecuta `seed.sh` y luego llama al deploy hook del web service para que la API arranque de nuevo.
