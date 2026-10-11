[English](../quickstart.md) · Español

# Inicio rápido: de cero a una corrección verificada

Esta guía te lleva de nada a tener Pitangus corriendo en tu máquina, un análisis de código vulnerable de verdad y una
corrección que Pitangus confirma, en unos 15 minutos. No necesitas saber de seguridad de aplicaciones: cada paso dice
qué vas a ver. Los pasos marcados **opcional** pueden esperar. ¿Términos nuevos? Mira
[Qué es Pitangus](vista-general.md) y el [glosario](glosario.md).

## Requisitos

- **Docker** (Engine 24 o posterior con Compose v2.24 o posterior), **make** y **git**.
- 4 GB de memoria y 8 GB de disco libre.
- macOS, Linux o Windows con WSL2 (clona dentro de Linux, no bajo `/mnt/c`).

## 1. Arrancar (5 min)

```bash
git clone --branch v0.13.0 https://github.com/Pitangus-Dev/pitangus.git
cd pitangus
make doctor
```

`make doctor` comprueba Docker, Compose, el disco, el puerto y los permisos. Cada línea debería empezar con `✓`:

```text
Result: 14 passed, 0 warnings, 0 errors
```

Una línea con `✗` dice qué corregir en la línea de abajo. Después:

```bash
make setup PREBUILT=1
make up
```

`make setup PREBUILT=1` crea `.env` y las carpetas y elige las imágenes publicadas y firmadas en lugar de construirlas
(omítelo para construirlas desde el código). `make up` las descarga junto con los motores, unos 800 MB: menos de un
minuto con una conexión rápida, unos 2 minutos a 50 Mbps (medido desde cero: cerca de 1 minuto a 150 Mbps, 3 en un
portátil con WSL2). Con una VPN o un proxy corporativo la primera descarga puede tardar mucho más: mira
[Solución de problemas](solucion-problemas.md). Termina así (los mensajes de la terminal están en inglés):

```text
Waiting for the panel to respond.....
Engines: ready.
Panel: http://127.0.0.1:8766
Setup code: …
```

Abre <http://127.0.0.1:8766> y crea la cuenta de administrador con el **código de configuración**. Si lo pierdes,
`make setup-code` lo vuelve a mostrar.

Justo después, el panel te pide activar el segundo factor (TOTP) con tu app de autenticación: es obligatorio para los
administradores (`PITANGUS_REQUIRE_TOTP`, ver [Configuración](configuracion.md)) y no se abre nada más hasta que lo
actives. Guarda los códigos de respaldo que te muestra.

El panel sigue el idioma de tu navegador; puedes cambiarlo cuando quieras desde la cabecera o la pantalla de inicio de
sesión. Los comentarios en PRs, los avisos, Jira, los informes y la salida de la CLI usan `PITANGUS_DEFAULT_LOCALE`
(`en` por defecto).

## 2. Verlo funcionar sin conectar nada (2 min)

```bash
make demo
```

Analiza de verdad, con los mismos motores del panel, los ejemplos vulnerables a propósito que trae el repositorio
(código en siete lenguajes, dependencias con vulnerabilidades conocidas, un secreto y un Dockerfile) e importa un
modelo de amenazas de ejemplo:

```text
Analyzing … example files with Pitangus's engines…
Code: … findings (completed).
Example threat model imported: "Demo · Customer portal (STRIDE)".
Done: open the panel and look at Overview, Findings and Threats.
```

En el panel verás el activo **demo · ejemplos vulnerables**:

- **Resumen:** hallazgos por severidad, vulnerabilidades con explotación activa (KEV) y lo que hay que atender
  primero.
- **Hallazgos:** despliega uno y mira **Cómo corregirlo** (el comando o el ejemplo de código).
- **Amenazas:** el diagrama, las amenazas y el informe PDF.

<!-- screenshot: overview | El Resumen después de make demo, con los hallazgos por severidad y la lista de primeros pasos -->

Con `make demo IMAGE=nginx:1.21` también se analiza una imagen de contenedor pública (Trivy y Grype, un par de minutos).

`make demo FULL=1` además crea **Lapis Labs**, una organización inventada que llena todas las vistas, sin conexión y en
segundos: cinco repositorios `lapis-labs/…` con un mes de análisis (tendencias, hallazgos remediados, MTTR, plazos de
corrección, algunos vencidos), una revisión de pull request, una imagen de contenedor, el dominio `tienda.example.com`
verificado para la demo (alcance, programación semanal, usuario de prueba, tecnologías detectadas y dos análisis web
pasivos), `soporte.example.net` pendiente, dos miembros marcados «(demo)» y algunas decisiones de triage,
firmadas por `demo` o por esos miembros, nunca por ti. Sus hallazgos
son salidas de los motores grabadas sobre estos mismos ejemplos (`tests/fixtures`, `tests/engine-outputs`) y
reproducidas con los parsers y el registro de siempre: no se analiza ni se contacta nada. Crea antes la cuenta de
administrador (los miembros la esperan) y, si quieres KEV y EPSS en los hallazgos, abre una vez el Resumen antes de
ejecutarla (descarga esas fuentes; la demo solo las lee). Los dominios de la demo usan nombres reservados para ejemplos
y nunca se verifican ni se analizan de verdad. Ejecutarla otra vez no añade nada. Slack y Jira quedan fuera: guardarlos
contacta sus servidores.

> [!WARNING]
> `FULL=1` escribe en el espacio de trabajo donde lo ejecutas, junto a tus datos reales, y luego nada lo borra. Úsalo
> en una instalación para probar Pitangus o sacar capturas, no en la que usa tu equipo.

## 3. Conectar tus repositorios de GitHub (5 min)

En **Integraciones → Proveedores de código**, el panel te guía para crear la GitHub App de tu servidor con los permisos
justos (lectura de código, comentarios y estados en PRs). Al final la instalas en los repositorios que quieras: mejor
*Only select repositories* para empezar. Detalle en [Conectar GitHub](github-app.md).

¿Sin GitHub (GitLab, Bitbucket, Azure DevOps o una carpeta local)? Usa [`scan` en la terminal o en CI](cli.md).

## 4. Primer análisis y primera corrección

1. Haz clic en **Nuevo análisis** en la cabecera (o pulsa `N`). El flujo guiado tiene una guía de pasos al lado: elige
   **Código**, luego **Añadir repositorios** y escoge uno o varios (o **Toda la organización**). Si quieres, añade un
   **Contexto** para el informe; después revisa **Revisar y lanzar** y pulsa **Iniciar análisis**.
2. El análisis corre en segundo plano; síguelo en **Análisis**. Al terminar, el panel muestra un aviso.
3. En **Hallazgos**, empieza por lo marcado como KEV o crítico. Cada hallazgo trae **Cómo corregirlo**.
4. Aplica la corrección, súbela a la rama principal y pulsa **Reverificar** en el hallazgo. Al terminar el análisis,
   dice **Corregido ✓ · ya no aparece en el análisis** o **Sigue presente en el análisis**. Si el análisis quedó
   incompleto, lo dice, porque un análisis incompleto no demuestra nada.

<!-- screenshot: new-scan | El flujo guiado de Nuevo análisis en su primer paso, con los tipos Código, Imagen de contenedor y Aplicación web o API -->

Si decides no corregir algo, regístralo en el triage (riesgo aceptado o falso positivo) con su motivo y, si es un riesgo
aceptado, una fecha de caducidad: queda como evidencia y no vuelve a molestar. Ver [Hallazgos](hallazgos.md).

## 5. Que trabaje solo (opcional, recomendado)

- **Pull requests y rama principal:** en **Pull requests**, un administrador activa la vigilancia de tus repositorios.
  Cada PR se revisa solo (solo cuenta lo que introduce) y, tras cada merge, la rama principal se reanaliza. Ver
  [Analizar tu código](analisis-de-codigo.md).
- **Avisos nuevos a diario:** activos por defecto. Una vez al día se contrastan tus dependencias, sin conexión, con los
  avisos publicados después del último análisis.
- **Avisos en tu canal:** en **Integraciones → Avisos**, un administrador añade Slack, Teams o un webhook para que te
  enteres sin abrir el panel. Para que los mensajes enlacen al hallazgo, define `PITANGUS_PUBLIC_URL`.

## 6. Analizar tu sitio web, de forma pasiva (opcional)

Si tienes un sitio web o una API, Pitangus puede leerlo como lo haría un visitante y señalar cabeceras de seguridad que
faltan, cookies sin sus atributos, archivos expuestos, TLS débil y librerías desactualizadas. Nunca ataca. Está apagado
hasta que el servidor define `PITANGUS_DAST_ENABLED=1`:

```bash
echo 'PITANGUS_DAST_ENABLED=1' >> .env
make up
```

Después, como administrador: **Dominios y APIs → Añadir dominio**, demuestra que lo controlas (un registro TXT de DNS,
un archivo o una etiqueta meta) y lanza **Nuevo análisis → Aplicación web o API**. El recorrido completo, con usuarios
de prueba y programación, está en [Analizar un sitio web o una API](analisis-web.md).

## 7. Más adelante (opcional)

- **Equipo:** invita a más personas en **Usuarios** (rol miembro o administrador).
- **Jira:** en **Integraciones → Gestión de incidencias**, para convertir hallazgos en incidencias sin duplicados.
- **Imágenes privadas:** credenciales de solo lectura en **Integraciones → Registros de contenedores**. Ver
  [Analizar imágenes de contenedor](analisis-de-imagenes.md).
- **Auditorías:** en **Hallazgos**, **Más formatos → Evidencia para auditoría (SOC 2, ISO, PCI…)…** genera el PDF (o
  **Informe de los seleccionados** con los que marques). Ver [Cumplimiento](cumplimiento.md).
- **Actualizaciones:** instalaste una versión fija, así que `make update` por sí solo se queda en ella. Cuando salga una
  nueva ([Releases](https://github.com/Pitangus-Dev/pitangus/releases)), mira [Actualizar Pitangus](actualizar.md).
- **Desde otra máquina:** ponlo detrás de HTTPS ([Desplegar en un VPS](despliegue-vps.md)); sin HTTPS fuera de
  `127.0.0.1` no arranca.

## Si algo sale mal

| Síntoma | Solución |
| --- | --- |
| `make doctor` muestra un `✗` | Haz lo que dice la línea de abajo y vuelve a ejecutar `make doctor`. |
| El primer `make up` va muy lento | Probablemente estás detrás de una VPN o un proxy: mira [Solución de problemas](solucion-problemas.md#vpn-y-proxy). |
| Perdiste el código de configuración | `make setup-code`. |
| Un motor sale como *No probado* | `make status` lista las imágenes que faltan; `make engines` las descarga. |

Más en [Solución de problemas](solucion-problemas.md).

## Siguientes pasos

- [Conceptos clave](conceptos.md): ejecuciones, hallazgos, huellas y triage.
- [Analizar tu código](analisis-de-codigo.md), [Analizar imágenes de contenedor](analisis-de-imagenes.md),
  [Analizar un sitio web o una API](analisis-web.md).
- [Integraciones y automatización](integraciones.md): CI, SARIF, Jira y avisos.
