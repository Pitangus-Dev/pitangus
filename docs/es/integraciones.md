[English](../integrations.md) · Español

# Integraciones y automatización

Las integraciones conectan Pitangus con las herramientas que tu equipo ya usa: GitHub para el código y los pull
requests, registros de contenedores para imágenes privadas, Slack, Teams o un webhook para los avisos, Jira Cloud para
las incidencias y tu CI para los resultados de otros escáneres. Todas son opcionales; Pitangus funciona por su cuenta
con carpetas locales e imágenes públicas. Las configura quien administra. Los tokens y las URL de webhooks quedan
cifrados en PostgreSQL mediante la bóveda, y los valores secretos nunca vuelven al navegador.

## La página de Integraciones

**Integraciones** (`#/integrations`, o `G` y luego `E`) es una página por secciones, cada una una lista de filas con su
estado (conectado, sin configurar, en desarrollo) y su configuración plegada debajo:

| Sección | Qué conectas | Quién |
| --- | --- | --- |
| **Proveedores de código** | La GitHub App; GitLab, Bitbucket y Azure DevOps aparecen **En desarrollo** | Conectan los administradores; los miembros ven el estado |
| **Registros de contenedores** | Tokens de solo lectura para registros privados | Administradores |
| **Avisos** | Slack, Microsoft Teams y webhooks genéricos | Solo administradores (los miembros no ven esta sección) |
| **Gestión de incidencias** | Jira Cloud: la conexión, los destinos y las reglas de enrutamiento | Conectan los administradores; los miembros ven el estado |
| **Asistencia con IA** | Nada todavía: próximamente | Los administradores pueden retirar una clave guardada por una versión anterior |

<!-- screenshot: integrations | La página de Integraciones con sus secciones: proveedores de código, registros de contenedores, avisos, gestión de incidencias y asistencia con IA -->

Los miembros ven una nota arriba que dice que conectar proveedores y guardar claves es cosa de un administrador.

## Repositorios y pull requests de GitHub

La conexión compatible para repositorios es una **GitHub App**. Necesita cuatro permisos: Contents (lectura), Metadata (lectura), Pull requests (lectura y escritura) y Commit statuses (lectura y escritura). Pitangus usa tokens de instalación de una hora en memoria y no necesita webhooks ni OAuth. Sigue el proceso completo en [Conectar GitHub](github-app.md).

En cada repositorio, una persona administradora puede activar la vigilancia de pull requests, decidir si Pitangus comenta y publica un estado del commit, elegir la severidad que bloquea y, si hace falta, volver a analizar la rama principal cuando cambia. Pitangus consulta GitHub cada `PITANGUS_PR_POLL_SECONDS` en lugar de exponer un webhook entrante. [Analizar tu código](analisis-de-codigo.md) explica cómo cuenta los hallazgos una revisión de pull request.

Las conexiones con GitLab, Bitbucket y Azure DevOps aparecen como **En desarrollo** y todavía no funcionan. Aun así, puedes analizar repositorios de esos proveedores desde sus pipelines con la CLI.

## CI y SARIF

El repositorio incluye una [GitHub Action](../../action.yml) compuesta y oficial, además del comando `pitangus scan` para CI. Analizan la carpeta descargada, pueden comparar un cambio con una rama base, generan SARIF y devuelven códigos de salida documentados. No necesitan un servidor Pitangus en ejecución. [Terminal y CI](cli.md) contiene las entradas, salidas, códigos y ejemplos derivados de `action.yml` y del parser de la CLI.

Para sumar al registro de Pitangus los hallazgos de otro motor, importa SARIF 2.1.0 desde el panel. Un pipeline puede enviar SARIF a una instancia mediante `POST /api/ci/sarif` con `PITANGUS_IMPORT_TOKEN`; usa HTTPS y guarda el token en el almacén de secretos de CI. El sitio genera la [referencia de la API de automatización](../../docs-site/README.es.md#referencia-de-api-generada) desde OpenAPI.

### Traer resultados de otros analizadores

Pitangus no corre todos los motores que existen, y lo dice en
[Qué cubre Pitangus](vista-general.md#qué-cubre-pitangus-y-qué-no). Lo que no corre, lo importa: cualquier
herramienta que escriba SARIF 2.1.0 entra en el mismo registro, con las mismas huellas, triage, plazos, incidencias
de Jira y avisos que los hallazgos propios, y se marca corregido igual cuando una importación posterior ya no lo
reporta. Tres caminos: **Nuevo análisis → Importar SARIF** en el panel; `python -m pitangus import-sarif` en el
servidor; o desde CI, la entrada `import-sarif` de la Action, que envía los archivos a `/api/ci/sarif` con
`PITANGUS_IMPORT_TOKEN` ([cli.md](cli.md#importar-resultados-de-otras-herramientas-import-sarif)).

Los dos huecos por los que más preguntan:

- **Análisis profundo de flujo de datos.** Las reglas propias de Pitangus siguen los datos dentro de un archivo.
  CodeQL y Semgrep llegan más lejos. En GitHub Actions, conserva el SARIF de CodeQL en vez de subirlo (o además de
  subirlo) a code scanning, y envíalo a Pitangus:

  ```yaml
        - uses: github/codeql-action/init@v4      # fíjala al SHA del commit de la etiqueta, como las demás
          with:
            languages: javascript-typescript
        - uses: github/codeql-action/analyze@v4
          with:
            upload: never
            output: codeql
        - uses: Pitangus-Dev/pitangus@v0.14.0
          if: always()
          with:
            scan: false
            import-sarif: codeql/javascript.sarif   # un archivo por lenguaje en esa carpeta
            server: https://pitangus.example.com
            token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
  ```

  CodeQL es gratis en repositorios públicos y, con GitHub Advanced Security, en los privados; correr su CLI en otro
  sitio se rige por los términos de CodeQL de GitHub. El mismo paso con Semgrep está en
  [cli.md](cli.md#resultados-de-otras-herramientas).

  CodeQL escribe un SARIF por lenguaje, cada uno con su categoría (`runAutomationDetails.id`, `/language:python/`):
  una importación completa solo remedia lo que desapareció de la misma herramienta **y categoría**, así que importar
  el archivo de JavaScript nunca cierra los hallazgos de Python. Un SARIF sin categoría no se distingue de otro de la
  misma herramienta: dale una categoría a cada uno (la entrada `category` de CodeQL, `--sarif-category` en su CLI), o
  impórtalo con `scope=partial`, que abre y actualiza pero no remedia nada.
- **Pruebas dinámicas.** Para un dominio verificado, Pitangus ofrece siempre la [comprobación de exposición](analisis-web.md)
  (la raíz de cada host y rutas conocidas con httpx, testssl.sh y nuclei, sin rastreo). Su análisis web y de API
  pasivo completo, experimental, usa ZAP sobre un dominio verificado (recorrer y leer, o las operaciones GET y HEAD de una definición OpenAPI; nunca atacar)
  cuando el servidor define `PITANGUS_DAST_ENABLED=1`: a demanda o programados, sobre subdominios listados si el
  dominio tiene prueba DNS, con las cabeceras de petición guardadas para el dominio (claves de API, tokens bearer,
  cookies) e iniciando sesión con hasta 3 usuarios de prueba, junto con katana, nuclei (solo plantillas de detección),
  testssl.sh y httpx. El dominio se puede demostrar con un registro TXT, un archivo bajo `/.well-known/` o una etiqueta meta.
  Para algo más profundo (escaneos activos, plantillas de ataque, un pentest con IA como Strix),
  corre el escáner por tu cuenta, contra sistemas tuyos, e importa su SARIF sobre el dominio verificado: ver
  [Trae tu propio DAST](#trae-tu-propio-dast) más abajo.

### Trae tu propio DAST

El análisis web propio de Pitangus es pasivo y se lanza desde el panel ([Analizar un sitio web o una API](analisis-web.md)): guarda los hallazgos de ZAP exactamente como lo haría una importación del SARIF de ZAP, con las mismas huellas, así que ambos pueden alimentar el mismo dominio sin duplicados. Para escaneos activos, o para mantener el escáner en tu pipeline: si ya corre **OWASP ZAP** o **Nuclei**, su SARIF entra en el registro como cualquier otra importación, con un **dominio verificado** como activo: los hallazgos tienen el mismo triage, plazos, incidencias de Jira y avisos que los del código, y una importación completa posterior deja remediado lo que el escáner ya no reporte.

1. En **Dominios y APIs**, una persona administradora añade el dominio (`https://app.example.com`), publica el registro TXT que muestra el panel (`_pitangus.app.example.com` = `pitangus-verify=…`) y lo verifica. El dominio pasa a ser el activo `domain:app.example.com`. El registro se consulta de nuevo cada día; si desaparece, o pasan 90 días sin comprobarlo, el dominio deja de ser un activo hasta que alguien lo verifique otra vez.
2. El pipeline escribe el SARIF y lo envía con las entradas `import-sarif`, `server`, `token` y `asset` de la Action (o con `python -m pitangus import-sarif … --asset domain:app.example.com --server …`).

ZAP solo escribe SARIF con la plantilla `sarif-json` del add-on de informes, desde un job `report` del plan del [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/) ([job report](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/), [plantilla SARIF](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-sarif-json/)). Un plan pasivo (spider y análisis pasivo, sin ataques) desde GitHub Actions:

```yaml
name: Análisis dinámico
on:
  schedule: [{ cron: '0 3 * * 1' }]
  workflow_dispatch:

permissions: {}

jobs:
  zap:
    runs-on: ubuntu-latest
    steps:
      - name: ZAP, pasivo, con el Automation Framework
        run: |
          cat > zap.yaml <<'EOF'
          env:
            contexts:
              - name: app
                urls: ["https://app.example.com"]
                includePaths: ["https://app.example.com/.*"]
            parameters:
              failOnError: true
              progressToStdout: true
          jobs:
            - type: spider
              parameters:
                maxDuration: 2
            - type: passiveScan-wait
            - type: report
              parameters:
                template: sarif-json
                reportDir: /zap/wrk
                reportFile: zap
          EOF
          # ZAP corre con su propio usuario (zap); la carpeta debe aceptar su escritura
          chmod a+w .
          docker run --rm -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2 \
            zap.sh -cmd -autorun /zap/wrk/zap.yaml
          # la plantilla sarif-json escribe zap.json
      - uses: Pitangus-Dev/pitangus@v0.14.0
        if: always()
        with:
          scan: false
          import-sarif: zap.json
          asset: domain:app.example.com
          server: https://pitangus.example.com
          token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
```

Nuclei escribe SARIF con `-se` ([opciones](https://docs.projectdiscovery.io/tools/nuclei/running)). Mantén baja la tasa de peticiones, deja fuera las plantillas que hacen fuzzing o pueden tumbar el objetivo y fija la imagen:

```yaml
      - name: Nuclei
        run: |
          docker run --rm -v "$PWD:/out" projectdiscovery/nuclei:v3.3.5 \
            -u https://app.example.com -rl 20 -c 10 -severity low,medium,high,critical \
            -etags dos,fuzz,intrusive -se /out/nuclei.sarif
      - uses: Pitangus-Dev/pitangus@v0.14.0
        if: always()
        with:
          scan: false
          import-sarif: nuclei.sarif
          asset: domain:app.example.com
          server: https://pitangus.example.com
          token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
```

Qué hace Pitangus con ello: los hallazgos de un escáner web llevan `scanner: dast`; la ubicación es la URL sin query ni fragmento (un token de sesión o un *cache-buster* en la URL no debe convertir la misma alerta en un hallazgo nuevo en cada ejecución); la huella es regla, URL y nombre del parámetro, nunca la evidencia; y solo se guardan el método, el parámetro y una evidencia acotada, nunca la petición ni la respuesta que adjunta ZAP (llevan cookies y cabeceras de autorización). Nuclei pone la ruta de la plantilla donde SARIF espera un archivo y la URL en las propiedades del resultado; Pitangus lee la URL. Una ejecución con las dos herramientas está bien: cada una solo remedia lo que ella misma reportó.

**Strix** ([usestrix/strix](https://github.com/usestrix/strix), Apache-2.0: agentes de IA que intentan explotar lo que encuentran) escribe `findings.sarif` junto a sus otros informes. Impórtalo sobre el dominio verificado como cualquier otro SARIF (`import-sarif: strix_runs/<run>/findings.sarif`, `asset: domain:app.example.com`). Un hallazgo sobre un endpoint llega anclado a `SECURITY.md`; Pitangus lo ubica en la URL del endpoint (el objetivo de la ejecución más la ruta, `GET /api/users/{id}` → `https://app.example.com/api/users/{id}`, conservando el método), así que es un hallazgo web. Uno con ubicación en el código sigue siendo un hallazgo de código en su archivo y línea. Se respeta la etiqueta de severidad de Strix (su `info` no pasa a `low`), el CWE sale de su regla, la huella de sus huellas parciales (un título redactado de otra forma es el mismo hallazgo), y las áreas que anota como cubiertas o pendientes de revisar no son hallazgos. Las credenciales que repitan sus descripciones se redactan como en cualquier hallazgo web; el script de la prueba de concepto nunca viene en el SARIF.

**Solo contra sistemas tuyos o que estés autorizado a probar.** El registro TXT demuestra a Pitangus el control de la zona DNS; no es una autorización para probar nada, y Pitangus no comprueba que la tengas. El escaneo activo (el *active scan* de ZAP, el fuzzing `-dast` de Nuclei) puede dañar datos y disparar defensas: hazlo solo donde tengas permiso, fuera de producción salvo que sepas lo que haces, y deja el plan en pasivo en el resto de los casos. Sigue siendo un *análisis*, no un pentest.

## Jira Cloud

Pitangus convierte hallazgos en incidencias de Jira Cloud, sin duplicados entre análisis. Solo admite sitios de Jira
Cloud bajo `https://<sitio>.atlassian.net`.

### Conectar un sitio

Quien administra conecta Jira en **Integraciones → Gestión de incidencias** con el sitio, el correo de la cuenta y un
[token de API de Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens), y pulsa **Guardar y validar**:
Pitangus comprueba la cuenta antes de guardarla. El token queda cifrado en la bóveda y nunca vuelve al navegador: el
panel muestra el correo y los últimos cuatro caracteres del token.

Solo se aceptan sitios `https://<sitio>.atlassian.net` y no se siguen redirecciones, así que el panel no se puede usar
para enviar peticiones a otro lugar. Jira Server y Data Center quedan fuera a propósito: obligarían a aceptar hosts
arbitrarios de tu red.

### Destinos

Un destino dice a dónde van las incidencias: un proyecto y un tipo de incidencia, elegidos entre los que ofrece Jira, y
qué va en cada campo de su pantalla de creación. Cada campo recibe una variable de Pitangus (título, severidad,
prioridad de Jira, descripción, CWE, CVE, paquete, versión corregida, archivo, línea, repositorio, enlace al hallazgo,
primera detección, plazo de corrección, etiquetas), un valor fijo entre los que Jira permite o una plantilla con
`{{variables}}` (sustitución simple, no se evalúa nada). Pitangus valida la asignación contra Jira al guardarla: todos
los campos obligatorios asignados, tipos que encajan y valores permitidos. El resumen y la descripción vienen asignados
por defecto, y también el plazo cuando la pantalla lo tiene.

Un destino también fija el idioma de sus incidencias y comentarios (el `PITANGUS_DEFAULT_LOCALE` del servidor, salvo que
elijas inglés o español) y qué pasa cuando un análisis verifica una incidencia como corregida: ver más abajo.

### Reglas de enrutamiento

Las reglas de enrutamiento eligen el destino por repositorio: repositorios concretos o patrones sobre el nombre
(`org/payments-*`), en orden. **Gana la primera regla activa que coincide**, y una última regla por defecto cubre el
resto (se puede desactivar).

- Una regla **manual** crea incidencias solo cuando alguien lo pide, desde **Hallazgos**.
- Una regla **automática** las crea sola: cuando un análisis completo, una importación SARIF o la revisión diaria de
  avisos encuentra hallazgos nuevos con al menos su severidad mínima, sus incidencias se encolan y las crea el worker,
  con reintentos si Jira no responde. Las revisiones de pull requests no crean incidencias, ni los hallazgos descartados
  en el triage o en rutas excluidas.
- Una regla automática con **relleno** (backfill) también crea, de forma espaciada, las incidencias de los hallazgos que
  ya estaban abiertos al guardarla o activarla.

El formulario de la regla muestra qué crearía antes de guardarla: cuántas incidencias, para cuántos hallazgos abiertos,
y cómo se verá en Jira la más grave (su título y sus primeras líneas). Cuando el relleno termina, la regla muestra cuántas
incidencias se crearon, enlaza las primeras y, si alguna falló, por qué, agrupado por motivo.

### Cuando se verifica la corrección

Cuando un análisis completo o una importación completa verifica como remediado un hallazgo enlazado, Pitangus **comenta
en la incidencia** y le añade la etiqueta del destino (`pitangus-fixed`, salvo que la cambies o la dejes vacía), así
encuentras las corregidas con una sola búsqueda (`labels = pitangus-fixed`). Cada equipo cierra sus incidencias a su manera, con sus
propios flujos, así que **por defecto Pitangus no mueve ni cierra incidencias**: un administrador puede elegir, por
destino, un estado del flujo de trabajo de ese tipo de incidencia al que moverlas. Si una incidencia no puede pasar a
ese estado desde su estado actual, no se fuerza nada y el comentario lo dice.

Una incidencia que cubre varios hallazgos recibe todo esto cuando todos están remediados. Si alguno reaparece o alguien lo
reabre en Pitangus, Pitangus comenta y quita la etiqueta; nunca devuelve la incidencia a otro estado. Las decisiones de triage (remediado a
mano, falso positivo, riesgo aceptado, reabierto) también se comentan.

### Crear incidencias desde Hallazgos

En la tabla de hallazgos, selecciona hallazgos y pulsa **Crear en Jira** (hasta 50 a la vez; lo descartado en el triage
no se exporta). Cada uno va al destino que eligen las reglas de su repositorio. Pitangus crea **una incidencia por
tarea de corrección**: los avisos del mismo paquete van juntos, con la versión que los corrige todos, mientras que los
hallazgos de código y de secretos van de a uno.

El título de la incidencia dice qué hacer y dónde, por ejemplo `Alta · starlette 0.37.2 → 1.3.1 · org/api (poetry.lock)`,
y su descripción empieza por lo que un desarrollador necesita para actuar: el cambio, el archivo, el comando y cuándo
queda corregido; después, por qué importa (severidad, plazo, KEV y EPSS cuando aplican) y, al final, los detalles y las
referencias.

Cada incidencia lleva la etiqueta `appsec-<huella>` de cada hallazgo que cubre. Antes de crear, Pitangus busca por esas
etiquetas, y el enlace se recuerda por repositorio y huella, así que exportar otra vez, hoy o después del siguiente
análisis, enlaza la incidencia existente en lugar de duplicarla. Si el proyecto no permite fijar la prioridad al crear,
Pitangus reintenta sin ella. Las incidencias se escriben en el idioma de su destino, porque las lee todo el equipo.

## Slack, Teams y webhooks

En **Integraciones → Avisos**, una persona administradora puede añadir:

- webhooks entrantes de Slack;
- webhooks de Workflows de Microsoft Teams;
- un webhook HTTPS genérico.

Cada canal elige sus eventos (hallazgos nuevos desde una severidad mínima, lotes terminados). Pitangus envía un mensaje
por análisis, agrupado: los cinco hallazgos más graves, el total y un enlace al panel si `PITANGUS_PUBLIC_URL` está
definida. Los mensajes salen desde una outbox de PostgreSQL con reintentos, por lo que un reinicio no descarta los
pendientes. Las peticiones del webhook genérico llevan una firma HMAC-SHA256 en `X-Pitangus-Signature`; el secreto para
verificarla solo se muestra al crear el canal. Las revisiones de pull requests no avisan aquí: ya comentan en el PR.

Los destinos de red privada se bloquean por defecto para reducir el riesgo de SSRF. `PITANGUS_ALLOW_PRIVATE_WEBHOOKS=1`
los habilita de forma explícita.

## Automatización periódica

Con `PITANGUS_PERIODIC=leader` (el valor predeterminado), un worker elegido mediante PostgreSQL ejecuta las tareas vencidas. Entre ellas están la vigilancia de pull requests y de la rama principal, la actualización de datos de avisos, la revisión de dependencias y la entrega de las outboxes de notificaciones y Jira.

Las plataformas con su propio programador pueden usar `PITANGUS_PERIODIC=external`. En ese caso, una sola tarea ejecuta `pitangus periodic` o llama a `GET /api/cron` con `PITANGUS_CRON_TOKEN` (o `CRON_SECRET` en Vercel). No ejecutes los dos modos: la ruta de cron no está disponible si no configuraste el modo externo y un token válido. Consulta [Tareas periódicas](despliegue.md#tareas-periódicas) y la referencia generada de la API de automatización en el sitio.

## Asistencia con IA

Hoy la IA **no participa** en ningún análisis, y no hay ninguna clave que guardar en el panel. La asistencia con IA
(una explicación de cada hallazgo y una propuesta de parche, con tu propia clave de OpenAI o Anthropic) está en
desarrollo; cuando llegue, pedirá consentimiento en cada ejecución antes de enviar nada, con un presupuesto por
ejecución y redacción de secretos, y nunca enviará código fuente sin ese consentimiento. Si una versión anterior guardó
una clave, la sección **Asistencia con IA** la lista para que quien administra pueda retirarla.

Quien opera el servidor ya puede declarar `OPENAI_API_KEY` o `ANTHROPIC_API_KEY`. Nada las usa; estos comandos listan
qué claves existen y comprueban una contra el catálogo de modelos del proveedor, sin enviar código ni hallazgos y sin
gastar tokens:

```bash
make cli ARGS="providers"
make cli ARGS="ai-check --provider openai"
```

## Lista de seguridad

1. Da a las credenciales de GitHub y de registros solo los repositorios y permisos de lectura que necesitan.
2. Guarda los tokens de CI, métricas y cron en el almacén de secretos de la plataforma; nunca dentro del workflow.
3. Usa HTTPS para cada instancia de Pitangus y webhook accesible desde fuera.
4. Mantén desactivado el acceso a webhooks y registros privados salvo que hayas diseñado para ello el límite de red del worker.
5. Prueba los destinos de notificaciones y Jira desde el panel antes de activar el enrutamiento automático.

Consulta [Seguridad](seguridad.md) para saber qué sale de la máquina, cómo se guardan las credenciales y cuáles son las concesiones conocidas.

## Siguientes pasos

- [Conectar GitHub](github-app.md): crear e instalar la GitHub App.
- [Terminal y CI](cli.md): `scan` y la GitHub Action.
- [Hallazgos](hallazgos.md): triage, plazos y exportaciones, Jira incluido.
- [Analizar un sitio web o una API](analisis-web.md): el análisis web pasivo y la verificación del dominio.
- [Qué cubre Pitangus](vista-general.md#qué-cubre-pitangus-y-qué-no), y lo que importa en su lugar.
