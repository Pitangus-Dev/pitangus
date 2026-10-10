[English](../integrations.md) · Español

# Integraciones y automatización

Pitangus puede conectarse con GitHub y Jira, recibir SARIF desde CI, enviar avisos agrupados y ejecutar tareas periódicas sin convertir el panel en una API pública. Las integraciones son opcionales y las configura una persona administradora. Los tokens y las URL de webhooks quedan cifrados en PostgreSQL mediante la bóveda; los valores secretos nunca vuelven al navegador.

## Repositorios y pull requests de GitHub

La conexión compatible para repositorios es una **GitHub App**. Necesita cuatro permisos: Contents (lectura), Metadata (lectura), Pull requests (lectura y escritura) y Commit statuses (lectura y escritura). Pitangus usa tokens de instalación de una hora en memoria y no necesita webhooks ni OAuth. Sigue el proceso completo en [Conectar GitHub](github-app.md).

En cada repositorio, una persona administradora puede activar la vigilancia de pull requests, decidir si Pitangus comenta y publica un estado del commit, elegir la severidad que bloquea y, si hace falta, volver a analizar la rama principal cuando cambia. Pitangus consulta GitHub cada `PITANGUS_PR_POLL_SECONDS` en lugar de exponer un webhook entrante. [Revisión de pull requests](funcionalidades.md#revision-de-pull-requests) explica el comportamiento exacto.

Las conexiones con GitLab, Bitbucket y Azure DevOps aparecen como **En desarrollo** y todavía no funcionan. Aun así, puedes analizar repositorios de esos proveedores desde sus pipelines con la CLI.

## CI y SARIF

El repositorio incluye una [GitHub Action](../../action.yml) compuesta y oficial, además del comando `pitangus scan` para CI. Analizan la carpeta descargada, pueden comparar un cambio con una rama base, generan SARIF y devuelven códigos de salida documentados. No necesitan un servidor Pitangus en ejecución. [Terminal y CI](cli.md) contiene las entradas, salidas, códigos y ejemplos derivados de `action.yml` y del parser de la CLI.

Para sumar al registro de Pitangus los hallazgos de otro motor, importa SARIF 2.1.0 desde el panel. Un pipeline puede enviar SARIF a una instancia mediante `POST /api/ci/sarif` con `PITANGUS_IMPORT_TOKEN`; usa HTTPS y guarda el token en el almacén de secretos de CI. El sitio genera la [referencia de la API de automatización](../../docs-site/README.es.md#referencia-de-api-generada) desde OpenAPI.

### Traer resultados de otros analizadores

Pitangus no corre todos los motores que existen, y lo dice en
[funcionalidades.md](funcionalidades.md#qué-cubre-pitangus-y-qué-no). Lo que no corre, lo importa: cualquier
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
        - uses: Pitangus-Dev/pitangus@v0.12.2
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
- **Pruebas dinámicas.** Pitangus nunca ejecuta ni ataca tus aplicaciones. Hasta que lo ofrezca, corre ZAP o Nuclei
  por tu cuenta, contra sistemas tuyos, e importa su SARIF sobre un dominio verificado: ver
  [Trae tu propio DAST](#trae-tu-propio-dast) más abajo.

### Trae tu propio DAST

Pitangus todavía no ejecuta escáneres web (está en [en desarrollo](funcionalidades.md#en-desarrollo)). Si tu pipeline ya corre **OWASP ZAP** o **Nuclei**, su SARIF entra en el registro como cualquier otra importación, con un **dominio verificado** como activo: los hallazgos tienen el mismo triage, plazos, incidencias de Jira y avisos que los del código, y una importación completa posterior deja remediado lo que el escáner ya no reporte.

1. En **Análisis → Dominios**, una persona administradora añade el dominio (`https://app.example.com`), publica el registro TXT que muestra el panel (`_pitangus.app.example.com` = `pitangus-verify=…`) y lo verifica. El dominio pasa a ser el activo `domain:app.example.com`. El registro se consulta de nuevo cada día; si desaparece, o pasan 90 días sin comprobarlo, el dominio deja de ser un activo hasta que alguien lo verifique otra vez.
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
      - uses: Pitangus-Dev/pitangus@v0.12.2
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
      - uses: Pitangus-Dev/pitangus@v0.12.2
        if: always()
        with:
          scan: false
          import-sarif: nuclei.sarif
          asset: domain:app.example.com
          server: https://pitangus.example.com
          token: ${{ secrets.PITANGUS_IMPORT_TOKEN }}
```

Qué hace Pitangus con ello: los hallazgos de un escáner web llevan `scanner: dast`; la ubicación es la URL sin query ni fragmento (un token de sesión o un *cache-buster* en la URL no debe convertir la misma alerta en un hallazgo nuevo en cada ejecución); la huella es regla, URL y nombre del parámetro, nunca la evidencia; y solo se guardan el método, el parámetro y una evidencia acotada, nunca la petición ni la respuesta que adjunta ZAP (llevan cookies y cabeceras de autorización). Nuclei pone la ruta de la plantilla donde SARIF espera un archivo y la URL en las propiedades del resultado; Pitangus lee la URL. Una ejecución con las dos herramientas está bien: cada una solo remedia lo que ella misma reportó.

**Solo contra sistemas tuyos o que estés autorizado a probar.** El registro TXT demuestra a Pitangus el control de la zona DNS; no es una autorización para probar nada, y Pitangus no comprueba que la tengas. El escaneo activo (el *active scan* de ZAP, el fuzzing `-dast` de Nuclei) puede dañar datos y disparar defensas: hazlo solo donde tengas permiso, fuera de producción salvo que sepas lo que haces, y deja el plan en pasivo en el resto de los casos. Sigue siendo un *análisis*, no un pentest.

## Jira Cloud

Pitangus admite sitios de Jira Cloud bajo `https://<sitio>.atlassian.net`. Una persona administradora conecta el sitio, el correo y un token de API de Atlassian; después asigna variables de Pitangus a los campos que Jira ofrece para un proyecto y tipo de incidencia.

Las reglas de enrutamiento eligen el destino por repositorio. Una regla puede ser manual o automática, fijar una severidad mínima y procesar los hallazgos abiertos que ya existían. Las reglas automáticas se ejecutan después de un análisis completo, una importación SARIF y la revisión diaria de avisos; las revisiones de pull requests no crean incidencias. Pitangus evita duplicados con etiquetas derivadas de la huella de cada hallazgo y comenta cuando todos los hallazgos enlazados quedan verificados como corregidos. Nunca cierra la incidencia por su cuenta. Consulta [Funcionalidades → Jira](funcionalidades.md#jira) para conocer todos los límites.

## Slack, Teams y webhooks

En **Integraciones → Notificaciones**, una persona administradora puede añadir:

- webhooks entrantes de Slack;
- webhooks de Workflows de Microsoft Teams;
- un webhook HTTPS genérico.

Cada canal elige eventos de hallazgos nuevos y lotes terminados, además de su severidad mínima. Los avisos se agrupan por análisis y salen desde una outbox de PostgreSQL con reintentos, por lo que un reinicio no descarta los mensajes pendientes. Las peticiones del webhook genérico llevan una firma HMAC-SHA256 en `X-Pitangus-Signature`; el secreto para verificarla solo se muestra al crear el canal.

Los destinos de red privada se bloquean por defecto para reducir el riesgo de SSRF. `PITANGUS_ALLOW_PRIVATE_WEBHOOKS=1` los habilita de forma explícita. Configura `PITANGUS_PUBLIC_URL` si los mensajes deben enlazar al panel.

## Automatización periódica

Con `PITANGUS_PERIODIC=leader` (el valor predeterminado), un worker elegido mediante PostgreSQL ejecuta las tareas vencidas. Entre ellas están la vigilancia de pull requests y de la rama principal, la actualización de datos de avisos, la revisión de dependencias y la entrega de las outboxes de notificaciones y Jira.

Las plataformas con su propio programador pueden usar `PITANGUS_PERIODIC=external`. En ese caso, una sola tarea ejecuta `pitangus periodic` o llama a `GET /api/cron` con `PITANGUS_CRON_TOKEN` (o `CRON_SECRET` en Vercel). No ejecutes los dos modos: la ruta de cron no está disponible si no configuraste el modo externo y un token válido. Consulta [Tareas periódicas](despliegue.md#tareas-periodicas) y la referencia generada de la API de automatización en el sitio.

## Claves de proveedores de IA

El panel puede validar y guardar claves de OpenAI y Anthropic, pero el análisis con IA no está implementado. Pitangus no envía código ni hallazgos a esos proveedores. Las claves solo preparan la integración y no deben presentarse como una capacidad activa de análisis.

## Lista de seguridad

1. Da a las credenciales de GitHub y de registros solo los repositorios y permisos de lectura que necesitan.
2. Guarda los tokens de CI, métricas y cron en el almacén de secretos de la plataforma; nunca dentro del workflow.
3. Usa HTTPS para cada instancia de Pitangus y webhook accesible desde fuera.
4. Mantén desactivado el acceso a webhooks y registros privados salvo que hayas diseñado para ello el límite de red del worker.
5. Prueba los destinos de notificaciones y Jira desde el panel antes de activar el enrutamiento automático.

Consulta [Seguridad](seguridad.md) para saber qué sale de la máquina, cómo se guardan las credenciales y cuáles son las concesiones conocidas.
