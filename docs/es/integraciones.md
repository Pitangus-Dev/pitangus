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
  por tu cuenta, contra sistemas tuyos, e importa su SARIF de la misma forma (ZAP lo escribe con la plantilla
  `sarif-json` de su add-on de informes; Nuclei, con `-se`).

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
