[English](../faq.md) · Español

# Preguntas frecuentes sobre Pitangus

Respuestas cortas y honestas a lo que la gente pregunta antes y después de instalar Pitangus. Los términos se definen
en el [glosario](glosario.md).

## ¿Pitangus es un pentest?

No. Pitangus hace análisis: lee código, dependencias, configuración e imágenes sin ejecutarlos, y lee las respuestas de
un sitio web sin atacarlo. Un pentest intenta explotar fallos en un sistema en marcha y demuestra el impacto. Un informe
de Pitangus no reemplaza el pentest que pueden exigir SOC 2 o ISO 27001. Puedes correr por tu cuenta una herramienta de
pentest e [importar sus resultados](integraciones.md#trae-tu-propio-dast). Ver [Conceptos clave](conceptos.md).

## ¿Mi código sale de mi servidor?

No. Pitangus corre en tu máquina o en tu servidor, y los motores leen ahí una copia de solo lectura de tu código. El
código se descarga de GitHub (a través de tu propia GitHub App); no se sube a ningún sitio. Las bases de avisos se
descargan y se consultan en local. La única excepción opcional para dependencias es la consulta en línea a OSV, que
envía nombres y versiones de paquetes (nunca código) a `api.osv.dev`, y solo si la marcas en un análisis. No hay
telemetría.

## ¿Qué se envía exactamente y a dónde?

La lista completa, destino por destino, está en [Qué sale de tu máquina](seguridad.md#qué-sale-de-tu-máquina). En
resumen: peticiones a GitHub por tus repositorios, descargas de fuentes públicas de avisos (NVD, CISA KEV, EPSS, las
bases de Trivy y OSV), los registros de imágenes cuando analizas una imagen, tu sitio de Jira y tus canales de avisos si
los conectas y, en los análisis web, peticiones a los dominios que verificaste.

## ¿Cuánto cuesta y con qué licencia?

Pitangus es software libre bajo la GNU Affero General Public License v3.0 ([`LICENSE`](../../LICENSE), AGPL-3.0-only).
No hay precio por desarrollador ni por análisis. Puedes usarlo, estudiarlo, modificarlo y redistribuirlo; si ofreces una
versión modificada a otras personas a través de una red, tienes que darles el código fuente de esa versión con la misma
licencia. Las reglas SAST de `rules/` son MIT, así que puedes reutilizarlas en otras herramientas. Solo pagas la máquina
donde corre.

## ¿Puede atacar mi sitio web?

No. Los análisis web son pasivos: peticiones `GET` y `HEAD` normales, un navegador que sigue enlaces, saludos TLS. Sin
inyecciones, sin fuzzing, sin enviar formularios salvo el inicio de sesión de un usuario de prueba, sin POST, PUT ni
DELETE. La comprobación de exposición solo pide la raíz de cada host y rutas conocidas; el análisis completo, que
rastrea, es experimental y está apagado salvo que el servidor defina `PITANGUS_DAST_ENABLED=1`. Solo quien administra
puede lanzarlos o programarlos, y solo contra un dominio cuyo control se demostró. Un análisis pasivo hace peticiones reales, así que
lánzalo solo contra sitios que tengas permiso de probar. Ver [Analizar un sitio web o una API](analisis-web.md).

## Pocos hallazgos: ¿significa que estoy seguro?

No. Un resultado limpio no demuestra que no haya vulnerabilidades. Cada motor solo ve lo que está hecho para ver (las
reglas de código de Pitangus no siguen los datos entre archivos, los análisis web no atacan), y cada ejecución te dice
lo que no revisó: pasos **No probado**, **Parcial** u **Omitido**, y sus limitaciones. Cuando una herramienta no corrió
o no llegó a un host, Pitangus no da esa parte por limpia ni marca remediados los hallazgos anteriores. Ver
[Conceptos clave](conceptos.md).

## ¿Funciona con GitLab, Bitbucket o Azure DevOps?

Todavía no como proveedor conectado: aparecen **En desarrollo**. Hoy puedes analizar esos repositorios en sus propios
pipelines con [`scan`](cli.md), que no necesita un servidor de Pitangus, o enviar los resultados como SARIF a un
Pitangus en marcha.

## ¿Usa IA?

No. Hoy la IA no participa en ningún análisis y no hay ninguna clave que guardar. La asistencia con IA (explicaciones y
propuestas de parche con tu propia clave de OpenAI o Anthropic, con consentimiento en cada ejecución) está en
desarrollo. Ver [Integraciones y automatización](integraciones.md#asistencia-con-ia).

## ¿Cuántos workers necesito?

Un worker corre un análisis a la vez y necesita unos 4 GB de memoria y 2 CPU. Con uno basta para empezar. Si los
análisis esperan en la cola (un lote de una organización, muchos pull requests), añade workers en la misma máquina
(`docker compose up -d --scale worker=3`) o en otras. Ver [Escalar](escalar.md).

## ¿Puedo traer resultados de otras herramientas?

Sí, como SARIF 2.1.0: CodeQL, Semgrep, Snyk, Trivy, ZAP, Nuclei, Strix y otras. Impórtalo desde **Nuevo análisis →
Importar SARIF**, con `pitangus import-sarif` en el servidor o desde CI con la GitHub Action. Los hallazgos importados
tienen el mismo triage, plazos, incidencias de Jira y avisos que los propios, y una importación completa posterior de la
misma herramienta remedia lo que ya no reporta. Ver
[Integraciones y automatización](integraciones.md#traer-resultados-de-otros-analizadores).

## ¿Necesita acceso a internet?

Necesita acceso de salida: para descargar las imágenes la primera vez, las bases y fuentes de avisos, para llegar a
GitHub y, en los análisis web, a los dominios que analizas. No necesita acceso de entrada: no hay webhooks, y los pull
requests se vigilan consultando GitHub. El panel escucha en `127.0.0.1` por defecto; para abrirlo a tu red o a
internet, ponlo detrás de HTTPS ([Instalación](instalacion.md)).

## ¿Necesita Docker?

Sí. Pitangus y sus motores corren como contenedores: Docker Engine 24 o posterior con Compose v2.24 o posterior, más
`make` y `git`. `make doctor` lo comprueba todo. Ver [Instalación](instalacion.md).

## ¿Está listo para producción?

Está en beta (v0.15). Funciona y tiene pruebas, pero la API y los formatos de datos todavía pueden cambiar entre
versiones. Cada versión dice qué hacer antes de actualizar. Haz copias de seguridad (`make backup`) y lee la
[guía para actualizar](actualizar.md) antes de cada actualización.

## ¿Cómo actualizo?

Cambia a la versión nueva y ejecuta `make update`: hace una copia de seguridad, descarga las imágenes y reinicia; las
migraciones corren solas. Ver [Actualizar Pitangus](actualizar.md).

## ¿En qué idiomas habla?

Inglés y español, en todo: el panel, los hallazgos, las guías de corrección, los informes, los comentarios en PRs y los
avisos. El panel sigue a tu navegador; lo que nadie pide en persona (comentarios en PRs, avisos, Jira, la CLI) usa
`PITANGUS_DEFAULT_LOCALE`. Ver [Vista general](vista-general.md#idiomas).

## ¿Quién puede ver y cambiar qué?

Todas las personas con sesión ven los hallazgos. Los **miembros** lanzan análisis y hacen triage; los
**administradores** además conectan proveedores, gestionan usuarios, aceptan riesgos, añaden y verifican dominios y
lanzan análisis web. Ver [Conceptos clave](conceptos.md#roles-administrador-y-miembro).

## Algo no funciona. ¿Por dónde empiezo?

Ejecuta `make doctor` y mira [Solución de problemas](solucion-problemas.md). Para reportar una vulnerabilidad del
propio Pitangus, sigue [SECURITY.md](../../.github/SECURITY.md).
