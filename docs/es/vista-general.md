[English](../overview.md) · Español

# Qué es Pitangus: seguridad de aplicaciones autoalojada

Pitangus es una herramienta de seguridad de aplicaciones que instalas tú. Analiza tu código fuente, sus dependencias,
tus imágenes de contenedor y, de forma pasiva, tus sitios web y APIs; guarda cada hallazgo en un solo registro y te
dice cuándo una corrección llegó de verdad. Está pensada para equipos pequeños y para quienes cuidan su seguridad: la
instalas en tu máquina o en tu servidor, y tu código nunca sale de ahí.

¿Primera vez con este vocabulario? Un **hallazgo** es un posible problema que reportó una herramienta (un paquete
vulnerable, un secreto filtrado, una cabecera de seguridad que falta). El [glosario](glosario.md) define cada término
que usan estas páginas.

## Cómo funciona

Cada análisis de un repositorio, una imagen de contenedor o un dominio verificado sigue el mismo camino, desde lo que
conectas hasta la evidencia que entregas.

1. **Motores en contenedores.** Pitangus no escribe sus propios escáneres. Ejecuta motores de código abierto
   consolidados, cada uno fijado a una versión y a un digest de imagen, en un contenedor endurecido y sin privilegios:
   Opengrep, Betterleaks, Trivy, OSV-Scanner y zizmor para código e imágenes por defecto, con Checkov y Grype como
   motores opcionales; httpx, testssl.sh y nuclei para la comprobación de exposición de un dominio, y ZAP y katana para
   el análisis web completo, experimental.
2. **Ejecuciones.** Cada análisis es una **ejecución**: el registro de qué se analizó, qué pasos corrieron, cuáles no y
   por qué. Un paso que no corrió aparece como *no probado*, nunca como limpio.
3. **Registro de hallazgos.** Cada hallazgo tiene una **huella** estable, así que el mismo problema se reconoce de una
   ejecución a otra. Lo que un análisis completo posterior ya no reporta queda remediado solo; lo que vuelve se
   reabre.
4. **Triage y verificación.** Tú decides qué es cada hallazgo (en curso, falso positivo, riesgo aceptado), y
   **Reverificar** vuelve a analizar para decirte si la corrección llegó.
5. **Evidencia.** Informes (PDF, Markdown, SARIF, JSON), un SBOM y declaraciones VEX, listos para una auditoría o un
   cliente.

[Conceptos clave](conceptos.md) explica cada una de estas piezas con más detalle.

## Qué cubre Pitangus y qué no

Pitangus ejecuta motores de código abierto consolidados, fijados por digest, y añade lo que ninguno tiene por sí solo:
un registro con triage, plazos, evidencia, revisión de pull requests y prueba de que una corrección es real. Ahí
también termina. Frente a una suite comercial (Snyk, Checkmarx, Veracode…), así queda:

| Área | Qué corre | Dónde se queda corto |
| --- | --- | --- |
| Dependencias (SCA) | Trivy y OSV-Scanner sobre NVD, GHSA y OSV, con KEV y EPSS; los paquetes maliciosos conocidos (`MAL-*` de OpenSSF, tipificados como malware, o con CWE, título y descripción de acuerdo) como hallazgo propio | Sin análisis de alcanzabilidad: una función vulnerable se reporta la llame tu código o no. |
| Secretos | Betterleaks y Trivy, con tus propios detectores, listas de permitidos y reglas integradas desactivadas por repositorio. Los archivos de credenciales (`.env*`, `.npmrc`, claves SSH…) solo los leen ellos, en una copia que se borra después | Solo los archivos del commit analizado: un secreto borrado en un commit anterior pero que sigue en el historial de Git no se ve. Si un secreto sigue funcionando solo se comprueba con `PITANGUS_SECRET_VALIDATION` (apagado por defecto: envía el secreto a su proveedor); si no, cada uno es crítico hasta rotarlo. |
| Imágenes de contenedor | Trivy sobre las capas, el historial y la configuración, leídos del registro; Grype como segunda opinión si se activa (`PITANGUS_GRYPE_ENABLED`) | La imagen nunca se ejecuta, así que no se revisa nada de su comportamiento en ejecución. |
| Infraestructura y pipelines | Trivy (Terraform, Kubernetes, Dockerfiles…) y zizmor (GitHub Actions); Checkov añade más comprobaciones y otros sistemas de CI si se activa (`PITANGUS_CHECKOV_ENABLED`) | Un motor apagado aparece como no ejecutado, nunca como limpio. La edición gratuita de Checkov no da severidad; Pitangus asigna una por regla. |
| Tu propio código (SAST) | Opengrep con las 66 reglas de Pitangus de `rules/` (14 con seguimiento de datos dentro de un archivo), incluidas las de lo que el código escrito con IA suele hacer mal; un lector de migraciones de Supabase y reglas de Firebase; opcionalmente 259 reglas de GitLab (`PITANGUS_THIRD_PARTY_RULES`) | **Es la capa más delgada.** Sin flujo de datos entre archivos y sin conocimiento de frameworks más allá de esas reglas. Para un análisis profundo, corre CodeQL o Semgrep y [trae sus resultados](integraciones.md#traer-resultados-de-otros-escáneres): tienen el mismo ciclo de vida. |
| Sitios web y APIs (DAST) | La **comprobación de exposición** de un dominio verificado, siempre disponible: la raíz de cada host y rutas conocidas con httpx, testssl.sh y nuclei, sin rastreo. El **análisis completo** es experimental: ZAP (spider, spider AJAX y reglas pasivas, o las operaciones GET y HEAD de una definición OpenAPI), más katana, nuclei (solo plantillas de detección), testssl.sh y httpx. Cabeceras guardadas opcionales y hasta 3 usuarios de prueba por análisis; a demanda o programado. Apagado salvo que el servidor defina `PITANGUS_DAST_ENABLED=1`; apagarlo no remedia nada de lo que encontró. Ver [Analizar un sitio web o una API](analisis-web.md). | **Solo pasivo:** sin inyecciones ni otros ataques, sin enviar formularios salvo el inicio de sesión de un usuario de prueba, sin POST, PUT ni DELETE. Los recorridos tienen tiempo limitado, así que un sitio grande no se cubre entero. Solo ZAP inicia sesión como usuario de prueba; si las cabeceras guardadas siguen iniciando sesión solo se comprueba si el dominio tiene página de comprobación de sesión. Un análisis web a la vez por instalación. Para pruebas activas, corre tu propio escáner e [importa sus resultados](integraciones.md#trae-tu-propio-dast). |
| Escala | Un análisis por worker; tantos workers como necesites, en una máquina o en varias | Sin análisis en paralelo dentro de un worker, sin manifiestos de autoescalado, sin una medición publicada. Ver [Escalar](escalar.md). |

Lo que una suite comercial no puede ofrecer es la otra mitad de la tabla: corre en tu servidor, el código no sale de
él, no hay precio por desarrollador y el código fuente es abierto (AGPL-3.0).

> [!NOTE]
> Un resultado limpio no demuestra que no haya vulnerabilidades. Pitangus dice lo que no revisó (*no probado*,
> *cobertura parcial*) para que pocos hallazgos nunca se lean como «seguro».

## En desarrollo

Aparecen en gris en el panel, marcadas **En desarrollo**. Hoy no producen resultados ni se pueden usar:

| Funcionalidad | Qué hará |
| --- | --- |
| Análisis web activos | Pruebas activas solo con la autorización de quien administra, registrada en la ejecución. Los análisis web y de API pasivos ya funcionan. |
| GitLab, Bitbucket, Azure DevOps | Conectar repositorios con tokens de proyecto de solo lectura. Hoy, analízalos en sus propios pipelines con [`scan`](cli.md). |
| Asistencia con IA | Explicaciones de hallazgos y propuestas de parche con tu propia clave, con consentimiento en cada ejecución. Hoy la IA no participa en ningún análisis. |
| API pública | Tokens personales con alcance y una `/api/v1` documentada. |

## Un recorrido corto por el panel

La barra lateral tiene tres grupos: **Riesgo** (Resumen, Hallazgos, Amenazas, Cobertura, CVE tracker, Cumplimiento),
**Escaneo** (Análisis, Repositorios, Imágenes, Dominios y APIs, Pull requests) y **Ajustes** (Políticas, Integraciones
y, para administradores, Usuarios). La cabecera siempre tiene **Nuevo análisis**.

### Resumen

**Resumen** (`#/overview`) resume el riesgo de todo lo que has analizado: hallazgos abiertos por severidad,
vulnerabilidades con explotación activa (KEV), lo que está fuera de plazo, encontrados frente a remediados en el tiempo
y los CVE más recientes. Cada cifra se calcula a partir de las ejecuciones, con su definición a la vista. En una
instalación nueva empieza con **Primeros pasos**, una lista que se tacha sola.

<!-- screenshot: overview | El Resumen con las cifras clave, los hallazgos por severidad y el gráfico de encontrados frente a remediados -->

### Hallazgos

**Hallazgos** (`#/findings`) es el registro: el estado actual de cada hallazgo de un activo, de una organización o de
varios a la vez, con filtros, triage, plazos, guías de corrección y exportaciones. Ver
[Hallazgos](hallazgos.md).

### Análisis

**Análisis** (`#/analyses`) lista cada ejecución con su tipo, estado y resultados. Abre una para ver sus pasos
(completado, parcial, omitido, no probado) y sus limitaciones.

### Dominios y APIs

**Dominios y APIs** (`#/domains`) reúne los sitios y APIs que controlas. Quien administra añade un dominio, demuestra
una vez que lo controla y desde ahí puede analizarlo de forma pasiva. Cada dominio tiene las pestañas **Resumen**,
**Hallazgos**, **Análisis**, **Alcance** y **Usuarios de prueba**. Ver [Analizar un sitio web o una API](analisis-web.md).

### Integraciones

**Integraciones** (`#/integrations`) es una página por secciones: **Proveedores de código** (la GitHub App),
**Registros de contenedores**, **Avisos** (Slack, Teams, webhooks; solo administradores), **Gestión de incidencias**
(Jira Cloud) y **Asistencia con IA** (próximamente). Ver [Integraciones y automatización](integraciones.md).

<!-- screenshot: integrations | La página de Integraciones con sus secciones: proveedores de código, registros de contenedores, avisos, gestión de incidencias y asistencia con IA -->

## Paleta de comandos y atajos de teclado

Pulsa `⌘K` en macOS o `Ctrl+K` en otros sistemas (o haz clic en **Buscar…** en la cabecera) para abrir la paleta.
Busca páginas, análisis, repositorios, imágenes y dominios, y ejecuta acciones: **Nuevo análisis**, **Importar
resultados SARIF**, **Añadir un dominio** (administradores), **Conectar un proveedor de código** y **Atajos de
teclado**.

<!-- screenshot: command-palette | La paleta de comandos abierta, con acciones, páginas y análisis recientes -->

Los atajos de una tecla funcionan en todo el panel, salvo mientras escribes en un campo o hay un diálogo abierto:

| Teclas | Hace |
| --- | --- |
| `⌘K` / `Ctrl+K` | Abrir o cerrar la paleta |
| `N` | Nuevo análisis |
| `?` | Ver los atajos |
| `G` y luego `O` | Resumen |
| `G` y luego `F` | Hallazgos |
| `G` y luego `T` | Amenazas |
| `G` y luego `V` | Cobertura |
| `G` y luego `C` | CVE tracker |
| `G` y luego `M` | Cumplimiento |
| `G` y luego `A` | Análisis |
| `G` y luego `R` | Repositorios |
| `G` y luego `I` | Imágenes |
| `G` y luego `D` | Dominios y APIs |
| `G` y luego `P` | Pull requests |
| `G` y luego `L` | Políticas |
| `G` y luego `E` | Integraciones |
| `G` y luego `U` | Usuarios (administradores) |

Las letras son las mismas en todos los idiomas.

## Idiomas

Todo lo que lee una persona existe en inglés y en español: el panel, los hallazgos, las guías de corrección, los
informes, los comentarios en PRs y los avisos. El panel sigue el idioma de tu navegador, y el selector de idioma de la
cabecera (o de la pantalla de inicio de sesión) lo cambia. Los hallazgos se guardan como códigos de mensaje, no como
frases, así que cada persona los lee en su idioma y cambiarlo nunca exige volver a analizar. Lo que nadie pide en
persona (comentarios en PRs, avisos, incidencias de Jira, la CLI) usa `PITANGUS_DEFAULT_LOCALE` (`en` por defecto, ver
[Configuración](configuracion.md)). El texto de terceros, como el resumen de un aviso de NVD o GHSA, se muestra tal
como se publicó.

## Siguientes pasos

- [Inicio rápido](inicio-rapido.md): de cero a tu primera corrección verificada en unos 15 minutos.
- [Conceptos clave](conceptos.md): ejecuciones, hallazgos, huellas, triage y roles.
- [Instalación](instalacion.md): requisitos y los detalles del primer arranque.
- [Preguntas frecuentes](preguntas-frecuentes.md).
