[English](../threat-modeling.md) · Español

# Modelado de amenazas

Los analizadores encuentran fallas en lo que ya está escrito. El **modelado de amenazas** mira el diseño: dibujas el
sistema (sus componentes, los datos que circulan entre ellos y las fronteras de confianza que cruzan) y te preguntas
qué podría salir mal en cada punto. **Amenazas** (`#/threats`) te permite dibujar ese modelo, aplicar un método como
STRIDE y contrastar cada amenaza con lo que encontraron tus análisis. Una amenaza es un escenario por revisar, no una
falla confirmada. Los términos están en el [glosario](glosario.md).

## Requisitos previos

- Pitangus en marcha. Un modelo no necesita repositorios, pero vincular sus componentes a repositorios analizados o a
  dominios verificados es lo que aporta indicios ([Analiza tu código](analisis-de-codigo.md)).
- Para recibir sugerencias de componentes desde un repositorio de GitHub: la GitHub App instalada en él, con
  `contents: read` ([Conectar GitHub](github-app.md)).

## Crear un modelo

1. Abre **Amenazas** y haz clic en **Nuevo modelo**.
2. Ponle nombre al proyecto (por ejemplo «Pagos» o «Portal de clientes») y elige un **Enfoque** (más abajo). Puedes
   cambiarlo después sin perder el diagrama.
3. Si quieres, en **Partir de repositorios (opcional)**, elige uno o varios repositorios y haz clic en
   **Crear y proponer componentes**: Pitangus sugiere componentes y flujos a partir de sus manifiestos (consulta
   [Sugerencias desde repositorios](#sugerencias-desde-repositorios)).
4. Dibuja o ajusta el sistema en **Diagrama** y haz clic en **Guardar y recalcular**.

Cada modelo es un proyecto: asocia los **Repositorios del proyecto** cuando quieras, uno o varios (microservicios,
microfrontends). Un componente vinculado a un repositorio lo agrega a la lista solo.

### Enfoques

| Enfoque | Para qué | Qué hace Pitangus |
| --- | --- | --- |
| STRIDE | Amenazas de seguridad a componentes y flujos (suplantación, manipulación, repudio, revelación de información, denegación de servicio, elevación de privilegios) | Reglas integradas sobre el diagrama (`TM-*`) |
| LINDDUN | Amenazas a la privacidad de las personas | Reglas integradas sobre los elementos que guardan datos personales (`PV-*`) |
| PASTA | Riesgo de negocio en siete etapas | Etapas con notas; las etapas 3, 4 y 5 se alimentan del diagrama, de STRIDE y de los análisis |
| Árboles de ataque | Caminos hacia el objetivo de un atacante | Editor de árboles Y/O con dificultad, elemento y mitigación; calcula qué caminos siguen abiertos |
| MITRE ATT&CK | Técnicas de atacantes reales | El catálogo Enterprise completo, sin conexión, para mapear sobre los componentes, con sugerencias a partir de los datos de plataformas de MITRE (ver [MITRE ATT&CK](#mitre-attck)) y enlace a attack.mitre.org; también admite cualquier otro ID de técnica |
| Personalizado | El método de tu equipo | El diagrama más las herramientas que actives: reglas STRIDE o LINDDUN, amenazas propias, etapas PASTA, árboles de ataque, ATT&CK y la tabla de elementos |

En cualquier enfoque puedes **agregar tus propias amenazas**: título, escenario, categoría, elemento, severidad,
probabilidad, impacto, responsable y mitigación. Cada enfoque tiene una **Guía** (qué significa cada letra, las
etapas, cómo construir un árbol) que se abre junto a tu trabajo y recuerda si la dejaste abierta; las categorías de
STRIDE y LINDDUN muestran su pregunta guía al pasar el cursor.

**Las reglas integradas están a la vista** (STRIDE `TM-S01`…`TM-E02` en `pitangus/modules/threats/model.py`,
LINDDUN `PV-*` en `pitangus/modules/threats/methods.py`). Cada amenaza dice qué la dispara en ese elemento, su
severidad, sus mitigaciones y sus CWE. La severidad parte de la base de la regla, sube un nivel si el elemento está
expuesto a internet y maneja credenciales o pagos, y baja uno si es interno y poco sensible.

### MITRE ATT&CK

**El catálogo es el de MITRE, completo.** Pitangus incluye MITRE ATT&CK Enterprise v19.2 tal como MITRE lo publica en
[attack-stix-data](https://github.com/mitre-attack/attack-stix-data) (archivo fijado por SHA-256, nunca se descarga
en ejecución): 697 técnicas vigentes (222 técnicas y 475 subtécnicas), más 149 IDs revocados y 12 obsoletos, que se
reconocen y se señalan. **Mapear una técnica** abre el catálogo: recórrelo por táctica o busca por ID, nombre o
táctica. Los nombres son los de MITRE, en inglés; en español, nuestra traducción va debajo (técnicas y tácticas; las
subtécnicas conservan solo el nombre de MITRE). Los informes siguen el mismo criterio.

**De dónde salen las sugerencias.** MITRE indica, para cada técnica, las plataformas a las que aplica
(`x_mitre_platforms`). Pitangus solo decide en qué plataforma de ATT&CK corre cada tipo de componente y en qué
tácticas ese componente es lo que el atacante ataca; las técnicas son las que MITRE lista ahí. Solo con las
plataformas, un servidor recibiría 177 técnicas; las tácticas acotan la lista. Una sola tabla, en
`pitangus/modules/threats/methods.py` (`SUGGESTION_RULES`):

| Tipo de componente | Plataformas de MITRE | Tácticas | Por qué |
| --- | --- | --- | --- |
| Aplicación web, API, servicio interno | Windows, macOS, Linux (+ Containers) | Execution, Credential Access, Impact | Corren en un equipo, y en una plataforma de contenedores cuando la tecnología lo dice; ahí el atacante ejecuta código, se lleva los secretos que guardan y los deja sin servicio. |
| Función o tarea | IaaS | Execution, Credential Access, Impact | El código serverless corre en el proveedor de nube, no en un equipo que administres: MITRE ubica Serverless Execution y las técnicas de credenciales de nube en IaaS. |
| Base de datos, caché, cola | Windows, macOS, Linux (+ Containers) | Collection, Exfiltration, Impact | Los almacenes autogestionados corren en un equipo; lo que importa son los datos: tomarlos, sacarlos, destruirlos o alterarlos. |
| Almacenamiento de archivos | IaaS | Collection, Exfiltration, Impact | Suele ser un bucket en la nube; las técnicas de almacenamiento en la nube de MITRE (Data from Cloud Storage, Transfer Data to Cloud Account) son de IaaS. |
| Servicio de terceros | SaaS | Initial Access, Credential Access, Exfiltration | Un proveedor que no operas: una vía de entrada de confianza, tokens y sesiones que robar y un canal para sacar datos. |
| Proveedor de identidad | Identity Provider | Initial Access, Persistence, Credential Access | Tiene plataforma propia en ATT&CK: cuentas válidas, manipulación de cuentas y alteración de la autenticación. |

- Los componentes **expuestos a internet** suman **Initial Access** (Exploit Public-Facing Application, External
  Remote Services…).
- **Containers** se suma a un componente que corre en un equipo cuando su tecnología nombra un motor u orquestador de
  contenedores (Docker, Kubernetes, k8s, OpenShift, Podman, Helm, ECS, EKS, AKS, GKE, Fargate, Cloud Run, Nomad).
- Solo se sugieren técnicas; sus subtécnicas están a un clic en el catálogo.
- **Sin sugerencias** para un actor (ATT&CK no tiene plataforma para personas) ni para un **tipo propio** (su rol base
  decide las reglas STRIDE, no ATT&CK: una cámara no es un servicio web). Mapea sus técnicas desde el catálogo.
- ATT&CK también tiene Office Suite, Network Devices, ESXi y PRE; ningún tipo de componente corresponde todavía a
  ellas, y sus técnicas siguen en el catálogo.

Las sugerencias se agrupan por técnica, con los componentes a los que aplica cada una; añádela a uno o a todos. Nada se
añade solo.

## Dibujar el sistema

En **Diagrama**:

- **Componentes**: agrégalos desde la barra del lienzo y arrástralos. Tipos: actor, aplicación web, API, servicio,
  función, base de datos, caché, cola, almacenamiento, tercero y proveedor de identidad. **Otro tipo (lo nombras
  tú)** crea un tipo personalizado con cualquier nombre y un **Rol base para el análisis**, que decide qué reglas
  automáticas se le aplican.
- **Flujos**: conecta dos componentes arrastrando entre sus puntos de conexión. Un flujo dice qué transporta, su
  protocolo, sus datos, y si está autenticado y cifrado en tránsito.
- **Fronteras de confianza**: cajas que puedes mover (sus componentes se mueven con ellas) y redimensionar. Un
  componente pertenece a la frontera que contiene su centro.
- **Selecciona un elemento** para editarlo en el panel lateral: nombre, tipo, tecnología, descripción, los datos que
  guarda o maneja, y propiedades como expuesto a internet o autentica. Ahí también vinculas un componente a un
  repositorio o a un dominio y defines su **Carpeta dentro del repositorio** (consulta
  [Indicios](#indicios-no-confirmación)).
- **Redimensiona** componentes y fronteras arrastrando un borde o una esquina (los tiradores aparecen al pasar el
  cursor); mantén **Shift** para conservar la proporción.
- **Ordenar** distribuye todo por capas (actores, luego aplicaciones, luego APIs y servicios, luego datos y
  terceros), con cada frontera como un bloque que contiene sus componentes.
- Las etiquetas de los flujos se colocan donde no se encimen con componentes ni con otras etiquetas; las largas se
  acortan y se leen completas al seleccionar el flujo o al pasar el cursor.

Las posiciones se guardan con el modelo y las usan las exportaciones. **Tabla** sirve para editar muchos componentes,
flujos y fronteras a la vez. Si el servidor se actualiza mientras trabajas, las pestañas abiertas muestran
**Recargar**: guarda antes.

## Sugerencias desde repositorios

Desde cada repositorio del proyecto (al crearlo o después), Pitangus sugiere componentes y flujos y **los agrega al
diagrama sin duplicar** lo que ya hay, respetando lo que dibujó tu equipo: lo nuevo va dentro de su frontera o a la
derecha.

- Hasta 10 repositorios a la vez. Los de la GitHub App se leen en el momento, estén analizados o no; un repositorio
  del espacio de trabajo del servidor se propone a partir de su último análisis.
- Solo se leen manifiestos, por la API de GitHub (árbol del repositorio y archivos; el repositorio no se descarga):
  `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Dockerfile` y archivos compose,
  hasta 40 archivos, sin `node_modules`, fixtures ni pruebas.
- FastAPI, Next.js, Express o axum se convierten en procesos; psycopg, Prisma, Mongoose o sqlx en bases de datos (un
  ORM se une con su motor); Stripe, Twilio, S3, next-auth o un SDK de LLM en terceros o proveedores de identidad.
- **Cada componente sugerido cita la dependencia y el archivo de donde salió** y queda marcado como propuesto desde
  el repositorio, para que el equipo lo corrija.
- Solo se guardan nombres, nunca versiones ni valores de configuración.

Un repositorio sin analizar se modela igual, pero sus amenazas no tienen indicios hasta que se analice.

## Indicios, no confirmación

Cuando un componente está vinculado a un repositorio y ese código tiene hallazgos abiertos con alguno de los CWE de
una amenaza, la amenaza queda **Con indicios** y enlaza esos hallazgos (**Indicios en los análisis**). Es una señal
para revisar, no la prueba de que el escenario sea explotable.

- En un monorepo, define la **Carpeta dentro del repositorio** del componente (por ejemplo `frontend/`) para que solo
  cuenten los hallazgos de su propio código. Sin carpeta cuenta todo el repositorio, y la amenaza lo dice.
- No cuentan los hallazgos en rutas excluidas ni los descartados en el triage.
- Los avisos de dependencias son indicio de «dependencias vulnerables», no de una inyección en tu propio código.

## Decisiones

Cada amenaza se puede cerrar con una decisión: **Mitigada** (di qué control la mitiga y dónde se puede comprobar),
**Aceptada** (por qué y hasta cuándo) o **No aplica** (por qué no aplica a este sistema). Cada decisión guarda su
motivo, autor y fecha, y se puede reabrir. Si hay hallazgos abiertos que apuntan a la amenaza, el diálogo lo avisa
antes de decidir.

## Importar y exportar un modelo en JSON

El modelo tiene un formato JSON portable que puedes versionar, editar a mano o pedirle a un asistente de IA que
escriba.

**Importar.** En la lista, **Importar JSON** abre un asistente con un ejemplo completo para cada enfoque, un editor
para pegar o cambiar el JSON, **Formatear JSON** (sangría de dos espacios; si hay un error de sintaxis dice la línea y
la columna), carga de archivos (600 KB como máximo), descarga y copia del ejemplo, y **Copiar prompt para IA**: el
contrato completo (valores admitidos, reglas de ids y referencias, el formato de los IDs de ATT&CK y un ejemplo mínimo
válido) para dárselo a un asistente de IA. **Validar JSON** lo comprueba sin crear nada y lista **todos los problemas
de una vez**, en tres niveles: **errores** (bloquean la importación), **advertencias** (se cambió o no se pudo usar
algo que importa) y **ajustes menores** (un sinónimo leído como nuestro campo, un campo conservado como propiedad
personalizada). Los problemas idénticos se agrupan («description se leyó como scenario · en 12 amenazas propias») y se
abren para ver cada lugar; haz clic en uno para ir a él en el editor. La línea de estado cuenta solo errores y
advertencias («Listo para importar con 2 advertencias»); los ajustes menores quedan plegados bajo su número.

**Lo que se guarda se ve; nada de lo que escribes se descarta.** Solo la integridad estructural detiene la
importación: JSON inválido, `format` o `version` incorrectos, ids que faltan o se repiten, referencias (`source`,
`target`, `element`, `parent`, los `components` de una frontera) a ids que no existen, tipos equivocados (texto,
`true`/`false`, listas), un ID de ATT&CK que no lo es, tamaños por encima de su límite y secciones que un enfoque fijo
no usa. Todo lo demás se conserva y se muestra:

- Las **descripciones** de componentes, flujos y fronteras se guardan, se ven en el inspector (y como texto emergente
  en el diagrama) y salen en los anexos de flujos y de fronteras de confianza de los informes.
- Los **supuestos** (`assumptions: [{"id": "a1", "text": "…"}]`, o una lista de frases) son una sección del modelo:
  se editan en la pestaña **Contexto** y abren el informe, antes del análisis.
- Los **campos que Pitangus no conoce** pasan a ser **propiedades personalizadas** de su objeto: se listan y se editan
  (añadir, renombrar, quitar) en el inspector, en el diálogo de la amenaza, en el árbol y en la tabla de ATT&CK; en el
  diagrama, como texto emergente; en los informes, en un anexo «Propiedades personalizadas»; y se exportan de vuelta al
  lugar del JSON de donde vinieron. Los campos desconocidos del propio modelo son sus propiedades y secciones, visibles
  en **Contexto** y en el informe (una lista de objetos como tabla, una lista como viñetas). Un campo parecido a uno
  nuestro («sevirity») también se conserva, con una advertencia que pregunta si querías decir el nuestro.
- Los **sinónimos** se leen como nuestros campos con un ajuste menor: `component_id`, `component`, `element_id` o
  `flow_id` → `element`; la `description` de una amenaza → `scenario` (se unen si vienen los dos); el `name` o `title`
  de un árbol → `goal` (se antepone); el `label` de un paso → `text` y su `type` → `gate`; el `technique_id` de un
  mapeo → `technique` y `notes` → `note`; `from`/`to` de un flujo → `source`/`target`; y más. Los nombres de campo no
  distinguen mayúsculas ni guiones. La lista completa está en el JSON Schema (`x-pitangus-aliases`) y en el prompt para
  IA. Si llegan nuestro campo y un sinónimo con valores distintos, se usa el nuestro y el sinónimo queda como propiedad
  personalizada (advertencia).

**Tus propios valores.** Nuestras listas son sugerencias; cada equipo tiene las suyas. Un valor que Pitangus no conoce
pasa a ser una opción nueva de ese campo en tu espacio de trabajo (el selector la ofrece la próxima vez):

| Campo | Pitangus conoce | Cualquier otro valor |
| --- | --- | --- |
| `protocol` de un flujo | `https`, `http`, `grpc`, `websocket`, `sql`, `amqp`, `redis`, `smtp`, `sftp`, `other` | Se conserva tal cual (24 caracteres como máximo, p. ej. `wifi`, `mqtt`). Pitangus no puede saber si va cifrado: indica `encrypted` (entonces es solo un ajuste menor). |
| `kind` de un componente | `actor`, `web_app`, `api`, `service`, `function`, `database`, `cache`, `queue`, `storage`, `external`, `identity` | Se conserva como tipo propio (`kind: custom`, `custom_kind`) y se analiza con el rol de `custom_base` (por defecto `service`). |
| Clases de `data` | `public`, `internal`, `confidential`, `pii`, `credentials`, `payment` | Se conserva tal cual (40 caracteres como máximo); cuenta como dato interno y no se le aplican reglas de privacidad ni de credenciales. |
| `severity`, `likelihood`, `impact`, `difficulty` | `critical`, `high`, `medium`, `low` (y los sinónimos `crit`, `med`, `moderate`, `severe`…) | Se conserva con su nombre como nivel propio. Se ordena después de los niveles conocidos salvo que le des un equivalente (`level_equivalents: {"severity": {"Grave": "high"}}`, o **se ordena como** en el diálogo de la amenaza). |
| `status` de un mapeo de ATT&CK | `relevant`, `mitigated`, `not_applicable` (y `potential`, `possible`, `addressed`, `n/a`…) | Se conserva como estado propio. |
| `category` de una amenaza propia | Categorías de STRIDE y LINDDUN | Texto libre en todos los enfoques salvo STRIDE y LINDDUN (ver abajo). |

**Lo que es propio del método.** Cada plantilla conserva su principio: un modelo **STRIDE** tiene las seis categorías
de STRIDE y uno **LINDDUN** las siete de LINDDUN (un código, o el nombre de la categoría en inglés o en español, se lee
como su código); **PASTA** tiene sus siete etapas; un paso de un árbol de ataque es **AND** u **OR**. Un valor fuera
del método se conserva como propiedad personalizada con una advertencia que sugiere el enfoque **Personalizado** para
modelar con tus propias categorías o secciones. Un enfoque que Pitangus no tiene se importa como Personalizado y
conserva su nombre como propiedad. **Personalizado** es libertad total: acepta y muestra cualquier categoría, estado,
escala, sección o campo; una sección que trae el archivo activa su módulo.

**ATT&CK.** Pitangus incluye el catálogo completo de MITRE ATT&CK Enterprise (v19.2, todas las técnicas y subtécnicas
con su nombre y sus tácticas), sin conexión. Cualquier ID real se reconoce y se nombra (T1552.004 es «Private Keys»);
nuestra selección es solo lo que sugerimos. Un ID bien formado que no existe en ATT&CK se conserva con la advertencia
«no existe en ATT&CK v19.2», y uno revocado nombra su reemplazo cuando MITRE lo indica. Para actualizarlo, cambia la
versión fijada en `scripts/attack-catalog.py` y ejecuta `make attack-catalog`.

**JSON Schema.** El formato está descrito como JSON Schema (draft 2020-12): descárgalo desde el asistente de
importación (**Descargar JSON Schema**) o léelo en el repositorio en `web/src/examples/threat-models/schema.json`. Se
genera a partir de las mismas listas que usa el importador (`make openapi`), igual que el prompt para IA. Un documento
que valida contra él se importa sin errores. La ruta `/api/threat-models/validate` responde
`{…conteos, "problems": [{"severity", "path", "id", "code", "message"}]}`, donde `severity` es `error`, `warning` o
`info`, `path` es un JSON Pointer como `/model/flows/3/protocol` y `code` es igual para problemas idénticos; si hay
errores responde 400 con `error` (el primero) y la misma lista `problems`.

**Exportar.** En el editor, **Exportar → Modelo JSON (reimportable)** descarga `model.json`: el diagrama completo
(posiciones, componentes, flujos y fronteras, con sus descripciones), el enfoque, los módulos personalizados, los
supuestos, las amenazas que escribió tu equipo, las etapas PASTA, los árboles de ataque, las técnicas de ATT&CK, los
equivalentes de tus niveles propios y cada propiedad personalizada en su lugar.

El importador acepta tanto el sobre que descarga el panel (`{"format": "pitangus-threat-model", "version": 1,
"model": {…}}`) como un objeto de modelo suelto. Un ejemplo mínimo:

```json
{
  "name": "Portal de clientes",
  "methodology": "custom",
  "custom_modules": ["stride", "trees", "manual"],
  "repository_refs": ["equipo/portal"],
  "components": [
    {"id": "usuario", "name": "Cliente", "kind": "actor"},
    {"id": "api", "name": "API", "kind": "api", "asset_ref": "equipo/portal", "data": ["pii"]}
  ],
  "flows": [{"id": "login", "source": "usuario", "target": "api", "protocol": "https", "authenticated": false}],
  "boundaries": [{"id": "servidor", "name": "Servidor", "components": ["api"]}]
}
```

Reglas que conviene saber:

- **Las referencias quedan pendientes, nunca se vinculan solas.** Los repositorios y dominios del archivo se guardan
  como `repository_refs` y `asset_ref`. No hace falta que existan al importar; vincúlalos después en el editor.
- **La disposición es opcional.** `position` (componentes), `size` (componentes redimensionados) y `box` (fronteras)
  se pueden omitir: el editor lo distribuye todo. Si las posiciones no encajan con sus fronteras (una caja más pequeña
  que sus componentes, o dos cajas que se solapan), el modelo se redistribuye al importar y la vista previa lo avisa.
- **Las secciones tienen que corresponder al enfoque.** El diagrama es común a todos los enfoques. STRIDE y LINDDUN
  aceptan amenazas propias; PASTA acepta sus etapas y árboles; Árboles de ataque acepta árboles; ATT&CK acepta
  técnicas. Un archivo con una sección que su enfoque fijo no usa se rechaza con un mensaje que dice qué sección sobra
  y sugiere otro enfoque o Personalizado (la sección no se descarta en silencio: la perderías). **Personalizado**
  acepta cualquier combinación: sus módulos (`stride`, `linddun`, `manual`, `pasta`, `trees`, `attack`, `elements`)
  son los de `custom_modules` más los de las secciones que trae el archivo.
- Al exportar un enfoque fijo solo se incluyen sus secciones; los datos que queden de otro enfoque tras cambiar de
  plantilla no se cuelan en el archivo.
- Los ID de instancia, las decisiones y los hallazgos de los análisis no forman parte del formato portable.

## Otras exportaciones

Desde **Exportar** en el editor:

| Exportación | Qué es |
| --- | --- |
| **Informe PDF** e **Informe Markdown** | Para el equipo de desarrollo: qué atender primero, el diagrama, las amenazas que escribió tu equipo, las que tienen indicios en los análisis y las de reglas agrupadas por patrón, con el detalle en anexos. Las amenazas del modelo no se presentan como fallas confirmadas. |
| **Diagrama SVG** | Solo el diagrama (`diagram.svg`); los cambios pendientes se guardan antes de descargar. |
| **OWASP Threat Dragon** | JSON de Threat Dragon v2. No se probó importarlo en Threat Dragon. |
| **pytm (Python)** | Un script de OWASP pytm (`tm.py`), para equipos que mantienen el modelo como código. |

Las descargas pasan por la API autenticada y muestran el error real si fallan.

## Errores frecuentes

| Lo que ves | Por qué | Qué hacer |
| --- | --- | --- |
| «Este JSON no es válido: línea 12, columna 5» | Hay una coma, comilla o llave mal puesta cerca de ahí | Haz clic en el problema para ir a él, corrígelo y usa **Formatear JSON** o valida otra vez. |
| «… apunta a «x», que no es el id de ningún elemento» | Una referencia a un id que no existe | Corrige el id o agrega el componente al que se refiere. |
| Una advertencia de que un valor es propio | Pitangus no conoce ese protocolo, tipo o clase de dato | No hay nada que corregir: se conserva. Indica lo que Pitangus no puede deducir (p. ej. `encrypted`). |
| «STRIDE solo tiene estas categorías…» | Una categoría fuera del método en un modelo STRIDE o LINDDUN | Se conserva como propiedad personalizada. Usa una categoría del método, o el enfoque Personalizado. |
| «N ajustes menores» | Sinónimos leídos como nuestros campos, campos conservados como propiedades personalizadas | No hay nada que corregir; ábrelos para ver cada uno. |
| La importación dice que una sección sobra | Esa sección no está permitida en ese enfoque | Cambia `methodology`, o usa `custom` y agrega el módulo a `custom_modules`. |
| «El archivo supera el máximo de 600 KB» | El modelo es demasiado grande | Divídelo en varios modelos. |
| No se proponen componentes desde un repositorio | Sus manifiestos no están entre los soportados, o la App no puede leerlo | Revisa el acceso de la App; agrega los componentes a mano. |
| Una amenaza no muestra indicios | El componente no está vinculado a un repositorio analizado, o la carpeta deja fuera los hallazgos | Vincula el repositorio, analízalo y revisa la carpeta del componente. |

## Siguientes pasos

- [Analiza tu código y tus dependencias](analisis-de-codigo.md): los indicios detrás de cada amenaza.
- [Hallazgos, triage y corrección](hallazgos.md).
- [Evidencias de cumplimiento](cumplimiento.md).
- [Glosario](glosario.md).
