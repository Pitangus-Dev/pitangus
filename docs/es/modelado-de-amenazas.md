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
| MITRE ATT&CK | Técnicas de atacantes reales | Una selección de técnicas (web, API, contenedores, nube) para mapear sobre los componentes, con sugerencias y enlace a attack.mitre.org |
| Personalizado | El método de tu equipo | El diagrama más las herramientas que actives: reglas STRIDE o LINDDUN, amenazas propias, etapas PASTA, árboles de ataque, ATT&CK y la tabla de elementos |

En cualquier enfoque puedes **agregar tus propias amenazas**: título, escenario, categoría, elemento, severidad,
probabilidad, impacto, responsable y mitigación. Cada enfoque tiene una **Guía** (qué significa cada letra, las
etapas, cómo construir un árbol) que se abre junto a tu trabajo y recuerda si la dejaste abierta; las categorías de
STRIDE y LINDDUN muestran su pregunta guía al pasar el cursor.

**Las reglas integradas están a la vista** (STRIDE `TM-S01`…`TM-E02` en `pitangus/modules/threats/model.py`,
LINDDUN `PV-*` en `pitangus/modules/threats/methods.py`). Cada amenaza dice qué la dispara en ese elemento, su
severidad, sus mitigaciones y sus CWE. La severidad parte de la base de la regla, sube un nivel si el elemento está
expuesto a internet y maneja credenciales o pagos, y baja uno si es interno y poco sensible.

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
para pegar o cambiar el JSON, carga de archivos (600 KB como máximo), descarga y copia del ejemplo, y un texto para
copiar y dárselo a un asistente de IA. **Validar JSON** lo comprueba sin crear nada; **Importar modelo** solo se
habilita cuando el texto actual valida.

**Exportar.** En el editor, **Exportar → Modelo JSON (reimportable)** descarga `model.json`: el diagrama completo
(posiciones, componentes, flujos y fronteras), el enfoque, los módulos personalizados, las amenazas que escribió tu
equipo, las etapas PASTA, los árboles de ataque y las técnicas de ATT&CK.

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
  técnicas. **Personalizado** acepta cualquier combinación, pero cada sección necesita su módulo en `custom_modules`
  (`stride`, `linddun`, `manual`, `pasta`, `trees`, `attack`, `elements`). Un archivo incompatible se rechaza con un
  mensaje que dice qué sección sobra y sugiere otro enfoque o Personalizado.
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
| «El contenido no es JSON válido» | Hay una coma, comilla o llave mal puesta | Corrige la sintaxis y valida otra vez. |
| La importación dice que una sección sobra | Esa sección no está permitida en ese enfoque | Cambia `methodology`, o usa `custom` y agrega el módulo a `custom_modules`. |
| «El archivo supera el máximo de 600 KB» | El modelo es demasiado grande | Divídelo en varios modelos. |
| No se proponen componentes desde un repositorio | Sus manifiestos no están entre los soportados, o la App no puede leerlo | Revisa el acceso de la App; agrega los componentes a mano. |
| Una amenaza no muestra indicios | El componente no está vinculado a un repositorio analizado, o la carpeta deja fuera los hallazgos | Vincula el repositorio, analízalo y revisa la carpeta del componente. |

## Siguientes pasos

- [Analiza tu código y tus dependencias](analisis-de-codigo.md): los indicios detrás de cada amenaza.
- [Hallazgos, triage y corrección](hallazgos.md).
- [Evidencias de cumplimiento](cumplimiento.md).
- [Glosario](glosario.md).
