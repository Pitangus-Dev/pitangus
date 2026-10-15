[English](../compliance.md) · Español

# Evidencias de cumplimiento: SBOM, VEX, informes de auditoría y CRA

Auditores, clientes y reguladores hacen cada vez más las mismas preguntas: qué hay dentro de tu software, qué
vulnerabilidades conocidas le afectan, qué decidiste sobre cada una y con qué rapidez las corriges. **Cumplimiento**
(`#/compliance`) convierte tus análisis y tu triage en los archivos que las responden: un **SBOM** (lista de
materiales del software, es decir, sus componentes), un **VEX** (tu declaración de si cada vulnerabilidad te afecta o
no), informes técnicos y evidencia de auditoría según un marco normativo. Para fabricantes que venden en la UE,
agrega un kit para los plazos de notificación del Reglamento de Ciberresiliencia (**CRA**). Los términos están en el
[glosario](glosario.md).

> [!NOTE]
> Todo esto es **evidencia, no una certificación**. La correspondencia con cada control es orientativa, y un informe
> de auditoría es material técnico para un auditor, no una opinión de auditoría, una certificación ni una
> atestación. Revísalo y fírmalo antes de entregarlo. Un informe de Pitangus no sustituye la prueba de penetración que
> pueden exigir SOC 2 o ISO 27001.

## Requisitos previos

- Al menos un **análisis completo terminado** de un repositorio o una imagen. El SBOM y los archivos consolidados
  salen del último análisis completo; una ejecución en la que algún motor no corrió no cuenta. Consulta
  [Analiza tu código](analisis-de-codigo.md) y [Analiza imágenes de contenedor](analisis-de-imagenes.md).
- El triage hecho donde importa: el VEX y las excepciones de la evidencia de auditoría salen de él
  ([Hallazgos, triage y corrección](hallazgos.md)).
- Para el kit CRA: un administrador.

## Descargar evidencias

1. Abre **Cumplimiento**.
2. En **Evidencias**, elige el alcance: un **Repositorio o imagen**, **Una organización**, **Elegir varios** o
   **Todos** (el mismo selector que en Hallazgos). Con un repositorio vienen las imágenes construidas desde él, salvo
   que lo desactives.
3. Elige el **Marco para la evidencia de auditoría** (consulta [Marcos](#marcos)).
4. Descarga lo que necesites. Para un activo:

   | Archivo | Qué es |
   | --- | --- |
   | **SBOM** | CycloneDX, los componentes y versiones del último análisis completo |
   | **VEX** | OpenVEX, si cada vulnerabilidad le afecta, según tu triage |
   | **Informe técnico** | PDF con los hallazgos abiertos, agrupados por corrección |
   | **Evidencia de auditoría** | PDF para el marco elegido: alcance, controles y todos los hallazgos |

   Para más de un activo, los mismos archivos salen **consolidados**: un SBOM y un VEX que cubren cada activo con un
   análisis completo terminado (cada uno con sus propios paquetes), y un PDF de evidencia de auditoría consolidada con
   cada activo, su cobertura y su riesgo abierto (hasta 500 activos).

Los archivos de un solo activo son las mismas exportaciones que obtienes en **Hallazgos → Más formatos**.

## SBOM (CycloneDX 1.6)

El SBOM se construye con el inventario que ya guarda cada análisis completo; no se vuelve a analizar nada. Está
disponible por ejecución y para el estado actual de un repositorio o imagen (tomado de su último análisis completo).
Incluye, para cada componente:

- su package URL (purl) y su versión,
- sus licencias, cuando Trivy las da,
- si es una dependencia directa del producto,
- en imágenes, los paquetes del sistema operativo,

además de la herramienta, el autor y la fecha de generación. Lo que Pitangus no sabe (el proveedor de cada paquete,
hashes por componente) no se inventa: se omite, y el documento dice de dónde salen sus datos. Es válido frente al
esquema oficial de CycloneDX y cubre la base que piden el CRA (Anexo I) y la guía alemana BSI TR-03183-2.

## VEX (OpenVEX)

Un VEX responde a «¿esta vulnerabilidad de una dependencia afecta a mi producto?». Pitangus ya guarda esa decisión con
su motivo, autor y fecha en el triage, y la traduce a declaraciones estándar sin afirmar nada más allá de lo decidido:

| Triage | Estado VEX |
| --- | --- |
| Abierto, sin decidir | `under_investigation`: el analizador lo encontró, nadie lo confirmó |
| En curso | `affected`, con la corrección como acción |
| Riesgo aceptado | `affected`, con el motivo y el vencimiento como acción |
| Falso positivo | `not_affected`, con el motivo como declaración de impacto |
| Remediado (a mano o porque dejó de aparecer) | `fixed` |

Solo se incluyen los avisos de dependencias con identificador (CVE, GHSA…): el código propio no se describe con VEX.

## Paquetes maliciosos

Los paquetes maliciosos conocidos (un aviso `MAL-*` de OpenSSF, uno que su base tipifica como malware, o uno en el que
coinciden dos de su CWE, su título y su descripción; ver [Analiza tu código](analisis-de-codigo.md)) se marcan como
**Malicioso**, críticos y Actuar ya, como un hallazgo por versión del paquete con todos sus avisos, y con la corrección
real: quitar el paquete y rotar los secretos de cada máquina donde se instaló. Nunca «actualiza a…».

## Marcos

El informe de evidencia de auditoría relaciona la misma evidencia técnica con los controles del marco que elijas. La
correspondencia es orientativa.

| Región | Marco | Qué relaciona |
| --- | --- | --- |
| Internacional | SOC 2 Tipo II | CC3.2, CC7.1 y CC8.1 |
| Internacional | ISO/IEC 27001:2022 | A.8.8, A.8.9, A.8.28 y A.8.29 |
| Internacional | PCI DSS 4.0.1 | Requisitos 6.2.4, 6.3.1, 6.3.2 (inventario) y 6.3.3 (parches en un mes) |
| Unión Europea | Ciberresiliencia de la UE (CRA) | Anexo I, parte II (vulnerabilidades, SBOM, pruebas) y artículo 14 |
| Unión Europea | NIS2, Directiva (UE) 2022/2555 | Art. 21(2) y anexo técnico: desarrollo seguro, pruebas y vulnerabilidades |
| Unión Europea | DORA, Reglamento (UE) 2022/2554 | Entidades financieras: riesgo TIC, pruebas y gestión de vulnerabilidades |
| Unión Europea | RGPD, art. 32 | Seguridad del tratamiento: la parte técnica del software que trata datos personales |
| Estados Unidos | NIST SSDF, SP 800-218 | Desarrollo de software seguro |
| Estados Unidos | NIST CSF 2.0 | Identificar y Proteger: inventario, vulnerabilidades, respuesta al riesgo y desarrollo seguro |
| Estados Unidos | NIST SP 800-53 Rev. 5 | FedRAMP: análisis de vulnerabilidades, corrección de fallos y pruebas del desarrollador |
| Estados Unidos | HIPAA, Regla de Seguridad | Salud: insumo para el análisis y la gestión de riesgos |
| Latinoamérica | Brasil: Res. CMN 4.893 / 5.274 | Gestión continua de vulnerabilidades, pruebas y trazabilidad |
| Latinoamérica | Chile: Ley 21.663 | Gestión de riesgos, revisión periódica y registro de decisiones |
| Latinoamérica | Colombia: SFC, CE 007 de 2018 | Vulnerabilidades técnicas, desarrollo seguro y evidencia para supervisión |
| Latinoamérica | México: CNBV, bancos (CUB) y financiamiento colectivo (IFC) | Pruebas de vulnerabilidades, clasificación y remediación |
| Latinoamérica | México: fondos de pago electrónico (IFPE) | Escaneo de vulnerabilidades, plan de remediación y análisis de código antes de liberar |
| Latinoamérica | México: LFPDPPP, art. 18 | Medidas de seguridad técnicas para datos personales |
| — | General | Sin marco: gestión de vulnerabilidades |

**Qué contiene la evidencia de auditoría.** Un PDF conciso con alcance, método, los hallazgos con su estado, las
excepciones aprobadas (riesgos aceptados y falsos positivos con su motivo), la política de
[plazos de corrección](hallazgos.md#plazos-de-corrección) con los hallazgos vencidos, y espacio para firmas. Si lo
generas desde **Hallazgos → Más formatos → Evidencia para auditoría**, puedes completar la organización, para quién y
por quién se prepara, el sistema, el periodo, cuánto detalle por hallazgo incluir (todo, solo críticos y altos, o
solo la tabla) y si incluir las excepciones. Todo es opcional.

## Imágenes y los repositorios desde los que se construyen

**Imágenes** muestra desde qué repositorio se construye cada imagen, leído de sus etiquetas OCI o vinculado a mano
por un administrador (el vínculo manual gana). Así, las evidencias de un repositorio incluyen las imágenes
construidas desde él, y los informes dicen «construida desde org/repo @ commit». Consulta
[Analiza imágenes de contenedor](analisis-de-imagenes.md).

## Kit CRA (opcional)

El Reglamento de Ciberresiliencia de la UE obliga a los fabricantes que venden en la UE productos con elementos
digitales a notificar cada vulnerabilidad **que se explote activamente en su producto**, desde el 11 de septiembre de
2026: una alerta temprana en 24 horas desde que tienen conocimiento, una notificación en 72 horas y un informe final
14 días después de que haya una medida correctora. Se notifica por la plataforma única de ENISA. **Pitangus nunca
notifica por ti**: controla los plazos, prepara un borrador y registra quién marcó cada etapa como enviada.

El kit está apagado por defecto y solo tiene sentido si el CRA te aplica.

1. **Actívalo.** Un administrador abre **Políticas**, busca **Vendemos productos con software en la UE (CRA)**, lo
   activa y da un motivo, que queda en el historial. Apagarlo oculta el kit y conserva sus datos.
2. **Marca tus productos.** En **Cumplimiento**, un administrador usa **Marcar un producto** para elegir qué
   repositorios o imágenes son productos, con su nombre comercial y hasta cuándo tienen soporte.
3. **Evalúa cada coincidencia con KEV.** Cuando un CVE del catálogo CISA KEV aparece en un producto, se abre un
   evento **por evaluar**, sin ningún plazo corriendo: KEV solo dice que el CVE se explota en algún sitio, y tu
   producto puede no llegar al código vulnerable. Un administrador registra una de dos:
   - **No afecta a nuestro producto**, con un motivo. El evento se cierra y se puede reabrir.
   - **Se explota activamente en nuestro producto**: hay pruebas fiables de que alguien lo explotó en tu producto.
     Ese momento es el de conocimiento, y desde él empiezan los plazos de 24 h, 72 h y 14 días. No se puede deshacer.
4. **Notifica y registra.** Cada evento muestra el tiempo que queda por etapa. **Copiar borrador** te da un texto para
   enviar por la plataforma de ENISA; **Marcar como enviada** registra quién envió cada etapa y cuándo.

Un hallazgo descartado como falso positivo en el triage no abre evento. Los eventos se calculan en cada análisis, así
que un producto necesita un análisis completo terminado antes de que haya algo que evaluar.

## Errores frecuentes

| Lo que ves | Por qué | Qué hacer |
| --- | --- | --- |
| «Necesita un análisis completo terminado» junto al SBOM | El activo no tiene un análisis completo terminado, o el último quedó incompleto | Lanza un análisis completo y comprueba que corrieron todos los motores. |
| El SBOM no trae proveedor ni hashes | Pitangus no inventa datos que no tiene | Agrégalos desde tu sistema de compilación si tu auditor los pide. |
| El VEX lista una vulnerabilidad como `under_investigation` | Nadie le hizo triage todavía | Haz su triage en **Hallazgos**. |
| Un informe consolidado cubre como máximo 500 activos | El alcance es demasiado grande | Reduce el alcance. |
| No aparece el kit CRA | La notificación CRA está apagada | Un administrador la activa en **Políticas**. |

## Siguientes pasos

- [Hallazgos, triage y corrección](hallazgos.md).
- [Analiza imágenes de contenedor](analisis-de-imagenes.md).
- [Modelado de amenazas](modelado-de-amenazas.md): evidencia del diseño para acompañar los análisis.
- [Seguridad](seguridad.md): cómo protege Pitangus tus datos.
