[English](../glossary.md) · Español

# Glosario de términos de seguridad de aplicaciones

Los términos que usan la documentación y el panel de Pitangus, en orden alfabético. Cada entrada enlaza a la página
donde más importa.

## A

**Activo.** Algo que Pitangus analiza y para lo que lleva un registro de hallazgos: un repositorio, una imagen de
contenedor o un dominio verificado. Ver [Conceptos clave](conceptos.md).

**Alcance.** Los hosts a los que puede llegar un análisis web: el propio dominio, más los subdominios que quien
administra marque **Analizar** en la pestaña **Alcance** del dominio. Lo que queda fuera no se pide. Ver
[Analizar un sitio web o una API](analisis-web.md).

**Análisis activo.** Una prueba dinámica que envía ataques (inyecciones, fuzzing, cargas manipuladas) para ver si una
aplicación falla. Pitangus no hace análisis activos; están en desarrollo. Ver [Conceptos clave](conceptos.md).

**Análisis pasivo.** Una prueba dinámica que solo envía lo que mandaría un visitante normal y lee las respuestas. Los
análisis web de Pitangus son pasivos. Ver [Analizar un sitio web o una API](analisis-web.md).

## C

**Cobertura parcial.** Una parte de lo que el análisis debía revisar no se revisó (una herramienta falló, no llegó a
un host, un usuario de prueba no pudo iniciar sesión). Pocos hallazgos en esa parte no demuestran nada, y los
hallazgos anteriores de ahí no se marcan remediados. Ver [Conceptos clave](conceptos.md).

**CRA (Cyber Resilience Act).** El reglamento de la UE sobre productos con elementos digitales. Pide a los fabricantes
un SBOM y notificar las vulnerabilidades explotadas activamente en plazos fijos. Pitangus tiene un kit CRA opcional.
Ver [Cumplimiento](cumplimiento.md).

**CVE (Common Vulnerabilities and Exposures).** El identificador público de una vulnerabilidad conocida, como
`CVE-2024-3094`. Pitangus guarda una copia local de los CVE de NVD en el **CVE tracker**. Ver [Hallazgos](hallazgos.md).

**CVSS (Common Vulnerability Scoring System).** Una puntuación de 0 a 10 de la severidad técnica de una vulnerabilidad,
calculada a partir de un vector. Pitangus calcula la puntuación desde el vector en lugar de copiarla. Dice qué tan
grave es un fallo, no qué tan probable es que se explote (ver EPSS y KEV).

**CWE (Common Weakness Enumeration).** Un catálogo de tipos de debilidad, como CWE-79 (cross-site scripting). Los
hallazgos llevan su CWE, que los enlaza con la guía de OWASP y con las amenazas de un modelo de amenazas.

## D

**DAST (pruebas dinámicas de seguridad de aplicaciones).** Probar una aplicación en marcha desde fuera, a través de sus
respuestas. El DAST de Pitangus es pasivo. Ver [Analizar un sitio web o una API](analisis-web.md).

## E

**Ejecución.** El registro de un análisis, una revisión de PR, una importación o una revisión de avisos: qué se
analizó, sus pasos y sus estados, sus hallazgos y sus limitaciones. Ver [Conceptos clave](conceptos.md).

**EPSS (Exploit Prediction Scoring System).** Una probabilidad diaria, publicada por FIRST, de que un CVE se explote en
los próximos 30 días. Pitangus descarga el archivo completo y lo usa en la prioridad.

## F

**Falso positivo.** Una decisión de triage: la herramienta reportó algo que no es un problema real. Necesita un motivo
y queda en el historial del hallazgo. Ver [Hallazgos](hallazgos.md).

## G

**GHSA (GitHub Security Advisory).** Un aviso de la base de avisos de GitHub, con un identificador como
`GHSA-xxxx-xxxx-xxxx`. Muchas veces es la misma vulnerabilidad que un CVE; Pitangus los une en un solo hallazgo.

## H

**Hallazgo.** Un posible problema en un lugar, reportado por una herramienta: un paquete vulnerable, un secreto en una
línea, una mala configuración, una cabecera que falta en una URL. Ver [Conceptos clave](conceptos.md).

**Huella (fingerprint).** El identificador estable de un hallazgo, calculado a partir de qué es el problema y dónde
está, nunca del valor de un secreto. Permite reconocer el mismo hallazgo de una ejecución a otra. Ver
[Conceptos clave](conceptos.md).

## I

**IaC (infraestructura como código).** Infraestructura descrita en archivos: Terraform, manifiestos de Kubernetes,
Dockerfiles, CloudFormation, pipelines. Pitangus la revisa con Trivy y zizmor, y también con Checkov si se activa. Ver
[Analizar tu código](analisis-de-codigo.md).

**IP de salida.** La dirección pública desde la que salen los análisis del servidor. Si un sitio filtra por IP (un
firewall o un WAF), tiene que permitirla. Se define con `PITANGUS_EGRESS_IPS`. Ver
[Analizar un sitio web o una API](analisis-web.md).

## K

**KEV (Known Exploited Vulnerabilities).** El catálogo de CISA de vulnerabilidades explotadas en la práctica. Un
hallazgo en KEV pasa al primer lugar de las prioridades. Ver [Hallazgos](hallazgos.md).

## M

**Modelo de amenazas.** La descripción de un sistema (componentes, flujos de datos, límites de confianza) y de las
amenazas contra él. Ver [Modelado de amenazas](modelado-de-amenazas.md).

## N

**No probado.** El estado de un paso cuyo motor no corrió (Docker no accesible, falta una imagen, una opción
apagada). No se afirma nada de lo que revisa ese motor. Ver [Conceptos clave](conceptos.md).

## O

**OSV (Open Source Vulnerabilities).** Una base abierta de avisos de paquetes de código abierto, que también incluye
los avisos de GitHub. OSV-Scanner compara tus dependencias con ella en local.

**OWASP Top 10.** La lista de la OWASP Foundation con las diez categorías de riesgo más importantes en aplicaciones web
(edición vigente: 2025). Los hallazgos enlazan a su categoría y la página **Cobertura** cruza los análisis con ella.
Ver [Hallazgos](hallazgos.md).

## P

**Pentest (prueba de penetración).** Una prueba en la que una persona o un agente intenta explotar fallos en un sistema
en marcha y demuestra el impacto. Pitangus hace análisis, no pentests. Ver [Conceptos clave](conceptos.md).

**Plazo de corrección.** La fecha en la que un hallazgo pendiente debería estar corregido, contada desde su primera
detección según la severidad (por defecto: crítica 7 días, alta 30, media 90, baja 180). Ver [Hallazgos](hallazgos.md).

## R

**Reverificar.** Volver a analizar después de una corrección para confirmar que llegó. En el panel, **Reverificar** en
un hallazgo responde **Corregido ✓** o **Sigue presente**; después el botón pasa a **Volver a verificar**. Ver
[Hallazgos](hallazgos.md).

**Revisión de PR.** Un análisis del último commit de un pull request que solo cuenta lo que introduce el PR, con un
comentario y un estado de commit en GitHub que puede bloquear el merge. Ver [Analizar tu código](analisis-de-codigo.md).

**Riesgo aceptado.** Una decisión de triage: el equipo conoce un hallazgo y decide no corregirlo por ahora. Solo quien
administra puede aceptar un riesgo, con un motivo y una fecha de caducidad; al caducar, el hallazgo vuelve a contar.
Ver [Hallazgos](hallazgos.md).

**Ruta excluida.** Una carpeta o un patrón que quien administra excluye de los hallazgos de un repositorio (datos de
prueba, código generado), con un motivo. Lo excluido no cuenta ni bloquea PRs, pero sigue visible. Ver
[Hallazgos](hallazgos.md).

## S

**SARIF (Static Analysis Results Interchange Format).** Un formato JSON estándar para resultados de escáneres (versión
2.1.0). Pitangus lo exporta y lo importa de otras herramientas. Ver [Integraciones y automatización](integraciones.md).

**SAST (pruebas estáticas de seguridad de aplicaciones).** Analizar el código fuente sin ejecutarlo, buscando fallos
como inyecciones. Pitangus corre Opengrep con sus propias reglas. Ver [Analizar tu código](analisis-de-codigo.md).

**SBOM (lista de materiales de software).** La lista de componentes que contiene un software, con versiones y
licencias. Pitangus exporta CycloneDX 1.6. Ver [Cumplimiento](cumplimiento.md).

**SCA (análisis de composición de software).** Revisar tus dependencias contra vulnerabilidades conocidas. Ver
[Analizar tu código](analisis-de-codigo.md).

**Secreto.** Una credencial en el código o en una imagen: una clave de API, un token, una contraseña, una clave
privada. Pitangus dice dónde está, nunca su valor.

**STRIDE.** Un método de modelado de amenazas que busca seis tipos de amenaza: suplantación (Spoofing), manipulación
(Tampering), repudio (Repudiation), revelación de información (Information disclosure), denegación de servicio (Denial
of service) y elevación de privilegios (Elevation of privilege). Ver [Modelado de amenazas](modelado-de-amenazas.md).

## T

**TOTP (contraseña de un solo uso basada en tiempo).** Los códigos de una app de autenticación. Obligatorio para los
administradores de Pitangus, y admitido en los usuarios de prueba cuyo inicio de sesión lo pide.

**Triage.** Registrar una decisión sobre un hallazgo: en curso, falso positivo, riesgo aceptado o remediado. Ver
[Hallazgos](hallazgos.md).

## U

**Usuario de prueba.** Una cuenta en tu propio sitio con la que un análisis web inicia sesión para ver páginas detrás
de un login. Se guarda por dominio, cifrada, con una clave TOTP opcional. Ver
[Analizar un sitio web o una API](analisis-web.md).

## V

**Verificación del dominio.** Demostrarle a Pitangus que controlas un dominio antes de poder analizarlo, con un registro
TXT de DNS, un archivo bajo `/.well-known/` o una etiqueta meta. Solo la prueba DNS cubre los subdominios. Demuestra
control, no autorización para probar. Ver [Analizar un sitio web o una API](analisis-web.md).

**VEX (Vulnerability Exploitability eXchange).** Declaraciones legibles por máquina sobre si un producto está afectado
por una vulnerabilidad. Pitangus convierte el triage en OpenVEX. Ver [Cumplimiento](cumplimiento.md).

## W

**Worker.** El proceso que corre los análisis, de a uno, tomándolos de una cola en PostgreSQL. Añade workers para
analizar más a la vez. Ver [Escalar](escalar.md).

**WSTG (Web Security Testing Guide).** La guía de OWASP para probar aplicaciones web, con una prueba numerada por tema.
Los hallazgos web enlazan a la prueba de la WSTG que corresponde.
