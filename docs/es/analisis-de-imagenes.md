[English](../scanning-images.md) · Español

# Analiza imágenes de contenedor

Un análisis de imagen lee una imagen de contenedor directamente desde su registro y te dice qué lleva antes de
desplegarla: paquetes con vulnerabilidades conocidas, secretos olvidados en sus capas o en su historial de
construcción, y ajustes riesgosos como ejecutarse como root. **La imagen nunca se ejecuta ni se construye**, y no
ocupa espacio en tu Docker. Como en todo análisis, los resultados son hallazgos que hay que confirmar, y un resultado
limpio no demuestra que no haya vulnerabilidades. Los términos están en el [glosario](glosario.md).

## Requisitos previos

- Pitangus en marcha ([instalación](instalacion.md)), con las imágenes de los motores disponibles (`make up` o
  `make engines`): Trivy, y Grype y Checkov si un administrador los activó en **Ajustes → Motores de análisis**
  (los dos vienen apagados; al activarlos ahí se descargan sus imágenes).
- La referencia de la imagen, tal como la usarías en `docker pull`: `ghcr.io/acme/api:1.4`, `nginx:1.27` (las de
  Docker Hub pueden ir sin registro) o `…@sha256:…`. Fija una versión o un digest para saber exactamente qué
  revisaste; sin etiqueta se asume `latest`.
- Para una imagen privada: un token de **solo lectura** de su registro, guardado por un administrador (consulta
  [Registros privados](#registros-privados)). Las imágenes públicas no necesitan nada.

## Analizar una imagen desde el panel

1. Haz clic en **Nuevo análisis** (o pulsa `N`) y elige **Imagen de contenedor**.
2. En **Imágenes**, escribe una referencia por línea. Hasta 100 por lote; varias imágenes corren una tras otra y
   puedes seguirlas en **Análisis**. Bajo el campo, cada registro indica si se usarán credenciales guardadas o si el
   acceso es público. Si solo quieres probar, el panel ofrece ejemplos públicos (una imagen antigua con muchos
   avisos, una reciente con pocos y una vulnerable a propósito).
3. Si quieres, agrega **Contexto** para el informe y pasa a **Revisar y lanzar**.

El análisis corre en segundo plano como cualquier otro
([Análisis en segundo plano y progreso](analisis-de-codigo.md#análisis-en-segundo-plano-y-progreso)).

## Analizar una imagen desde la terminal

`scan-image` sirve en CI, después de construir y publicar una imagen. Corre dentro del contenedor de la API de
Pitangus, así que el servidor tiene que estar en marcha, y el resultado se guarda y aparece en el panel:

```bash
make cli ARGS="scan-image --reference ghcr.io/acme/api:1.4"
```

Imprime un resumen en JSON. Tiene esta forma (los valores son un ejemplo):

```json
{
  "id": "…",
  "status": "completed",
  "image": "ghcr.io/acme/api:1.4",
  "summary": {
    "candidates": 42,
    "severities": {"critical": 1, "high": 9, "medium": 20, "low": 12},
    "agreement": 30,
    "kev": 1
  }
}
```

`agreement` cuenta los avisos que reportaron tanto Trivy como Grype; `kev`, los que están en el catálogo CISA KEV.

| Código de salida | Significado |
| --- | --- |
| `0` | Sin hallazgos |
| `1` | Hay hallazgos |
| `2` | Entrada inválida: la referencia no es válida, el registro no resuelve o resuelve a una dirección privada |
| `3` | Incompleto: un motor no corrió, así que el resultado no demuestra nada |

Son los mismos códigos que `scan-repository` y [`scan`](cli.md).

## Qué se revisa

| Qué | Cómo |
| --- | --- |
| Paquetes del sistema y de aplicaciones | **Trivy 0.75.0, y Grype 0.120.0 si se activa** (**Ajustes → Motores de análisis**; apagado por defecto, figura como no ejecutado (desactivado) y no remedia nada de lo que encontró antes). Sobre código fuente coinciden casi por completo; sobre imágenes discrepan en paquetes cuyas correcciones la distribución aplicó a versiones antiguas (en `nginx:1.21`: 781 avisos en común, 99 solo de Trivy y 11 solo de Grype, uno de ellos crítico). Los avisos se unen por paquete, versión e identificador (CVE o GHSA), comparando los nombres como los escribe cada motor (un paquete Java es `grupo:artefacto` para Trivy y `artefacto` para Grype; una versión de Go es `v1.22.1` para uno y `go1.22.1` para el otro); los que ven ambos motores ganan confianza. De una imagen multiplataforma, ambos analizan la misma plataforma: Grype la que leyó Trivy (normalmente `linux/amd64`; el paso de Grype la nombra), nunca la del propio servidor (en un servidor ARM se mezclarían dos imágenes). |
| Secretos en las capas | Trivy busca credenciales en los archivos de cada capa. |
| Credenciales en `ENV` | Variables con nombre de secreto (`*_TOKEN`, `*_PASSWORD`, `API_KEY`…) y un valor fijo: cualquiera que descargue la imagen las lee con `docker inspect`. |
| Credenciales en el historial de construcción | `ARG` usados en un `RUN` (por ejemplo `NPM_TOKEN=… npm ci`), URLs con usuario y contraseña, y cabeceras `Authorization` fijas: se quedan en la imagen y `docker history` las muestra. La corrección recomendada es `RUN --mount=type=secret` de BuildKit. |
| Configuración | Reglas de Pitangus: usuario root, falta de `HEALTHCHECK`, `ADD` desde una URL, SSH expuesto, la etiqueta `latest` sin digest e imágenes de más de un año. |
| Instrucciones del historial | **Checkov**, si se activa (**Ajustes → Motores de análisis**), sobre un Dockerfile reconstruido a partir del historial de la imagen: descargas sin verificar TLS (`curl -k`, `wget --no-check-certificate`, `NODE_TLS_REJECT_UNAUTHORIZED=0`), `pip --trusted-host`, gestores de paquetes sin firma, `sudo`, `chpasswd`… Cada hallazgo apunta al paso del historial. Se reconstruye el Dockerfile porque el modo de imágenes propio de Checkov exige una cuenta de Prisma Cloud. |

Los hallazgos de configuración que ven a la vez Trivy, Checkov (si está activo) y las reglas de Pitangus quedan como uno solo (la
regla de Pitangus es la principal). Los avisos de dependencias reciben el mismo trato que en un análisis de código:
versión corregida, KEV, EPSS y prioridad ([Hallazgos de dependencias](analisis-de-codigo.md#hallazgos-de-dependencias)).

No se guarda ningún valor secreto: solo el nombre de la variable o el paso del historial.

## Registros privados

Un administrador guarda las credenciales en **Integraciones → Registros de contenedores**. Se cifran en el servidor,
nunca vuelven al navegador ni se escriben en los logs; llegan a los motores por variables de entorno, no por la línea
de comandos. Guardar otra vez para el mismo registro las reemplaza. Usa siempre un token de **solo lectura**:

| Registro (host) | Usuario | Token |
| --- | --- | --- |
| `ghcr.io` | tu usuario de GitHub | token clásico solo con `read:packages` |
| `docker.io` | tu usuario de Docker Hub | token de acceso de solo lectura (Account settings, Personal access tokens) |
| `<cuenta>.dkr.ecr.<región>.amazonaws.com` | `AWS` | salida de `aws ecr get-login-password` (caduca a las 12 h) |
| `<región>-docker.pkg.dev` | `_json_key_base64` | clave de una cuenta de servicio con Artifact Registry Reader |

Los registros de tu red interna (direcciones IP privadas) están bloqueados, para que nadie use el panel para que el
servidor alcance servicios internos. Para analizar desde tu propio registro en la red local, arranca el servidor con
`PITANGUS_ALLOW_PRIVATE_REGISTRIES=1` ([Configuración](configuracion.md)).

## Qué verás en el panel

Cada imagen es su propio activo en **Hallazgos**, identificado por registro y repositorio, **sin la etiqueta**. Cuando
analizas `api:1.5`, lo que ya no aparece respecto de `api:1.4` queda como remediado, y lo que vuelve se reabre. La
cabecera de la ejecución muestra el digest y cuántos avisos confirmaron ambos motores.

**Imágenes** lista las imágenes que analizaste (o agregaste) y el repositorio desde el que se construye cada una:

- **El vínculo con su repositorio.** Pitangus lo lee de las etiquetas OCI de la imagen
  (`org.opencontainers.image.source` y `org.opencontainers.image.revision`). Si faltan o están mal, un
  administrador lo vincula a mano (**Vincular un repositorio**), y el vínculo manual gana sobre la etiqueta. Ninguno
  de los dos tiene que estar analizado antes: el selector lista los repositorios analizados y aquellos a los que
  llegan la GitHub App o un token conectado, y **Vincular una imagen** en cada fila de **Repositorios** abre la lista de imágenes para vincular las
  que elijas sin salir de la página. Un
  repositorio aún sin analizar se muestra así; el vínculo se conserva y suma la imagen a los alcances de ese
  repositorio desde su primer análisis.
- **Para qué sirve el vínculo.** Las evidencias de un repositorio incluyen las imágenes construidas desde él, los
  informes dicen «construida desde org/repo @ commit», y el selector de alcance de Hallazgos y Cumplimiento puede
  sumarlas al repositorio ([Varios activos a la vez](hallazgos.md#varios-activos-a-la-vez)).
- **Agregar imagen** pone una imagen en la lista sin analizarla, si quieres vinculada a su repositorio
  (**Se construye desde**) y analizada al momento si marcas **Analizarla ya**. Entra en hallazgos y evidencias con
  su primer análisis. Un administrador puede quitar una imagen que nunca se analizó.

## Lo que no cubre

Un análisis de imagen lee los paquetes y la configuración que hay dentro. Cómo se comporta la aplicación requiere un
análisis de su código y del sitio desplegado. Los paquetes del sistema operativo se revisan contra avisos nuevos solo
cuando la imagen se vuelve a analizar (la vigilancia diaria de avisos cubre las dependencias del código).

## Errores frecuentes

| Lo que ves | Por qué | Qué hacer |
| --- | --- | --- |
| La referencia de la imagen no es válida | No tiene la forma de `docker pull` (mayúsculas, espacios…) | Escríbela como `registro/repositorio:etiqueta`, en minúsculas. |
| No se pudo resolver el registro | El nombre del registro no resuelve desde el servidor | Revisa el nombre y el DNS del servidor. |
| El registro resuelve a una dirección privada | Los registros internos están bloqueados por defecto | Arranca el servidor con `PITANGUS_ALLOW_PRIVATE_REGISTRIES=1` si es tuyo. |
| El análisis falla por autenticación | No hay credenciales o el token caducó (los de ECR duran 12 h) | Guarda o renueva el token en **Integraciones → Registros de contenedores**. |
| Código de salida `3` o ejecución incompleta | Un motor no corrió | Ejecuta `make engines` y revisa los pasos de la ejecución. |

Más en [Solución de problemas](solucion-problemas.md).

## Siguientes pasos

- [Hallazgos, triage y corrección](hallazgos.md).
- [Evidencias de cumplimiento](cumplimiento.md): SBOM y VEX de las imágenes y de los repositorios desde los que se construyen.
- [Analiza tu código y tus dependencias](analisis-de-codigo.md).
- [Analizar desde la terminal y en CI](cli.md).
