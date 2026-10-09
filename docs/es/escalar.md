[English](../scaling.md) · Español

# Escalar: más repositorios, más workers

Pitangus es un solo código, pero sus tres piezas escalan por separado: la **API y el panel** no guardan estado
propio, el **worker** es donde corren los análisis y **PostgreSQL** lo tiene todo, incluida la cola de análisis.
Añadir capacidad es añadir workers; nada más cambia. Esta página cuenta qué hace un worker, cómo añadir más, dónde
analizar sin servidor y qué no escala todavía.

## Qué hace un worker

- **Un análisis a la vez.** El worker toma un trabajo de la cola, lo termina y toma el siguiente. Dentro de un
  análisis, los motores corren uno detrás de otro, cada uno con su tope: 3 GB de memoria y 2 CPU cuando el worker los
  arranca por el socket de Docker; el tope del propio worker (`PITANGUS_WORKER_MEMORY`, 4 GB en
  [`deploy/compose.yaml`](../../deploy/compose.yaml)) cuando corren dentro de su imagen.
- **Una cola que no se pierde.** Los análisis son filas de la tabla `jobs`. Los workers las toman con `FOR UPDATE
  SKIP LOCKED`, así que dos nunca cogen la misma. Un trabajo en marcha se renueva cada pocos segundos; si su worker
  muere, deja de renovarse y a los 5 minutos se marca como fallido, con un mensaje claro, en vez de quedarse colgado.
  Los análisis nunca se reintentan solos.
- **Un líder.** El worker que tiene el candado de líder en PostgreSQL corre además las tareas periódicas (la vigilancia
  de avisos, la copia de NVD, los lotes). Los demás solo analizan. Si el líder muere, otro toma el candado.
- **Cachés, no estado.** Cada worker guarda las bases de los motores en su carpeta de datos (Trivy ~1,3 GB, Grype
  ~2,1 GB si analizas imágenes). En un worker nuevo se vuelven a descargar y pueden vivir en disco efímero.

Un worker es, por tanto, una unidad de **4 GB de memoria y 2 CPU**, y el rendimiento crece con el número de workers
para los análisis que se encolan de uno en uno: revisiones de PR, análisis que lanzas, importaciones desde CI. Los
lotes de una organización son la excepción (abajo).

## Añadir workers

### En la misma máquina

```bash
docker compose up -d --scale worker=3
```

Tres workers toman de la misma cola. Dimensiona el servidor para ello: cada worker necesita sus 4 GB (o 3 GB por
motor con el socket), además de la API y PostgreSQL (~400 MB en reposo). Un servidor de 16 GB corre tres con holgura.

### En otras máquinas

Un worker solo necesita llegar a PostgreSQL. Arranca la imagen del worker donde quieras con los mismos dos valores que
la API:

```bash
docker run -d --name pitangus-worker \
  -e PITANGUS_DATABASE_URL=postgresql://usuario:contraseña@db.interna:5432/pitangus \
  -e PITANGUS_MASTER_KEY='<la misma clave que la API>' \
  -v pitangus-worker-data:/data \
  ghcr.io/pitangus-dev/pitangus-worker:0.12
```

`ghcr.io/pitangus-dev/pitangus-worker` trae los motores dentro y los corre como procesos propios: esa máquina no
necesita el socket de Docker. La clave maestra es la que descifra la GitHub App y las credenciales de registros, así
que todo worker la necesita. Deja PostgreSQL en una red privada; los workers nunca tienen que ser accesibles desde
fuera.

### Kubernetes y plataformas de contenedores

Un Deployment para la API, otro para el worker, y tantas réplicas del worker como necesites. Las piezas, las cuatro
variables y las tareas periódicas están en [despliegue.md](despliegue.md#kubernetes). Para escalar según la carga, la
cola se ve en las métricas de abajo: `pitangus_jobs{status="queued"}` y `pitangus_jobs_oldest_queued_age_seconds` son
lo que debe mirar un autoescalador (el scaler de PostgreSQL de KEDA, o una regla sobre las métricas). Todavía no
publicamos manifiestos ni una configuración de autoescalado.

### Sin servidor: analizar en CI

Las revisiones de pull requests no tienen por qué pasar por el servidor. La [GitHub Action](cli.md#en-ci) y
`pitangus scan` corren los mismos motores dentro del runner de CI, desde la imagen del worker, y pueden enviar los
resultados a tu instancia (`import-sarif --server`). Cientos de repositorios revisados en cada PR gastan minutos de tu
CI, no de tu worker.

## Dimensionar

| Repositorios | Análisis al día (aprox.) | Workers | Memoria para los workers |
| --- | --- | --- | --- |
| hasta 30 | unas decenas | 1 | 4 GB |
| 30–150 | alrededor de cien | 2–3 | 8–12 GB |
| más | | uno más por cada ~70 repositorios, o analizar los PR en CI | +4 GB cada uno |

Un análisis completo de un repositorio típico tarda unos minutos; el primero de una imagen, más, mientras Trivy y
Grype descargan sus bases. Estas filas salen de cómo están limitados los motores, no de una medición publicada:
todavía no hemos medido cientos de repositorios bajo carga, y publicaremos las cifras cuando lo hagamos.

## Vigilar la cola

`GET /api/metrics` (con `PITANGUS_METRICS_TOKEN`, ver [despliegue-vps.md](despliegue-vps.md#monitorización)) expone lo
que importa: `pitangus_jobs{status}`, `pitangus_jobs_oldest_queued_age_seconds` (cuánto lleva esperando el análisis
más antiguo), `pitangus_jobs_failed_24h` y `pitangus_workers_alive`. Una cola que no deja de crecer pide más workers;
cero workers significa que nada se analiza.

## Qué no escala todavía

- **Varios análisis a la vez en un mismo worker.** Hoy es un análisis por worker. Está previsto correr varios con un
  presupuesto de memoria compartido, y dar prioridad a las revisiones de PR sobre los análisis completos.
- **Lotes de una organización.** Un lote («analizar toda esta organización») lo alimenta el líder de un repositorio
  en uno, y solo mientras la cola está vacía, así que avanza más o menos al ritmo de un solo worker por muchos que
  añadas. Los análisis encolados de uno en uno sí se reparten. Está previsto alimentar tantos como workers libres haya.
- **Manifiestos de autoescalado.** Las métricas están; los ejemplos de Kubernetes/KEDA, no.
- **Una medición publicada.** La tabla de dimensionado es derivada, no medida.
- **Pruebas dinámicas.** Los análisis nunca ejecutan ni atacan tus aplicaciones; ver
  [funcionalidades.md](funcionalidades.md#qué-cubre-pitangus-y-qué-no).
