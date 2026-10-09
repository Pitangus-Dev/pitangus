English · [Español](es/escalar.md)

# Scaling: more repositories, more workers

Pitangus is one codebase, but its three pieces scale apart: the **API and panel** keep no state of their own, the
**worker** is where scans run, and **PostgreSQL** holds everything, the scan queue included. Adding capacity means
adding workers; nothing else changes. This page says what one worker does, how to add more, where to run scans
without a server at all, and what doesn't scale yet.

## What one worker does

- **One scan at a time.** A worker claims one job from the queue, runs it to the end, then claims the next. Inside a
  scan, the engines run one after another, each with its own ceiling: 3 GB of memory and 2 CPUs when the worker
  starts them through the Docker socket; the worker's own ceiling (`PITANGUS_WORKER_MEMORY`, 4 GB in
  [`deploy/compose.yaml`](../deploy/compose.yaml)) when they run inside its image.
- **A durable queue.** Scans are rows in the `jobs` table. Workers claim them with `FOR UPDATE SKIP LOCKED`, so two
  workers never take the same one. A running job is renewed every few seconds; if its worker dies, the job stops being
  renewed and is marked failed after 5 minutes, with a clear message, instead of hanging forever. Scans are never
  retried on their own.
- **One leader.** Whichever worker holds the leader lock in PostgreSQL also runs the periodic tasks (the advisory watch,
  the NVD copy, batches). The others only scan. If the leader dies, another worker takes the lock.
- **Caches, not state.** Each worker keeps its engine databases under its data folder (Trivy ~1.3 GB, Grype ~2.1 GB
  if you scan container images). They download again on a fresh worker and can live on ephemeral disk.

So a worker is a unit of **4 GB of memory and 2 CPUs**, and throughput grows with the number of workers for scans
queued one by one: PR reviews, scans you launch, CI imports. Organization batches are the exception (below).

## Adding workers

### On the same machine

```bash
docker compose up -d --scale worker=3
```

Three workers claim from the same queue. Size the host for it: each worker needs its 4 GB (or 3 GB per engine with
the socket), on top of the API and PostgreSQL (~400 MB at rest). A server with 16 GB runs three comfortably.

### On other machines

A worker only needs to reach PostgreSQL. Run the worker image anywhere with the same two values as the API:

```bash
docker run -d --name pitangus-worker \
  -e PITANGUS_DATABASE_URL=postgresql://user:password@db.internal:5432/pitangus \
  -e PITANGUS_MASTER_KEY='<the same key as the API>' \
  -v pitangus-worker-data:/data \
  ghcr.io/pitangus-dev/pitangus-worker:0.12
```

`ghcr.io/pitangus-dev/pitangus-worker` carries the engines and runs them as its own processes: no Docker socket on
that machine. The master key is what decrypts the GitHub App and the registry credentials, so every worker needs it.
Keep PostgreSQL on a private network; workers never need to be reachable from outside.

### Kubernetes and container platforms

One Deployment for the API, one for the worker, replicas on the worker as you need them. The pieces, the four
variables and the periodic tasks are in [deploy.md](deploy.md#kubernetes). To scale on demand, the queue is visible
through the metrics below: `pitangus_jobs{status="queued"}` and `pitangus_jobs_oldest_queued_age_seconds` are what an
autoscaler (KEDA's PostgreSQL scaler, or a rule on the metrics) should watch. We don't ship manifests or an autoscaler
configuration yet.

### No server at all: scan in CI

Pull request reviews don't have to touch the server. The [GitHub Action](cli.md#in-ci) and `pitangus scan` run the
same engines inside the CI runner, from the worker image, and can push the results to your instance
(`import-sarif --server`). Hundreds of repositories reviewed on every PR cost your CI minutes, not your worker's.

## Sizing

| Repositories | Scans a day (rough) | Workers | Memory for the workers |
| --- | --- | --- | --- |
| up to 30 | a few dozen | 1 | 4 GB |
| 30–150 | a hundred or so | 2–3 | 8–12 GB |
| more | | one more per ~70 repositories, or scan PRs in CI | +4 GB each |

A full scan of a typical repository takes a few minutes; the first scan of an image, longer, while Trivy and Grype
download their databases. These rows come from how the engines are capped, not from a published benchmark: we
haven't measured hundreds of repositories under load yet, and we'll publish the numbers when we do.

## Watching the queue

`GET /api/metrics` (with `PITANGUS_METRICS_TOKEN`, see [deploy-vps.md](deploy-vps.md#monitoring)) exposes what
matters: `pitangus_jobs{status}`, `pitangus_jobs_oldest_queued_age_seconds` (how long the oldest scan has waited),
`pitangus_jobs_failed_24h` and `pitangus_workers_alive`. A queue that keeps growing means more workers; a worker count
of zero means nothing gets scanned.

## What doesn't scale yet

- **Parallel scans inside one worker.** Today it is one scan per worker. Running several with a shared memory budget
  is planned, as is giving pull request reviews priority over full scans.
- **Organization batches.** A batch ("scan this whole organization") is fed by the leader one repository at a
  time, and only while the queue is empty, so it advances at roughly one worker's pace however many you add. Scans
  queued one by one do spread across workers. Feeding as many as there are free workers is planned.
- **Autoscaling manifests.** The metrics are there; the Kubernetes/KEDA examples aren't.
- **A measured benchmark.** The sizing table is derived, not measured.
- **Dynamic testing.** Scans never run or attack your applications; see [features.md](features.md#what-pitangus-covers-and-what-it-doesnt).
