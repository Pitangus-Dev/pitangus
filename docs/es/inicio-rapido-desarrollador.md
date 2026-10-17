[English](../quickstart-developer.md) · Español

# Inicio rápido para un desarrollador

Solo necesitas Docker. No se instala nada, tu código no se ejecuta y nada sale de tu máquina. Las bases de avisos de
los motores quedan en el volumen `pitangus-cache`: solo el primer análisis las descarga.

**Analiza tu proyecto** (desde su carpeta):

```bash
docker run --rm -v "$PWD":/src:ro -v pitangus-cache:/data ghcr.io/pitangus-dev/pitangus-worker:0.15 python -m pitangus --data-dir /data scan /src
```

**Solo lo que añade tu cambio:** agrega `--base origin/main`. Lo que ya estaba no se te cobra.

**Arréglalo con tu propia IA:** agrega `--format prompt` y pega cada prompt en Claude, Cursor o Copilot. Lleva la regla,
el lugar, el código encontrado y la corrección, nunca el valor de un secreto.

**Antes de cada push**, con [pre-commit](https://pre-commit.com) (`pre-commit install --hook-type pre-push`). Analiza
lo que vas a subir, los commits tal como los guarda git, frente a lo que el remoto ya tiene: un archivo sin seguimiento
o un cambio sin commit nunca lo bloquea.

```yaml
repos:
  - repo: https://github.com/Pitangus-Dev/pitangus
    rev: v0.15.1          # la primera versión con el hook
    hooks:
      - id: pitangus
```

El hook analiza lo que vas a subir, no tu árbol de trabajo: los cambios ya commiteados frente a `origin/main`
(`PITANGUS_BASE` fija otra base), así que un archivo que no has commiteado, con seguimiento o sin él, no puede
bloquear el push. Una base que no existe detiene el hook con un mensaje que lo dice.
Ejecuta la imagen publicada del worker por su digest, nunca por una etiqueta que pueda moverse; si tienes
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) instalado, antes comprueba que la firmó el flujo
de publicación de Pitangus, igual que la GitHub Action, y si no, no la ejecuta.

**En cada pull request** (GitHub), en `.github/workflows/pitangus.yml`:

```yaml
on: pull_request
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: Pitangus-Dev/pitangus@v0.15.1   # fíjala al SHA del commit de la etiqueta
```

Códigos de salida: `0` pasa · `1` hallazgos en o por encima de `--fail-on` (alta por defecto) · `3` un motor no pudo
ejecutarse, que nunca se toma por limpio. Opciones, otros CI y un servidor para el equipo:
[Analizar desde la terminal y en CI](cli.md) · [Inicio rápido con el panel](inicio-rapido.md).
