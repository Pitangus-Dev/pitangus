[English](../brand.md) · Español

# Marca de Pitangus: nombre, logo, colores y voz

Cómo se ve y cómo habla Pitangus, para quien escriba sobre él, contribuya al panel o a los informes, o construya algo a
su lado. La fuente de verdad es el manual de identidad de
[`.claude/skills/pitangus-brand`](../../.claude/skills/pitangus-brand/SKILL.md): cada color con su único significado,
en claro y en oscuro ([`tokens.json`](../../.claude/skills/pitangus-brand/tokens.json)), tipografía, espaciado,
radios, componentes y lo que está prohibido. El panel aplica esos tokens en `web/src/index.css`, y los informes PDF y
Markdown en `pitangus/modules/reporting/design.py`. Si esta página y el manual no coinciden, manda el manual.

## Nombre

**Pitangus** es el *Pitangus sulphuratus*, el pájaro que en Colombia llamamos **bichofué**. Se queda quieto en su rama,
vigila todo lo que se mueve y caza bichos de todo tipo, en el aire o en el suelo; es pequeño y aun así enfrenta a
gavilanes mucho más grandes que él. Eso queremos ser para los equipos pequeños: vigilar cada cambio, atrapar lo que está
mal y demostrar que ya no está.

La marca se escribe **Pitangus**; en texto en español también se puede decir «el bichofué». El nombre técnico también es
`pitangus`: paquete, CLI, variables `PITANGUS_*`, imágenes, contenedor y estado de commit en GitHub. El repositorio de
GitHub es `pitangus`, en la organización `Pitangus-Dev`. Pitangus está hecho en Colombia por **Arodium**.

## Logo

<img src="../assets/pitangus.svg" width="96" alt="Logo de Pitangus: la cabeza de un bichofué de perfil">

La cabeza del bichofué de perfil: la corona y el antifaz negros, la ceja blanca, el pico negro y el pecho amarillo
azufre. Su contorno es tinta, así que tiene dos formas:

| Archivo | Uso |
| --- | --- |
| `web/public/assets/pitangus-logo.svg` (copia: [`assets/pitangus.svg`](../assets/pitangus.svg)) | La cabeza sola, **solo sobre fondos claros** (`bg`, `surface`). Sobre un fondo oscuro el contorno de tinta desaparece y la ceja queda flotando. |
| `web/public/assets/pitangus-icon.svg` (también `favicon.svg`) | La cabeza sobre su placa de piedra (`#F5F6F7`): el favicon, el avatar de la app y **cualquier fondo oscuro**. |

En el panel la marca la dibuja `web/src/shared/ui/brand-mark.tsx`; en la barra lateral va sobre su placa, arriba.

- Usa los archivos tal cual: no los redibujes, estires, rotes ni les cambies los colores.
- Tamaño mínimo: 24 px. El favicon es el único uso por debajo.
- Junto al nombre: el logo a la izquierda y «Pitangus» en IBM Plex Sans seminegrita.

## Color

Pitangus usa **neutros fríos**: una página de piedra fría (`bg`) y superficies blancas, nunca crema. Cada color
significa una sola cosa, y un color con dos papeles quiere decir que uno de ellos está mal.

### Neutros y marca

| Token | Claro | Oscuro | Uso |
| --- | --- | --- | --- |
| `bg` | `#F5F6F7` | `#111315` | Fondo de la página, piedra fría. |
| `surface` | `#FFFFFF` | `#181B1E` | Tablas, diálogos, menús, gráficos. |
| `sunken` | `#ECEEF1` | `#202428` | Campos, filas al pasar el cursor y seleccionadas, un chip seleccionado. |
| `line` | `#DADDE1` | `#2C3136` | Filetes: reglas de tablas, divisiones de secciones. |
| `ink` | `#16181B` | `#ECEEF0` | Texto y títulos; enlaces (subrayados). |
| `muted` | `#5C636B` | `#9AA1A9` | Leyendas, etiquetas, metadatos (≥ 4,5:1 en los dos temas). |
| `sulphur` | `#F2C230` | `#F2C230` | **Solo la marca y la acción principal**, con texto `on-sulphur` (`#16181B`). |
| `rufous` | `#9C4A1E` | `#C9764A` | El ala del bichofué: solo ilustración, nunca texto de la interfaz, enlaces ni foco. |
| `focus` | `#16181B` | `#F2C230` | Anillo de foco del teclado: 2px sólido con 2px de separación. |

**El azufre quiere decir «haz lo principal».** **Nuevo análisis** en la cabecera, la acción principal de un formulario o
diálogo y la llamada a la acción de un estado vacío van en azufre sólido, como mucho una por zona. Todo lo demás es un
botón con contorno o fantasma. El azufre nunca es un estado, una severidad, un botón pálido ni un tinte de selección.

### Estados

Cada estado tiene una familia de tres tokens: texto, fondo suave y borde. La severidad sale de ellos, siempre con su
palabra al lado, nunca solo por color.

| Familia | Texto en claro | Texto en oscuro | Significa |
| --- | --- | --- | --- |
| `critical` | `#B42318` | `#FF8B7B` | Fallo, errores, severidad Crítica y Alta, KEV. Crítica es un chip sólido con texto blanco. |
| `attention` | `#9E4708` | `#F5A35C` | Severidad Media, ejecuciones parciales, por vencer, configuración a medias. **Naranja, nunca amarillo.** |
| `ok` | `#1E7444` | `#5CC98A` | Completado, conectado, remediado, verificado. |
| `info` | `#2D5A87` | `#8DB4DD` | Severidad Baja, en curso, en cola, avisos neutros. |

Un aviso informativo es una fila sobre la superficie normal con el icono de estado en su color; solo un error que
bloquea la tarea lleva el fondo suave y el borde de `critical`. Los gráficos usan las mismas familias; una serie única
va en gris neutro. Todo se comprueba con contraste WCAG AA en los dos temas.

### La barra lateral: la corona del bichofué

La identidad vive en el marco de la app, no en los datos. La barra lateral es `chrome`, tinta casi negra en los dos
temas (`#16181B` en claro, `#0B0C0E` en oscuro), con texto claro y el elemento activo en azufre sobre un fondo
elevado. La cabecera y el contenido se quedan en `bg` y `surface`. Nada más del panel usa `chrome`.

## Tipografía

**IBM Plex Sans** para todo e **IBM Plex Mono** para el código, en el panel y en los informes (los informes PDF también
usan Source Serif 4 para títulos y texto corrido). El monoespaciado es solo para código, rutas, hosts, ids de regla,
CVE y versiones.

| Estilo | Tamaño / interlínea | Uso |
| --- | --- | --- |
| `page-title` | 24/30, seminegrita | El título de la página, una vez por vista. |
| `section-title` | 16/24, seminegrita | El título de una sección o un diálogo. |
| `body` | 14/22 | Texto por defecto y celdas de tablas. |
| `small` | 13/20 | La línea secundaria de una fila. |
| `caption` | 12/16 | Etiquetas de cifras, encabezados de columnas, pistas. En minúscula de oración, nunca en mayúsculas. |
| `code` | 13/20, mono | Solo código e identificadores. |

## Espacio, radios y sombras

- Espaciado en pasos de 4px: 24px entre secciones de una página, 16px dentro de tablas y diálogos.
- Radios: 4px para insignias y chips, 6px para botones, campos y menús, 8px para tablas, diálogos y gráficos. Nada más
  redondeado; totalmente redondo solo en puntos de estado, radios y interruptores.
- Sombras solo en lo que flota: menús y popovers, diálogos y la paleta de comandos. Las superficies planas no tienen.

Una página es estructura antes que cajas: título, una línea de descripción, barra de herramientas, contenido, a todo el
ancho y alineado a la izquierda. Tablas con borde fino, secciones separadas por una regla. Una tarjeta solo para un
gráfico o un objeto que se sostiene solo; nunca una tarjeta que envuelve la página ni una tarjeta dentro de otra.

## Iconos

Iconos [Phosphor](https://phosphoricons.com/) (MIT), peso regular, 16px (20px en la navegación), del color del texto que
acompañan, solo donde aportan significado. Un concepto, un icono: analizar siempre es `Scan`, nunca un icono de
«reproducir»; la IA nunca lleva destellos.

## Voz

Directa, sin miedo ni alarmismo: decimos qué pasa, por qué importa y cómo se arregla. En español: neutro
latinoamericano, tuteo. En inglés: llano, segunda persona, voz activa. Cada idioma se escribe para sus lectores, no se
traduce del otro (ver [`.claude/skills/pitangus-i18n/SKILL.md`](../../.claude/skills/pitangus-i18n/SKILL.md)).

- Frases cortas y verbos concretos («Añadir dominio», «Iniciar análisis»); un botón y su confirmación usan la misma
  palabra.
- Nombra lo que la gente reconoce (dominio, usuario de prueba, alcance), nunca nombres internos.
- Los errores dicen qué pasó y cómo seguir, sin disculpas.
- La corrección de un hallazgo es el texto de la propia herramienta más su guía de OWASP: Pitangus nunca inventa
  remediaciones.
- Los resultados negativos no prueban ausencia: di cuándo algo no se revisó («no probado», «cobertura parcial»).
- Sin emoji, sin exclamaciones, sin eslóganes dentro del panel.

Fuera del panel:

- Titular: **«Vigila cada cambio. Demuestra cada corrección.»** (en inglés, **"Watch every change. Prove every fix."**).
- Lema: **«Detéctalo. Corrígelo. Demuéstralo.»** (en inglés, **"Spot it. Fix it. Prove it."**).

«Demostrar» quiere decir evidencia: el hallazgo ya no se reproduce cuando se repite el mismo análisis. No es una
garantía de que no haya vulnerabilidades; dilo donde la promesa necesite matiz.

## Lo que no se hace

Botones amarillo pálido; amarillo para cualquier estado; cajas de aviso pastel completas; iconos de «reproducir» para
analizar; tarjetas que envuelven una página o que van dentro de otra; rejillas de tarjetas idénticas con icono, título y
viñetas; radios de más de 8px; botones negros sólidos; etiquetas en mayúsculas espaciadas; etiquetas en monoespaciado;
«→» al final de un texto; degradados; desenfoques; iconos de destellos; fondos crema.
