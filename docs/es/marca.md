[English](../brand.md) · Español

# Marca

## Nombre

**Pitangus** es el *Pitangus sulphuratus*, el pájaro que en Colombia llamamos **bichofué**. Se queda quieto en su rama, vigila todo lo que se mueve y caza bichos de todo tipo, en el aire o en el suelo; es pequeño y aun así enfrenta a gavilanes mucho más grandes que él. Eso queremos ser para los equipos pequeños: vigilar cada cambio, atrapar lo que está mal y demostrar que ya no está.

La marca se escribe **Pitangus**; en texto en español también se puede decir «el bichofué». El nombre técnico también es `pitangus`: paquete, CLI, variables `PITANGUS_*`, imágenes, contenedor y estado de commit en GitHub. El repositorio de GitHub es `pitangus`, en la organización `pitangus-dev`. Pitangus está hecho en Colombia por **Arodium**.

## Mascota y logo

<img src="../assets/pitangus.svg" width="96" alt="Logo de Pitangus: la cabeza de un bichofué de perfil">

La cabeza del bichofué de perfil: el antifaz negro con la ceja blanca, el pico negro y el pecho amarillo azufre. Los archivos fuente son [`assets/pitangus.svg`](../assets/pitangus.svg) (la cabeza sola, para fondos claros) y `web/public/assets/pitangus-icon.svg` (la cabeza sobre una placa crema: el favicon y la marca en fondos oscuros, donde el negro se confundiría con el fondo). En el panel los dibuja `web/src/shared/ui/brand-mark.tsx`.

- Tamaño mínimo: 16 px (favicon). Por debajo de 24 px la ceja deja de leerse, pero la silueta se sigue reconociendo.
- No lo estires, no lo rotes ni le cambies los colores; en fondos oscuros usa siempre la placa crema.
- Junto al nombre: el logo a la izquierda y «Pitangus» en seminegrita, con una separación de un cuarto del lado del logo.

## Color

La paleta sale del pájaro: el amarillo azufre de su pecho, la tinta de su antifaz, el rufo de sus alas y el papel de las notas de campo. El amarillo es color de relleno, nunca de texto sobre fondo claro (no pasa el contraste); en fondo claro el acento para texto, enlaces y foco es el rufo.

| Token | Claro | Oscuro | Uso |
| --- | --- | --- | --- |
| `--primary` (azufre) | `#F2C230` con texto en tinta | `#F5CD4A` | botones principales y rellenos |
| `--brand` (acento) | rufo `#9C4A1E` | azufre `#F5CD4A` | enlaces, selección, foco, indicadores |
| Tinta | `#1C1A16` | — | texto en claro; el antifaz del logo |
| Papel / noche | `#FBF5E6` | `#16140F` · superficies `#211E16` | fondos |
| Crema | `#FFFDF5` · `#FFF8E8` | texto en oscuro | la placa y la ceja del logo |
| Reportes PDF | `#9C4A1E` sobre `#FBF5E6` | — | `pitangus/modules/reporting/design.py` |

Contraste del acento: rufo 5,7:1 sobre crema y azufre 12:1 sobre el fondo oscuro (WCAG AA para texto). El acento nunca colorea el texto de una severidad ni las series de los gráficos: esas tienen su propia paleta validada, y una severidad siempre se muestra con su etiqueta, nunca solo por color.

## Voz

Directa, sin miedo ni alarmismo: decimos qué pasa, por qué importa y cómo se arregla. En español: neutro latinoamericano, tuteo. En inglés: llano, segunda persona, voz activa. Cada idioma se escribe para sus lectores, no se traduce del otro (ver [`.claude/skills/pitangus-i18n/SKILL.md`](../../.claude/skills/pitangus-i18n/SKILL.md)).

- Titular: **«Vigila cada cambio. Demuestra cada corrección.»** (en inglés, **"Watch every change. Prove every fix."**).
- Lema: **«Detéctalo. Corrígelo. Demuéstralo.»** (en inglés, **"Spot it. Fix it. Prove it."**).

«Demostrar» quiere decir evidencia: el hallazgo ya no se reproduce cuando se repite el mismo análisis. No es una garantía de que no haya vulnerabilidades; dilo donde la promesa necesite matiz.
