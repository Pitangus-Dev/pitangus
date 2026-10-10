---
name: pitangus-brand
description: Pitangus's identity manual (colors with one meaning each, light and dark tokens, type, spacing, radii, components, voice, prohibitions). Read it ALWAYS before creating or changing anything visual in the panel, reports, docs site or landing, and before reviewing such a diff. It is the source of truth; pitangus-design applies it to each surface.
---

# Pitangus · identity manual

Source of truth for how Pitangus looks and speaks. The same manual is published for people as a Design System
artifact (https://claude.ai/artifact/Ky9X1xsABVxqLnZ9SqNb9E); when the two differ, update both in the same change.

- `tokens.json`: every color (light and dark, with its one usage), type style, spacing, radius and shadow.
- `components/*.md`: when to use each component and what it looks like; `components/reference.css` shows the exact
  treatment with the tokens.
- The panel implements these tokens in `web/src/index.css`; reports in `pitangus/modules/reporting/design.py`.

Pitangus is a self-hosted application security tool: it analyses code, images and sites, and proves what it finds. Its identity comes from the great kiskadee (*Pitangus sulphuratus*): **sulphur** belly, **black** crown, **white** brow, **rufous** wing. The panel is a working instrument, not a landing page: it reads fast, every color means one thing, nothing is decoration.

## Principles

1. **One color, one meaning.** `sulphur` is the brand and the primary action, nothing else. States have their own families (`critical`, `attention`, `ok`, `info`) and severity is drawn from them. A color in two roles means one of them is wrong.
2. **One solid yellow per view.** The page's primary action is `sulphur`. Always-present actions (the header's "New scan") and an empty state's call to action use the **brand-quiet** button (`sulphur-soft` + `sulphur-line`). Everything else is outline or ghost. No solid black buttons.
3. **Structure before boxes.** A page is: title, one line of description, toolbar, content. Tables with a hairline border, sections split by a rule, key figures in one ruled row. A card (`surface` + `line` + `radius-lg`) only for a chart or a self-contained object. Never a card wrapping the page, never a card inside a card.
4. **Full width, left aligned.** Content uses the main area's width and aligns with the header. Only running text is capped (~70 characters); tables and lists are not.
5. **Cool neutrals, not cream.** `bg` cool stone, `surface` white. Cream with a terracotta accent is the "AI default" look; Pitangus does not use it.
6. **Content decides the form.** Monospace only for code, paths, hosts, rule ids, CVEs and versions. No letter-spaced uppercase labels, no decorative numbering (01 / 02), no "→" appended to text.

## Color

- Text: `ink` on `bg`, `surface`, `sunken`; `ink-2` secondary; `muted` for labels and metadata. All ≥ 4.5:1 in both themes.
- Brand: `sulphur` with `on-sulphur` text. `rufous` only in the logo and illustrations.
- Selection (row, chip, option): `ink` border on `sunken`. Never a brand tint.
- Focus: `focus`, 2px solid with 2px offset (ink on light, sulphur on dark). Text fields: 2px inner border. Underlined tabs: the underline itself.
- Links: `ink`, underlined.
- States (text · background · border):
  - `critical` · `critical-soft` · `critical-line`: failure, error, High severity, KEV.
  - `attention` · `attention-soft` · `attention-line`: Medium severity, partial, due soon, half-done setup. **Orange, never yellow.**
  - `ok` · `ok-soft` · `ok-line`: completed, connected, fixed, verified.
  - `info` · `info-soft` · `info-line`: Low severity, running, queued, neutral notices.
- Severity: Critical = solid `sev-critical` chip with white text; High `sev-high`; Medium `sev-medium`; Low `sev-low`; Info `sev-info` outline. Always with its word, never color alone.
- Charts: severity series from the same tokens; a single series in `chart-neutral`; "fixed" in `chart-fixed`; grid `chart-grid`. No decorative blues or purples.

## Type

IBM Plex Sans for everything, IBM Plex Mono for code: the same family as the PDF reports. Styles: `page-title` 24/30 (the page h1, once), `section-title` 16/24, `body` 14/22, `body-strong`, `small` 13/20 (a row's secondary line), `caption` 12/16 (figure labels, table headers, hints; sentence case), `figure` 24/28 tabular, `code` 13/20 mono only.

## Space, radii, shadows

Spacing in 4px steps (`space-1` … `space-8`): `space-6` between page sections, `space-4` inside tables and dialogs. Radii: `radius-sm` 4px (badges, chips), `radius-md` 6px (buttons, fields, menus), `radius-lg` 8px (tables, dialogs, charts); nothing rounder; fully round only for status dots, radios and switches. Shadows: `shadow-float` for menus and popovers, `shadow-dialog` for dialogs and the palette; flat surfaces have none.

## Content and voice

Spanish uses "tú"; short sentences, concrete verbs ("Añadir dominio", "Iniciar análisis"); a button and its confirmation use the same word. Name what people recognize (domain, test user, scope), never internal names. Errors say what happened and how to continue, no apologies. An empty state invites one action. A finding's fix is the tool's own text plus its linked OWASP guidance: Pitangus never invents remediation. Negative results don't prove absence: say when something was not checked ("not tested", "partial coverage"). No emoji, no exclamations, no slogans inside the panel.

## Iconography

Lucide at 16px, in the color of the text beside it, only where it carries meaning (navigation, file type, status). Never inside a tinted circle or box, never a sparkle icon for "AI". Logos: `pitangus-logo.svg` on light grounds, `pitangus-icon.svg` (with its tile) on dark grounds (`web/public/assets/`), used as is, never redrawn.

## Motion

Only in response to an action (open, expand, confirm), short (≤150ms) and behind `prefers-reduced-motion`. No per-section entrance animations.

## Prohibited

Cards wrapping a page; cards inside cards; grids of identical icon+title+bullets cards; radii above 8px; yellow for states; solid black buttons; letter-spaced uppercase labels; monospace labels; "→" at the end of text; gradients; blurs; sparkle icons; cream grounds.
