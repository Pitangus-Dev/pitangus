---
name: pitangus-design
description: Pitangus's design rules for the panel (web/src), the PDF/Markdown reports and the threat diagram. Use ALWAYS before creating or changing a view, a component, a report, an export or the diagram, and when reviewing a diff that touches any of them.
---

# Pitangus design

Three surfaces, one set of ideas: **conclusion first, detail after; group by action; tokens only; accessible (WCAG 2.2 AA); no unescaped text.**
If a rule conflicts with what the user asks for, ask; never break it silently.

## 1. Panel (web/src)

The identity manual, `.claude/skills/pitangus-brand` (SKILL.md, `tokens.json`, `components/*.md`, `reference.css`), is
the source of truth; read it first. This section is how the panel implements it.

- **Tokens only**, from `web/src/index.css`, which carries the manual's light and dark values. Never raw Tailwind palette
  classes (`bg-red-500`) or hex values; `tests/test_ui_tokens.py` enforces it. Panel name → manual token:
  - Neutrals: `bg-app`/`background` = `bg` (cool stone, never cream); `bg-panel`/`card`/`popover` = `surface`;
    `bg-inset`/`bg-app-soft`/`muted`/`secondary`/`accent` = `sunken` (inputs' hover, hover rows, the selected row or chip);
    `border-app-line`/`border` = `line` (hairlines); `border-input`/`app-faint` = `line-strong` (borders that identify a
    control, ≥ 3:1; never text); `text-app-fg` = `ink`, `text-app-secondary` = `ink-2`, `text-app-muted`/`app-subtle` = `muted`.
  - Brand: `bg-sulphur` + `text-on-sulphur` (the primary button); `sulphur-soft`/`sulphur-line` only highlight searched text
    (`<mark>`). `brand` is ink (links, active item, checked controls); `focus` is ink on light and sulphur on dark.
    Rufous only in the logo.
  - States, one meaning each (text · `-soft` ground · `-line` border): `danger` = critical (failure, error, Alta, KEV;
    `danger-solid` + `on-solid` only for the Crítica chip and a destructive confirm); `attention` = orange (Media, partial,
    due soon, half-done setup; **never yellow**: there is no `warning` token any more, and `tests/test_ui_tokens.py`
    bans `*-warning` classes); `success` = ok (completed, connected, fixed, verified); `info` = slate blue (Baja, running,
    queued, neutral notices).
  - Severity: `SEVERITY_CLASS`/`severityClass` from `shared/ui/severity.ts`, always with its word: Crítica solid critical
    with white text, Alta critical, Media attention, Baja info, Info muted outline. States as outline badges: `STATE_CLASS`.
  - Charts: `--sev-*` from those tokens (the Crítica series differs from the chip: deepened towards ink in light, a brighter red in dark, so it
    differs from Alta and keeps 3:1), a single series in `--chart-neutral`, "fixed" in `--series-fixed` (ok), grid `--grid-line`
    (chart-grid), the activity ramp `--seq-1…5` (chart-neutral over surface). No decorative blues or purples; text never
    takes a series colour.
- **Buttons** (`shared/ui/button-variants.ts`): `default` = solid sulphur, for doing the main thing: the header's "New
  scan", a form's or dialog's primary action, an empty state's call to action; at most one per zone (header, content,
  dialog). Everything else `outline` (surface + line-strong) or `ghost`; `destructive` is critical text on surface. No
  pale-yellow buttons, no solid black buttons, no colour overrides through `className` (the one exception: the
  confirm dialog's destructive action, solid `danger-solid` with white text, as the manual's critical-solid says). No "→" or arrow icon appended
  to a label.
- **Notices** (`shared/ui/notice.tsx`): a row on the surface with the status icon in its family colour and the text in
  ink. Only an error that blocks the task is `blocking` (critical-soft + critical-line). No pastel boxes for information.
- **Icons**: Phosphor (`@phosphor-icons/react`, the `…Icon` names), regular weight, 16 px (20 px in the navigation),
  hidden from assistive technology by default (`IconContext` in `app/providers.tsx`; a labelled one sets
  `aria-hidden={false}` and `role="img"`). One concept, one icon, from the manual's table (new scan = `ScanIcon`, never a
  play icon). `lucide-react` is banned by the tests.
- **Logo**: `BrandMark` shows `pitangus-logo.svg` on light grounds and `pitangus-icon.svg` (its stone tile) on dark; the
  panel never puts cream or a tinted box around it.
- **Contrast**: text ≥ 4.5:1 on bg, surface and sunken; control borders and focus ≥ 3:1, in both themes. If you add or
  change a token, compute it for both themes.
- **Visible focus** on every control (global `:focus-visible`, 2 px `--focus`, 2 px offset; text fields draw it inside;
  underlined tabs use the underline). Never remove it with `outline-none` without an alternative.
- **Type**: IBM Plex Sans / Plex Mono (the same as the PDFs). Mono only for code, paths, hosts, rule ids, CVEs, versions
  and digests; figures use `tabular-nums`, never mono; no mono or uppercase letter-spaced labels, no decorative
  numbering. Page titles `text-2xl` once, one short line of description; captions in sentence case.
- **Motion**: only in response to an action, ≤ 150 ms, behind `motion-safe:`; `prefers-reduced-motion` turns it off.
- **Sizes**: text ≥ 11 px; click targets ≥ 24 px (`min-h-6`, `size-6`).
- **Semantics and ARIA**: `aria-pressed` (toggles), `aria-expanded`, `aria-current`, `role="radiogroup"`/`radio` with `aria-checked`, `role="status"`/`alert`/`progressbar`; every input has its `<label htmlFor>`; `CardTitle` is a real heading. ARIA labels are user-facing text: they come from the i18n catalogs (`.claude/skills/pitangus-i18n/SKILL.md`), in English and Spanish.
- **Loading**: skeletons shaped like the content (`Bone`, `SkeletonList`, `SkeletonTable`, `SkeletonTiles`, `SkeletonCard` from `shared/ui/loading.tsx`), announced once ("Loading…"). Never show a fake empty state while loading.
- **Hick's law**: one primary action, the rest in a menu (`shared/ui/menu.tsx`); grouped navigation; advanced options behind "More options"/"More filters". Forms have defaults: the user can generate without touching anything.
- **Long lists**: server-side pagination or search; never load everything.
- **Structure before boxes** (the default shadcn look reads as AI-made; `tests/test_ui_tokens.py` enforces the mechanical part):
  - Radii: badges and chips 4 px (`rounded-sm`), controls 6 px (`rounded-md`/`rounded-lg`), tables, dialogs and charts
    8 px (`rounded-xl`). Nothing rounder; `rounded-full` only for status dots, radios and switches.
  - A page is title, one line, toolbar, content, full width and left-aligned. Tables with a hairline, sections divided
    by a line, key figures in one ruled row (`KeyFigures`/`KeyFigure`). A card (surface + line + 8 px) only for a chart
    or a self-contained object; never a card wrapping the page, a card inside a card, or a grid of identical
    icon+title+bullets cards. Prefer a secondary line or columns to long "A · B · C" strings.
  - Selection is an ink border on sunken (`border-app-fg bg-app-soft`), never a brand tint.
  - No sparkle icons, no icon inside a tinted box, no gradients, no `backdrop-blur`, no `tracking-[…]`.
  - Floating surfaces: hairline border plus `shadow-md` (= `shadow-float`); dialogs and the palette `shadow-lg`
    (= `shadow-dialog`); flat surfaces have no shadow.

## 2. Reports (PDF and Markdown)

Every PDF is built with `pitangus/modules/reporting/design.py` (tokens, fonts, `cover`, `meta`, `kpis`, `chip`, `table`,
`h2`, `build`, `wide_page`). Do not create your own styles, colors or fonts.

**Look** (the "consultancy dossier" direction the user chose): Source Serif 4 for titles and prose, IBM Plex Sans for
labels and tables, IBM Plex Mono for IDs, paths and code, embedded from `reporting/assets/` (SIL OFL, licenses next to the
files). White page, the manual's palette in `design.py` (cool neutrals; ink as the accent, `BRAND`; sulphur only in the
cover's short rule; rufous only in the logo), ruled tables (a strong rule on top, hairlines between rows, no fills or
zebra), key figures in one ruled row (no cards), severity as coloured text from the same state colours as the panel
(Crítica deep red, Alta critical, Media attention orange, Baja info). Named greys and `CODE_BG` live in `design.py`: no
hex values in a report module.

**Structure, in this order:**
1. **Cover** with `cover(kind, title, subtitle, fields, note)`: what the report is, about which system, and `fields`
   (date, revision, reference — identifiers whole, in mono). Every page after it has the running header (subject and
   «Confidential») and the footer (version · reference · «page N of M»).
2. **Executive summary**: two or three sentences a person would write (what needs attention now, how much there is,
   what wasn't analyzed), then the key figures (`kpis`, four reads best, at most six).
3. **What to do first** (≤ 15 rows): ID, severity and the action in one sentence, with what and where underneath.
   Every action gets a per-report ID, `PIT-001`…, reused in every table and sheet of the document.
4. The body grouped **by action**, not by advisory:
   - dependencies: one row per package (manifest + version) with the version that closes all its advisories → `remediation.fix_groups` and `remediation.action`;
   - rule-based threats: one row per pattern with the affected components (`threat_report.digest`);
   - code: one **sheet** per critical or high finding (ID and severity, title, facts table, what happens, how to fix it
     with before over after at full width, how to verify it, references); medium and low in a table.
5. **About this report** (a numbered section, before the appendices): method and **coverage — say what was not
   analyzed** ("this is not the same as 'no findings'"), limitations, data sources and the closing notice (automated
   technical evidence, human review required, not a certification). Never present an incomplete analysis as clean.
6. Compact appendices (`h2(…, number=False)`; one row per item, no long descriptions), with a cap; the full data stays
   in JSON/SARIF/the panel. Signatures (`signoff`) only on audit reports.

**Form rules:**
- Severity with `chip` (coloured text, `SEVERITY_INK`, each ≥ 4.5:1 on white). KEV and malicious packages flagged in red next to the finding.
- Short cells: action with `action(entry, short=True)`; lists with `listing(items, n)` ("a, b and 4 more").
- All text coming from a repository, a model or a form goes through `t()` (escapes and truncates). In Markdown, escape `|` inside cells.
- Section titles with `h2()`: `build()` numbers them in reading order (appendices and sign-off pass `number=False`) and
  keeps `h2`, `h3` and `h4` from being orphaned. No `keepWithNext` on large tables. Code samples keep hard spaces and are
  broken into lines that fit the block (`technical._code`).
- Tone: concrete, no overstatement (never "exploitable" without proof; an indicator is a signal, not a confirmation). Wording in the reader's language through the i18n catalogs, English and Spanish.
- Rough budget: a single-repository technical report ≤ 15 pages without appendix; a threat model ≤ 15. If you exceed it, group more or move content to an appendix.
- **Exception: audit evidence** (SOC 2, ISO, consolidated). The reader is an auditor: scope, controls and method come before the
  findings, with no "What to do first"; the grouped findings table is the evidence and is complete; detail is capped (`DETAIL_LIMIT`).
- Coverage: use `coverage_gaps(steps)` (partial, not run, inconclusive, failed). Say "all engines completed" only if every step
  is `completed`. For threats, say whether indicators were searched (components with a linked repository).

## 3. Threat diagram

- Placement: `pitangus/modules/threats/diagram.py` and `web/src/features/threats/threat-layout.ts` are **the same algorithm**; if you change one, change the other. `tests/test_threat_layout_parity.py` checks it.
- Columns follow the data path (distance from the actors), one block per boundary without overlaps, reordered by neighbors, 8 px grid, stacks ≤ 5.
- Colors: the token palette (`COLORS` in Python, `threat-colors.ts` in the panel): `neutral, brand, info, success, warning, attention, danger`. These are categories for grouping components, not states; `brand` is the diagram's purple and `warning` its ochre (`tone-purple`, `tone-ochre`), the only places those hues appear. If none is chosen, use the component role's color; always with a legend. Never free-form hex from the user.
- Shapes: process rounded, data store between two lines, third party dashed. Unencrypted flow: dashed red.
- Short labels: "n · PROTOCOL" (e.g. `3 · HTTPS`). What travels goes in the report's flow table under the same number.
- The SVG and the PDF come from the same `scene()`: never draw in one what is not in the other.

## How to verify before calling it done

1. `make test` (includes `test_ui_tokens`, `test_report_design`, `test_threat_layout_parity`) and `cd web && pnpm exec tsc -b && pnpm exec oxlint src`.
2. **Look at it**: generate the PDF with real data (`data/runs/*/run.json`) and convert it with `pdftoppm -r 60 -png`; the SVG with `rsvg-convert`; the panel with a temporary preview page (delete it afterwards). Check pages, gaps, clipped text and contrast.
3. Compare pages before/after whenever you change a report.

To review a diff against these rules, use the `design-reviewer` agent.
