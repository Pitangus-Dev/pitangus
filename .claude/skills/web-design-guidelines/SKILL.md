---
name: web-design-guidelines
description: Review panel UI code (web/src) against Vercel's Web Interface Guidelines (accessibility, focus, forms, typography, content, dark mode, i18n, anti-patterns). Use when asked to review UI, check accessibility, audit design or UX, and before committing panel changes together with pitangus-design.
metadata:
  author: vercel (adapted for Pitangus)
  source: https://github.com/vercel-labs/web-interface-guidelines
  pinned_commit: 434b7f91364665f2f733b310ec54809bf8f37937
---

# Web Interface Guidelines (pinned copy)

Review the given files (or the current diff under `web/src`) against every rule in `guidelines.md` next to this file, and report findings in the format that file defines (`file:line`, terse).

This is a pinned snapshot (commit `434b7f91364665f2f733b310ec54809bf8f37937`, MIT, © Vercel Labs). Unlike the upstream skill it does **not** fetch the rules at run time: instructions that change remotely are a supply-chain risk. To update, diff upstream `command.md` against `guidelines.md`, review it, and bump `pinned_commit`.

Pitangus' own rules win where they differ: `.claude/skills/pitangus-brand` (identity) and `.claude/skills/pitangus-design` (panel, reports, diagram).
