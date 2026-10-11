"""The panel only uses color tokens: no stray Tailwind color or hex value in the components.

The tokens (`text-danger`, `bg-attention-soft`, `border-info-line`…) have their light and dark values
in `web/src/index.css`, with WCAG AA contrast checked. A stray color bypasses that guarantee.
"""

import json
import re
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "web" / "src"
PALETTE = ("slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|"
           "violet|purple|fuchsia|pink|rose")
RAW = re.compile(rf"(?<![\w-])(?:[a-z0-9\[\]&=_.-]+:)*(?:text|bg|border|ring|fill|stroke|decoration|outline|divide|from|to|via|"
                 rf"shadow|accent|placeholder|caret)-(?:(?:{PALETTE})-\d{{2,3}}|white|black)(?:/\d+)?(?![\w-])")
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
# The logo is an illustration with its own colors, not part of the interface.
EXEMPT = {"brand-mark.tsx"}


class TokenTests(unittest.TestCase):
    def test_components_use_only_color_tokens(self):
        found = []
        for path in sorted(SOURCE.rglob("*.ts*")):
            if path.name in EXEMPT:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for match in (*RAW.finditer(line), *HEX.finditer(line)):
                    found.append(f"{path.relative_to(SOURCE)}:{number} {match.group(0)}")
        self.assertEqual(found, [], "Usa los tokens de web/src/index.css en lugar de colores sueltos:\n" + "\n".join(found[:40]))

    def test_components_avoid_the_template_look(self):
        # The default shadcn look (pill-shaped boxes, mono eyebrows, glows) reads as AI-made: see pitangus-design §1.
        banned = re.compile(r"(?<![\w-])(?:[a-z0-9\[\]&=_.-]+:)*(?:rounded-(?:2xl|3xl|4xl)|tracking-\[[^\]]+\]|shadow-(?:xl|2xl)|"
                            r"bg-brand/\[0\.0\d\]|backdrop-blur(?:-\w+)?)(?![\w-])|\bSparkles\b")
        found = []
        for path in sorted(SOURCE.rglob("*.tsx")):
            if ".test." in path.name or path.name in EXEMPT:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                found += [f"{path.relative_to(SOURCE)}:{number} {match.group(0)}" for match in banned.finditer(line)]
        self.assertEqual(found, [], "Evita el aspecto de plantilla (pitangus-design §1):\n" + "\n".join(found[:40]))

    def test_components_follow_the_identity_manual(self):
        # .claude/skills/pitangus-brand: one meaning per colour, Phosphor icons, no pale-yellow buttons, no yellow states.
        rules = (
            (re.compile(r"from ['\"]lucide-react['\"]"), "icons come from @phosphor-icons/react"),
            # There is no yellow state: "warning" was folded into "attention" (orange).
            (re.compile(r"(?<![\w-])(?:[a-z0-9\[\]&=_.-]+:)*(?:text|bg|border|fill|stroke|decoration)-warning(?:-soft|-line)?(?![\w-])"),
             "use the attention family (orange), never a yellow warning"),
            # sulphur-soft only highlights searched text (<mark>); never a button or a box.
            (re.compile(r"(?<![\w-])(?:[a-z0-9\[\]&=_.-]+:)*(?:bg|border)-sulphur-(?:soft|line)(?![\w-])(?![^<]*</mark>)"),
             "sulphur-soft/sulphur-line only on <mark>"),
            (re.compile(r"variant=[\"']brand[\"']|\bbrand:\s*\"border-sulphur"), "no pale-yellow 'brand' button: primary or outline"),
            # Monospace is for code, paths, hosts, ids, CVEs and versions: never for figures, step numbers or labels.
            (re.compile(r"[\"'`][^\"'`]*\bfont-mono\b[^\"'`]*\b(?:tabular-nums|uppercase|tracking-\w+|rounded-full)\b[^\"'`]*[\"'`]|"
                        r"[\"'`][^\"'`]*\b(?:tabular-nums|uppercase|tracking-\w+|rounded-full)\b[^\"'`]*\bfont-mono\b[^\"'`]*[\"'`]"),
             "no monospace on figures, step numbers or labels"),
        )
        found = []
        for path in sorted(SOURCE.rglob("*.ts*")):
            if ".test." in path.name or path.name in EXEMPT or "shared/api" in path.as_posix():
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                found += [f"{path.relative_to(SOURCE)}:{number} {why}: {match.group(0)[:80]}"
                          for pattern, why in rules for match in pattern.finditer(line)
                          if not (why.startswith("no monospace") and "tracking-widest" in match.group(0) and "<Input" in line)]
        self.assertEqual(found, [], "Sigue el manual de identidad (.claude/skills/pitangus-brand):\n" + "\n".join(found[:40]))

    def test_copy_has_no_trailing_arrow(self):
        # "Continue →", "See all →": the manual bans an arrow appended to a label (an arrow inside a path, "A → B", is fine).
        found = []

        def walk(file, node, key=""):
            if isinstance(node, dict):
                for name, value in node.items():
                    walk(file, value, f"{key}.{name}" if key else name)
            elif isinstance(node, str) and re.search(r"(?:→|->)\s*$", node):
                found.append(f"{file}:{key} {node[-40:]}")

        for root in (SOURCE / "shared" / "i18n" / "locales", SOURCE.parents[1] / "pitangus" / "shared" / "i18n" / "locales"):
            for path in sorted(root.rglob("*.json")):
                walk(path.name, json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(found, [], "Sin «→» al final de los textos:\n" + "\n".join(found[:40]))


if __name__ == "__main__":
    unittest.main()
