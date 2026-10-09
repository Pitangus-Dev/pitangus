"""Panel structure: layers (lightweight FSD: app → pages → features → shared; a layer never imports from the ones above) and no native <select>."""

import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "web" / "src"
ORDER = ["app", "pages", "features", "shared"]  # top to bottom
IMPORT = re.compile(r"""from\s+['"]@/(?P<layer>[a-z]+)/""")
# The browser draws a native <select> with its own (white) list on Windows and in dark mode: use shared/ui/select.
NATIVE_SELECT = re.compile(r"<select\b")


class WebLayersTests(unittest.TestCase):
    def test_no_layer_imports_from_a_layer_above(self):
        violations = []
        for path in sorted(SRC.rglob("*.ts*")):
            parts = path.relative_to(SRC).parts
            if parts[0] not in ORDER:
                continue
            here = ORDER.index(parts[0])
            for match in IMPORT.finditer(path.read_text(encoding="utf-8")):
                target = match.group("layer")
                if target in ORDER and ORDER.index(target) < here:
                    violations.append(f"{path.relative_to(SRC)} importa de @/{target}")
        self.assertEqual(violations, [])

    def test_no_native_select(self):
        found = []
        for path in sorted(SRC.rglob("*.tsx")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if NATIVE_SELECT.search(line):
                    found.append(f"{path.relative_to(SRC)}:{number}")
        self.assertEqual(found, [], "Usa Select/SelectField de shared/ui en lugar de <select>:\n" + "\n".join(found))


if __name__ == "__main__":
    unittest.main()
