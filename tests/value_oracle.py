"""The fragment oracle the masking and rendering property tests share: a value leaks if any fragment of it shows, not
only if the whole of it does."""

import re

from pitangus.shared import render


def fragments(value: str, template: str = "") -> set[str]:
    """The runs of four or more letters and digits of `value` the renderer wouldn't keep (render.kept), but those that
    are also in the text around it."""
    return {run for run in re.findall(r"[^\W_]{4,}", value) if not render.kept(run) and run not in template}


def leaked(value: str, shown: str, template: str = "", *, numbers: int = 4) -> list[str]:
    """The fragments of `value` (`fragments`) that `shown` holds as a run of its own (not inside a longer word).
    `numbers`: how long a run of digits alone must be to count (an output with dates and counts of its own holds short
    numbers anyway)."""
    return sorted(run for run in fragments(value, template) if not (run.isdigit() and len(run) < numbers)
                  and re.search(rf"(?<![^\W_]){re.escape(run)}(?![^\W_])", shown))
