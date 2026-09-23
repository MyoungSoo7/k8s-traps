"""Regenerate docs/traps.md from the catalog in src/k8s_traps/traps.py."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))
from k8s_traps.traps import TRAPS  # noqa: E402

lines = ["# Trap catalog", "",
         "Generated from `src/k8s_traps/traps.py` by `scripts/gen_docs.py` — edit the source, not this file.", ""]
for t in TRAPS.values():
    lines += [f'<a id="{t.id.lower()}"></a>', f"## {t.id} — {t.title}", "",
              f"**Default severity:** {t.severity}", "", t.summary, "",
              f"**Where it came from.** {t.incident}", "", f"**Fix.** {t.fix}", ""]
out = pathlib.Path(__file__).parent.parent / "docs" / "traps.md"
out.write_text("\n".join(lines))
print(f"wrote {out}")
