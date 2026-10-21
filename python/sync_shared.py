"""Слияние общих файлов фильтров перед push (blacklist.json, whitelist.json).

Эти файлы общие для всех convert-* workflow. Каждый workflow меняет только секцию
своего протокола, поэтому вместо git-merge (который конфликтует на строке "updated")
берём актуальную версию из origin/main и подменяем в ней только свою секцию.

Использование: python sync_shared.py <протокол> <каталог_с_нашими_файлами>
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SHARED = {
    "python/src/filters/blacklist.json": "blacklist",
    "python/src/filters/whitelist.json": "whitelist",
}


def merge(proto: str, ours_dir: Path, repo: Path = Path(".")) -> None:
    for rel, section in SHARED.items():
        ours_file = ours_dir / rel
        if not ours_file.exists():
            continue
        ours = json.loads(ours_file.read_text(encoding="utf-8"))
        target = repo / rel
        merged = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {section: {}}
        merged.setdefault(section, {})
        if ours.get(section, {}).get(proto) == merged[section].get(proto):
            continue  # наша секция не изменилась — файл остаётся как в origin/main
        merged[section][proto] = ours.get(section, {}).get(proto, [])
        merged["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        target.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    merge(sys.argv[1], Path(sys.argv[2]))
