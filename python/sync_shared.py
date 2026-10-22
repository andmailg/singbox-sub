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


RKN_CACHE = "python/src/filters/rkn_networks_cache.json"


def merge_rkn_cache(ours_dir: Path, repo: Path = Path(".")) -> None:
    """Кэш подсетей одинаков для всех протоколов: оставляем сборку с большим _built_at."""
    ours_file, target = ours_dir / RKN_CACHE, repo / RKN_CACHE
    if not ours_file.exists():
        return

    def built(path: Path) -> str:
        try:
            return str(json.loads(path.read_text(encoding="utf-8")).get("_built_at", ""))
        except Exception:
            return ""

    if not target.exists() or built(ours_file) > built(target):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(ours_file.read_text(encoding="utf-8"), encoding="utf-8")


def merge(proto: str, ours_dir: Path, repo: Path = Path(".")) -> None:
    merge_rkn_cache(ours_dir, repo)
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
