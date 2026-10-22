#!/usr/bin/env bash
# Коммит и push результатов convert-* workflow без конфликтов с параллельными запусками.
#
# Использование: push_results.sh <ключ_протокола> "<сообщение коммита>" <свои файлы...>
#
# Свои файлы протокола переносятся поверх свежего origin/main целиком, а в общих файлах
# (blacklist/whitelist/кэш RKN) подменяется только секция протокола (python/sync_shared.py).
# Так параллельные workflow не конфликтуют на общих JSON, а push повторяется при отказе.
set -euo pipefail

PROTO="$1"; MSG="$2"; shift 2
ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
PYTHON="${PYTHON:-python}"
SHARED=(python/src/filters/blacklist.json python/src/filters/whitelist.json python/src/filters/rkn_networks_cache.json)

cd "$ROOT"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

# Только реально существующие файлы
OWN=(); for f in "$@"; do [ -e "$f" ] && OWN+=("$f"); done
SHARED_EXISTING=(); for f in "${SHARED[@]}"; do [ -e "$f" ] && SHARED_EXISTING+=("$f"); done

OUT="$(mktemp -d)"
cp --parents "${OWN[@]}" "${SHARED_EXISTING[@]}" "$OUT"/

for attempt in 1 2 3 4 5; do
  git fetch origin main
  git reset --hard origin/main
  (cd "$OUT" && cp --parents "${OWN[@]}" "$ROOT"/)
  "$PYTHON" python/sync_shared.py "$PROTO" "$OUT"

  git add "${OWN[@]}" "${SHARED_EXISTING[@]}"
  if git diff --cached --quiet; then
    echo "Нет изменений для коммита."
    exit 0
  fi
  git commit -m "$MSG"
  if git push origin HEAD:main; then
    exit 0
  fi
  echo "Push не удался (попытка $attempt), повтор..."
  sleep $((RANDOM % 20 + 5))
done
echo "::error::Не удалось отправить изменения после 5 попыток"
exit 1
