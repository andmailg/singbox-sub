"""Проверка дат обновления подписок из sub_urls.json через GitHub API."""

import json
import urllib.request
import urllib.error
import re
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "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")


def parse_http_date(date_str: str) -> str | None:
    """Парсит HTTP date string в читаемый формат."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S GMT")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return date_str


def extract_github_info(url: str) -> dict | None:
    """Извлекает owner/repo/branch из GitHub raw URL (любой формат)."""
    patterns = [
        # github.com/owner/repo/raw/refs/heads/branch/...
        r"github\.com/([^/]+)/([^/]+)/raw/refs/heads/([^/]+)/",
        r"github\.com/([^/]+)/([^/]+)/raw/refs/heads/([^/]+)",
        r"github\.com/([^/]+)/([^/]+)/raw/(master|main)/",
        # raw.githubusercontent.com/owner/repo/refs/heads/branch/...
        r"raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)/",
        r"raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)",
        # raw.githubusercontent.com/owner/repo/branch/...
        r"raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/",
    ]
    for pattern in patterns:
        m = re.search(pattern, url)
        if m:
            return {"owner": m.group(1), "repo": m.group(2), "branch": m.group(3)}
    return None


def get_github_last_commit(owner: str, repo: str, branch: str) -> str | None:
    """Получает дату последнего коммита через GitHub API."""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits?sha={branch}&per_page=1"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Accept", "application/vnd.github.v3+json")
        if GITHUB_TOKEN:
            req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read())
                if data:
                    # commit['commit']['committer']['date'] - дата коммита
                    commit_date = data[0]["commit"]["committer"]["date"]
                    dt = datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
                    return dt.strftime("%Y-%m-%d %H:%M UTC")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            if GITHUB_TOKEN:
                return "rate limited (token)"
            return "rate limited (no token)"
        return f"HTTP {e.code}"
    except Exception as e:
        return str(e)
    return None


def check_url_simple(key: str, url: str) -> dict:
    """Проверяет URL через HEAD запрос."""
    result = {
        "key": key,
        "url": url,
        "status": None,
        "last_modified": None,
        "content_length": None,
        "error": None,
    }

    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result["status"] = resp.status
            result["last_modified"] = parse_http_date(resp.headers.get("Last-Modified"))
            result["content_length"] = resp.headers.get("Content-Length")
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except TimeoutError:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    json_path = Path(__file__).parent / "sub_urls.json"
    with open(json_path, "r", encoding="utf-8") as f:
        urls = json.load(f)

    print(f"Проверка {len(urls)} подписок...\n")

    # Сначала проверяем все URL
    print(f"{'ID':<5} {'Статус':<7} {'Last-Modified':<25} {'Размер':<15} {'URL'}")
    print("-" * 120)

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_url_simple, key, url): key for key, url in urls.items()}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: int(x["key"]))

    # Собираем GitHub URL для дополнительной проверки
    github_urls = []
    for r in results:
        status = str(r["status"]) if r["status"] else "ERR"
        last_mod = r["last_modified"] or "-"
        size = "-"
        if r["content_length"]:
            size = f"{int(r['content_length']) / 1024:.1f} KB"
        error = f" ({r['error']})" if r["error"] else ""
        print(f"{r['key']:<5} {status:<7} {last_mod:<25} {size:<15} {r['url']}{error}")

        # Проверяем, является ли URL GitHub
        gh_info = extract_github_info(r["url"])
        if gh_info:
            github_urls.append((r["key"], gh_info))

    # Для GitHub URL получаем дату последнего коммита
    if github_urls:
        token_status = "с токеном" if GITHUB_TOKEN else "без токена (лимит 60/час)"
        print(f"\nПолучение дат последнего коммита для {len(github_urls)} GitHub URL ({token_status})...")
        for key, gh_info in github_urls:
            commit_date = get_github_last_commit(gh_info["owner"], gh_info["repo"], gh_info["branch"])
            print(f"  #{key}: {gh_info['owner']}/{gh_info['repo']}@{gh_info['branch']} -> {commit_date}")

    # Сводка
    print("\n" + "=" * 120)
    checked = [r for r in results if r["status"]]
    failed = [r for r in results if r["error"]]
    print("СВОДКА:")
    print(f"  Проверено: {len(checked)}")
    print(f"  Ошибок: {len(failed)}")


if __name__ == "__main__":
    main()
