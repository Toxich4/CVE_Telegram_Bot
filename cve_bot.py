#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Dict, Any, Optional, Tuple

import requests
from dotenv import load_dotenv

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_REF_URLS = 10  # сколько ссылок "More information" показывать на CVE
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


# ------------------------ утилиты ------------------------

def log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def get_env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if raw in ("1", "true", "yes", "y", "on", "да"):
        return True
    if raw in ("0", "false", "no", "n", "off", "нет"):
        return False
    return default


def parse_period_to_timedelta(period_raw: Optional[str]) -> Tuple[timedelta, str]:
    if not period_raw:
        return timedelta(minutes=30), "30m(default)"
    p = period_raw.strip().lower().replace(" ", "")
    mapping = {
        "30m": timedelta(minutes=30), "30min": timedelta(minutes=30),
        "30мин": timedelta(minutes=30), "30минут": timedelta(minutes=30), "30": timedelta(minutes=30),
        "hour": timedelta(hours=1), "1h": timedelta(hours=1), "час": timedelta(hours=1),
        "day": timedelta(days=1), "1d": timedelta(days=1), "сутки": timedelta(days=1), "день": timedelta(days=1),
        "week": timedelta(weeks=1), "1w": timedelta(weeks=1), "неделя": timedelta(weeks=1),
        "month": timedelta(days=30), "1mo": timedelta(days=30), "месяц": timedelta(days=30),
    }
    if p in mapping: return mapping[p], p
    log(f"WARNING: PERIOD='{period_raw}' не распознан — использую 30m по умолчанию.")
    return timedelta(minutes=30), "30m(default)"


def build_window_utc(delta: timedelta) -> Tuple[str, str]:
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - delta
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return start_dt.strftime(fmt), end_dt.strftime(fmt)


def fetch_nvd(pub_start: str, pub_end: str, retries: int = 3, timeout: int = 30) -> Dict[str, Any]:
    params = {"pubStartDate": pub_start, "pubEndDate": pub_end}
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(NVD_API, params=params, timeout=timeout)
            if r.status_code == 200:
                return r.json()
            log(f"NVD HTTP {r.status_code}: {r.text[:400]}")
        except requests.RequestException as e:
            log(f"NVD request error: {e}")
        if attempt < retries:
            backoff = 2 ** attempt
            log(f"Retrying NVD in {backoff}s (attempt {attempt+1}/{retries})")
            time.sleep(backoff)
    return {}


def pick_english_description(cve: Dict[str, Any]) -> Optional[str]:
    for d in cve.get("descriptions", []):
        if (d.get("lang") or "").lower() == "en":
            val = (d.get("value") or "").strip()
            if val:
                return val
    for d in cve.get("descriptions", []):
        val = (d.get("value") or "").strip()
        if val:
            return val
    return None


def get_cvss_v31_base_score(cve: Dict[str, Any]) -> Optional[float]:
    metrics = cve.get("metrics", {})
    arr = metrics.get("cvssMetricV31", [])
    for entry in arr:
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)
    return None


def get_reference_urls(cve: Dict[str, Any], max_urls: int = MAX_REF_URLS) -> List[str]:
    urls: List[str] = []
    seen = set()
    for ref in cve.get("references", []):
        url = (ref.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= max_urls:
            break
    return urls


DATE_HEAD_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
def date_only(iso_str: Optional[str]) -> str:
    if not iso_str: return "Unknown"
    m = DATE_HEAD_RE.match(iso_str.strip())
    return m.group(1) if m else "Unknown"


# ------------------------ ключевые слова из файла + строгий матч ------------------------

def load_keywords_file(path: str) -> List[str]:
    """
    Загружаем keywords из файла.
    Форматы:
      - по одному на строку
      - можно писать через запятую (разрешено микшевать)
      - комментарии строками, начинающимися с '#'
      - пустые строки игнорируются
    """
    if not os.path.isfile(path):
        log(f"WARNING: keywords file '{path}' не найден — список будет пустым.")
        return []
    items: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # позволим разделять запятыми в одной строке
            parts = [p.strip() for p in line.split(",") if p.strip()]
            items.extend(parts)
    return items


def build_keyword_patterns(keywords: List[str]) -> List[Tuple[str, re.Pattern]]:
    """
    Для каждой фразы строим паттерн с границами слова.
    - регистр игнорируется
    - между словами допускаем пробелы и/или дефисы: 'Azure AD' => Azure[ -]+AD
    - одиночные слова тоже по границам
    """
    patterns: List[Tuple[str, re.Pattern]] = []
    for kw in keywords:
        norm = kw.strip()
        if not norm:
            continue
        # схлопываем множественные пробелы внутри фразы
        base = re.sub(r"\s+", " ", norm.lower())
        # экранируем спецсимволы, пробел заменяем на класс пробелов/дефисов
        esc = re.escape(base).replace(r"\ ", r"(?:[ \t\-]+)")
        pat = re.compile(rf"\b{esc}\b", re.IGNORECASE)
        patterns.append((kw, pat))
    return patterns


def strip_urls(text: str) -> str:
    """Удаляем URL из описания, чтобы не ловить совпадения внутри ссылок."""
    return URL_RE.sub("", text or "")


def find_matched_keyword_regex(text: str, patterns: List[Tuple[str, re.Pattern]]) -> Optional[str]:
    t = strip_urls(text)
    for original_kw, pat in patterns:
        if pat.search(t):
            return original_kw
    return None


# ------------------------ форматирование и отправка ------------------------

def format_message_html(
    cve_id: str,
    cvss: Optional[float],
    published_iso: Optional[str],
    description: str,
    ref_urls: List[str],
) -> str:
    cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    cvss_str = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "N/A"
    published_str = date_only(published_iso)

    safe_desc = html_escape(description)
    safe_id = html_escape(cve_id)

    base = (
        f"🚨  <a href=\"{cve_link}\">{safe_id}</a> 🚨\n"
        f"💥  <b>CVSS</b>: {cvss_str}\n"
        f"📅  <b>Published</b>: {html_escape(published_str)}\n"
        f"📓  <b>Description</b>: {safe_desc}"
    )
    if ref_urls:
        lines = []
        for i, u in enumerate(ref_urls, 1):
            safe_url = html_escape(u)
            lines.append(f"{i}. <a href=\"{safe_url}\">{safe_url}</a>")
        base += "\n" + "ℹ️  <b>More information</b>:\n" + "\n".join(lines)
    return base


def send_telegram_message(token: str, chat_id: str, text: str, thread_id: Optional[int] = None) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if thread_id is not None:
        data["message_thread_id"] = thread_id
    try:
        r = requests.post(url, data=data, timeout=30)
        if r.status_code == 200:
            return True
        log(f"Telegram HTTP {r.status_code}: {r.text[:400]}")
        return False
    except requests.RequestException as e:
        log(f"Telegram request error: {e}")
        return False


# ------------------------ main ------------------------

def main() -> int:
    load_dotenv()

    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    thread_id_env = os.getenv("THREAD_ID", "").strip()
    thread_id = int(thread_id_env) if thread_id_env.isdigit() else None
    if not token or not chat_id:
        log("ERROR: TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID не заданы в .env")
        return 2

    # период, allow_all
    period_raw = os.getenv("PERIOD", "").strip()
    delta, period_name = parse_period_to_timedelta(period_raw)
    allow_all = get_env_bool("ALLOW_ALL", default=False)

    # файл ключевых слов (по умолчанию keywords.txt в текущем каталоге)
    kw_file = os.getenv("KEYWORDS_FILE", "keywords.txt").strip()
    keywords = load_keywords_file(kw_file)
    patterns = build_keyword_patterns(keywords)

    log(f"PERIOD={period_name} | ALLOW_ALL={allow_all} | THREAD_ID={thread_id} | KEYWORDS_FILE='{kw_file}'")
    log(f"Loaded {len(keywords)} keywords")

    pub_start, pub_end = build_window_utc(delta)
    log(f"Запрос к NVD: {NVD_API}?pubStartDate={pub_start}&pubEndDate={pub_end}")

    payload = fetch_nvd(pub_start, pub_end)
    vulns = payload.get("vulnerabilities", [])
    log(f"NVD вернул vulnerabilities: {len(vulns)}")

    sent = 0
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        description = pick_english_description(cve)
        if not description:
            continue

        if not allow_all:
            hit_kw = find_matched_keyword_regex(description, patterns)
            if not hit_kw:
                continue
        else:
            hit_kw = "ALLOW_ALL"

        cvss = get_cvss_v31_base_score(cve)
        published = cve.get("published")
        ref_urls = get_reference_urls(cve, MAX_REF_URLS)

        log(f"[MATCH] {cve_id} by '{hit_kw}'")

        msg = format_message_html(
            cve_id=cve_id,
            cvss=cvss,
            published_iso=published,
            description=description,
            ref_urls=ref_urls,
        )

        if send_telegram_message(token, chat_id, msg, thread_id=thread_id):
            sent += 1
            time.sleep(0.5)

    if sent == 0:
        log("Подходящих CVE нет — сообщений не отправлено.")
    else:
        log(f"Отправлено сообщений: {sent}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("Interrupted")
        sys.exit(130)
