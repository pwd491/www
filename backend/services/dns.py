import json
import logging
import yaml
from datetime import datetime
from pathlib import Path

from ..core.config import settings
from .storage import storage

logger = logging.getLogger(__name__)


class DnsService:
    _QUERYLOG_GLOB = "querylog.json*"

    def _find_querylog_files(self) -> list[Path]:
        """All querylog files in adguard_data_dir (querylog.json, querylog.json.1, …), newest first."""
        base = settings.adguard_data_dir
        if not base.is_dir():
            return []
        files = [p for p in base.glob(self._QUERYLOG_GLOB) if p.is_file()]
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return files

    def list_keywords(self) -> list[str]:
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT keyword FROM dns_keywords ORDER BY keyword ASC"
            ).fetchall()
        return [r["keyword"] for r in rows]

    def add_keyword(self, keyword: str) -> None:
        kw = keyword.strip().lower()
        if not kw:
            raise ValueError("Keyword cannot be empty")
        with storage.connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO dns_keywords(keyword) VALUES (?)",
                (kw,),
            )

    def add_keywords_bulk(self, text: str) -> dict:
        parts = [p.strip().lower() for p in text.split() if p.strip()]
        if not parts:
            raise ValueError("At least one keyword is required")
        added: list[str] = []
        already: list[str] = []
        with storage.connection() as conn:
            for kw in parts:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO dns_keywords(keyword) VALUES (?)",
                    (kw,),
                )
                if cur.rowcount > 0:
                    added.append(kw)
                else:
                    already.append(kw)
        return {"added": added, "already": already}

    def delete_keyword(self, keyword: str) -> bool:
        kw = keyword.strip().lower()
        with storage.connection() as conn:
            cur = conn.execute("DELETE FROM dns_keywords WHERE keyword = ?", (kw,))
            return cur.rowcount > 0

    def sync_adguard_clients_from_home(self) -> dict:
        """
        AdGuardHome: парсим `/opt/AdGuardHome/AdGuardHome.yaml` и обновляем таблицу
        `adguard_clients` (ip -> name).
        """
        yaml_path = settings.adguard_home_yaml_path
        if not yaml_path.is_file():
            logger.debug(
                "AdGuard clients sync: YAML не найден: %s (exists=%s)",
                yaml_path,
                yaml_path.exists(),
            )
            return {"synced": 0, "reason": "yaml_not_found"}

        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.exception("AdGuard clients sync: ошибка чтения/парсинга YAML: %s", e)
            return {"synced": 0, "reason": "yaml_parse_error"}

        mapping: dict[str, str] = {}
        clients = (data.get("clients") or {}).get("persistent") or []
        if not isinstance(clients, list):
            logger.debug(
                "AdGuard clients sync: неожиданный формат clients.persistent (type=%s)",
                type(clients).__name__,
            )
            clients = []

        for c in clients:
            if not isinstance(c, dict):
                continue
            name = c.get("name")
            ids = c.get("ids")
            if not isinstance(name, str) or not name.strip():
                continue
            if not isinstance(ids, list):
                continue
            for ip in ids:
                if isinstance(ip, str) and ip.strip():
                    mapping[ip.strip()] = name.strip()

        if not mapping:
            logger.debug("AdGuard clients sync: ничего не найдено в YAML")
            return {"synced": 0, "reason": "no_clients"}

        with storage.connection() as conn:
            conn.execute("DELETE FROM adguard_clients")
            conn.executemany(
                "INSERT OR REPLACE INTO adguard_clients(ip, name) VALUES (?, ?)",
                list(mapping.items()),
            )

        return {"synced": len(mapping)}

    def _load_adguard_client_names(self) -> dict[str, str]:
        with storage.connection() as conn:
            rows = conn.execute("SELECT ip, name FROM adguard_clients").fetchall()
        return {r["ip"]: r["name"] for r in rows}

    @staticmethod
    def _domain_from_log_row(row: dict) -> str:
        """AdGuard: старый формат QH; новый API — question.name / unicode_name."""
        qh = row.get("QH")
        if isinstance(qh, str) and qh.strip():
            return qh.strip().lower()
        q = row.get("question")
        if isinstance(q, dict):
            for key in ("unicode_name", "name"):
                v = q.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip().lower()
        return ""

    @staticmethod
    def _client_from_log_row(row: dict) -> str:
        for key in ("IP", "ClientIP", "client"):
            v = row.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
            if isinstance(v, list) and v:
                # В querylog поле `client` часто приходит как массив IP-адресов.
                # Для сопоставления по YAML используем первый адрес.
                first = v[0]
                return first.strip() if isinstance(first, str) else str(first)
        return "-"

    @staticmethod
    def _timestamp_from_row(row: dict) -> str:
        raw = row.get("T", row.get("time"))
        if raw is None:
            return "unknown"
        if isinstance(raw, str) and raw.strip():
            s = raw.strip().replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(s).isoformat(sep=" ")
            except ValueError:
                try:
                    base = s.split(".")[0]
                    if len(base) >= 19:
                        return datetime.fromisoformat(base).isoformat(sep=" ")
                except Exception:
                    pass
        if isinstance(raw, (int, float)):
            try:
                return datetime.fromtimestamp(int(raw)).isoformat(sep=" ")
            except (ValueError, OSError):
                pass
        return "unknown"

    @staticmethod
    def _normalize_client_ip(raw: str) -> str:
        s = (raw or "").strip()
        if s.startswith("[") and "]" in s:
            s = s.split("]", 1)[0].lstrip("[")
        return s.strip()

    def _append_matching_entries(
        self,
        row: dict,
        keywords: list[str],
        entries: list[dict],
        client_names: dict[str, str],
        client_ip_filter: str | None = None,
    ) -> bool:
        domain = self._domain_from_log_row(row)
        if not domain:
            return False
        matched_kws = [k for k in keywords if k in domain]
        if not matched_kws:
            return False
        client_ip = self._client_from_log_row(row)
        if client_ip_filter is not None:
            want = self._normalize_client_ip(client_ip_filter)
            got = self._normalize_client_ip(client_ip)
            if want != got:
                return False
        client_name = client_names.get(client_ip)
        client_display = client_name or client_ip
        entries.append(
            {
                "time": self._timestamp_from_row(row),
                "domain": domain,
                "client": client_display,
                "client_ip": client_ip,
                "client_name": client_name,
                "matched_keywords": matched_kws,
            }
        )
        return True

    def _time_to_hour_bucket(self, raw: str) -> str | None:
        s = (raw or "").strip()
        if not s or s == "unknown":
            return None
        iso = s.replace(" ", "T", 1) if " " in s and "T" not in s else s
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:00")
        except ValueError:
            try:
                base = s.split(".")[0]
                if len(base) >= 19:
                    dt = datetime.fromisoformat(base)
                    return dt.strftime("%Y-%m-%d %H:00")
            except ValueError:
                pass
            return None

    def build_dns_stats(self, entries: list[dict]) -> dict:
        by_keyword: dict[str, int] = {}
        by_hour: dict[str, int] = {}
        domain_counts: dict[str, int] = {}
        for e in entries:
            for kw in e.get("matched_keywords") or []:
                by_keyword[kw] = by_keyword.get(kw, 0) + 1
            dom = (e.get("domain") or "").strip()
            if dom:
                domain_counts[dom] = domain_counts.get(dom, 0) + 1
            bucket = self._time_to_hour_bucket(str(e.get("time") or ""))
            if bucket:
                by_hour[bucket] = by_hour.get(bucket, 0) + 1
        hours_sorted = sorted(by_hour.items(), key=lambda x: x[0])
        top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:12]
        return {
            "by_keyword": by_keyword,
            "by_hour": [{"hour": k, "count": v} for k, v in hours_sorted],
            "top_domains": [{"domain": k, "count": v} for k, v in top_domains],
            "total_queries": len(entries),
        }

    def find_queries_by_keywords(
        self,
        limit: int | None = None,
        client_ip: str | None = None,
    ) -> list[dict]:
        keywords = self.list_keywords()
        paths = self._find_querylog_files()
        client_ip_filter = (client_ip or "").strip() or None

        if not keywords:
            logger.debug(
                "DNS query log: нет ключевых слов в БД, пропуск сканирования"
            )
            return []

        if not paths:
            logger.error(
                "DNS query log: не найдены файлы %s в %s",
                self._QUERYLOG_GLOB,
                settings.adguard_data_dir,
            )
            return []

        logger.debug(
            "DNS query log: сканирование %s файл(ов), ключевых слов: %s",
            len(paths),
            len(keywords),
        )

        client_names = self._load_adguard_client_names()
        if not client_names:
            self.sync_adguard_clients_from_home()
            client_names = self._load_adguard_client_names()

        entries: list[dict] = []
        lines_total = 0
        json_errors = 0
        empty_domain = 0
        matched = 0
        sample_keys: list[str] | None = None
        first_file_stats: int | None = None

        for path in paths:
            try:
                st = path.stat()
                if first_file_stats is None:
                    first_file_stats = st.st_size
            except OSError as e:
                logger.debug("DNS query log: пропуск %s (%s)", path, e)
                continue

            try:
                with path.open("r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        lines_total += 1
                        try:
                            parsed = json.loads(line)
                        except json.JSONDecodeError as e:
                            json_errors += 1
                            if json_errors <= 3:
                                logger.debug(
                                    "DNS query log: JSON ошибка в строке %s: %s",
                                    lines_total,
                                    e,
                                )
                            continue
                        if isinstance(parsed, list):
                            iter_rows = [x for x in parsed if isinstance(x, dict)]
                        elif isinstance(parsed, dict) and isinstance(
                            parsed.get("data"), list
                        ):
                            iter_rows = [x for x in parsed["data"] if isinstance(x, dict)]
                        elif isinstance(parsed, dict):
                            iter_rows = [parsed]
                        else:
                            continue
                        for row in iter_rows:
                            if sample_keys is None and row:
                                sample_keys = list(row.keys())[:25]
                            dom = self._domain_from_log_row(row)
                            if not dom:
                                empty_domain += 1
                                continue
                            if self._append_matching_entries(
                                row,
                                keywords,
                                entries,
                                client_names,
                                client_ip_filter,
                            ):
                                matched += 1
            except OSError as e:
                logger.error("DNS query log: чтение файла %s: %s", path, e)
                return []

        if matched == 0 and lines_total > 0:
            logger.debug(
                "DNS query log: прочитано строк JSONL=%s, совпадений=0, "
                "пустой домен=%s, ошибок JSON=%s",
                lines_total,
                empty_domain,
                json_errors,
            )

        if matched == 0 and lines_total == 0 and first_file_stats and first_file_stats > 0:
            wrapped = self._try_load_wrapped_querylog(
                paths[0], keywords, limit, client_names, client_ip_filter
            )
            if wrapped:
                logger.debug(
                    "DNS query log: использован формат единого JSON (не JSONL), "
                    "записей после фильтра: %s",
                    len(wrapped),
                )
                return wrapped if limit is None else wrapped[:limit]
            logger.debug(
                "DNS query log: файлы непустые (%s байт в первом), но не удалось "
                "разобрать ни одной JSONL-строки (ошибок JSON: %s)",
                first_file_stats,
                json_errors,
            )

        entries.reverse()
        out = entries if limit is None else entries[:limit]
        if out:
            logger.debug(
                "DNS query log: отдано записей=%s (всего совпадений при скане=%s)",
                len(out),
                matched,
            )
        else:
            logger.debug(
                "DNS query log: после фильтра пусто (строк=%s, совпадений=%s)",
                lines_total,
                matched,
            )
        return out

    def _try_load_wrapped_querylog(
        self,
        path: Path,
        keywords: list[str],
        limit: int | None,
        client_names: dict[str, str],
        client_ip_filter: str | None = None,
    ) -> list[dict]:
        """Формат {'data': [ {...}, ... ] } или массив записей целиком."""
        max_bytes = 80 * 1024 * 1024
        try:
            if path.stat().st_size > max_bytes:
                logger.debug(
                    "DNS query log: файл слишком большой для цельного JSON (%s > %s)",
                    path.stat().st_size,
                    max_bytes,
                )
                return []
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug("DNS query log: цельный JSON не разобран: %s", e)
            return []

        rows: list[dict] = []
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            rows = [x for x in data["data"] if isinstance(x, dict)]
        elif isinstance(data, list):
            rows = [x for x in data if isinstance(x, dict)]
        else:
            logger.debug(
                "DNS query log: неожиданная структура JSON (тип корня: %s)",
                type(data).__name__,
            )
            return []

        entries: list[dict] = []
        for row in rows:
            self._append_matching_entries(
                row, keywords, entries, client_names, client_ip_filter
            )
        entries.reverse()
        return entries if limit is None else entries[:limit]


dns = DnsService()
