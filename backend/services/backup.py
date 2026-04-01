import logging
import os
import re
import sqlite3
import tarfile
import threading
import time
from pathlib import Path

from ..core.config import settings
from .storage import storage

logger = logging.getLogger(__name__)

_KEY_MAX_ARCHIVES = "backup_max_archives"
_KEY_INTERVAL_SEC = "backup_interval_seconds"
_KEY_LAST_AT = "backup_last_at"

_DEFAULT_MAX_ARCHIVES = 200
_DEFAULT_INTERVAL_SEC = 86400  # 24 h


class BackupService:
    _lock = threading.Lock()
    _started_at = time.time()
    _scheduler_thread: threading.Thread | None = None

    def _storage_dir(self) -> Path:
        return settings.backup_storage_dir.resolve()

    def _ensure_dir(self) -> Path:
        d = self._storage_dir()
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _get_setting_int(self, key: str, default: int) -> int:
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return default
        try:
            return int(row["value"])
        except ValueError:
            return default

    def _set_setting(self, key: str, value: str) -> None:
        with storage.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO app_settings(key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_max_archives(self) -> int:
        v = self._get_setting_int(_KEY_MAX_ARCHIVES, _DEFAULT_MAX_ARCHIVES)
        return max(1, min(100_000, v))

    def get_interval_seconds(self) -> int:
        v = self._get_setting_int(_KEY_INTERVAL_SEC, _DEFAULT_INTERVAL_SEC)
        return max(60, min(86400 * 366, v))

    def get_last_backup_at(self) -> int | None:
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", (_KEY_LAST_AT,)
            ).fetchone()
        if not row or not row["value"].strip():
            return None
        try:
            return int(row["value"])
        except ValueError:
            return None

    def set_last_backup_at(self, ts: int) -> None:
        self._set_setting(_KEY_LAST_AT, str(int(ts)))

    def save_settings(self, *, max_archives: int, interval_hours: int) -> dict:
        ma = max(1, min(100_000, int(max_archives)))
        ih = max(1, min(8760, int(interval_hours)))
        sec = ih * 3600
        self._set_setting(_KEY_MAX_ARCHIVES, str(ma))
        self._set_setting(_KEY_INTERVAL_SEC, str(sec))
        return {"max_archives": ma, "interval_hours": ih, "interval_seconds": sec}

    def list_paths(self) -> list[dict]:
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT id, path, created_at FROM backup_paths ORDER BY id ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def add_path(self, raw: str) -> dict:
        s = (raw or "").strip()
        if not s:
            raise ValueError("Путь не может быть пустым")
        p = Path(s).expanduser()
        try:
            resolved = p.resolve()
        except OSError as e:
            raise ValueError(f"Некорректный путь: {e}") from e
        if not resolved.exists():
            raise ValueError("Путь не существует")
        if not os.access(resolved, os.R_OK):
            raise ValueError("Нет доступа на чтение")
        sp = str(resolved)
        with storage.connection() as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO backup_paths(path, created_at) VALUES (?, ?)",
                    (sp, int(time.time())),
                )
            except sqlite3.IntegrityError as e:
                raise ValueError("Этот путь уже добавлен") from e
            pid = cur.lastrowid
            row = conn.execute(
                "SELECT id, path, created_at FROM backup_paths WHERE id = ?",
                (pid,),
            ).fetchone()
        return dict(row) if row else {}

    def remove_path(self, path_id: int) -> bool:
        with storage.connection() as conn:
            cur = conn.execute("DELETE FROM backup_paths WHERE id = ?", (path_id,))
            return cur.rowcount > 0

    def _archive_name(self) -> str:
        return f"backup-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz"

    def _prune_archives(self) -> int:
        d = self._storage_dir()
        if not d.is_dir():
            return 0
        files: list[Path] = []
        for p in d.iterdir():
            if (
                p.is_file()
                and p.name.startswith("backup-")
                and p.name.endswith(".tar.gz")
            ):
                files.append(p)
        keep = self.get_max_archives()
        if len(files) <= keep:
            return 0
        files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        removed = 0
        for p in files[keep:]:
            try:
                p.unlink()
                removed += 1
            except OSError as e:
                logger.warning("backup: не удалось удалить старый архив %s: %s", p, e)
        return removed

    def run_backup(self) -> dict:
        with self._lock:
            paths = self.list_paths()
            if not paths:
                raise ValueError("Нет путей для резервного копирования")

            self._ensure_dir()
            arc_path = self._ensure_dir() / self._archive_name()

            members: list[Path] = []
            for row in paths:
                p = Path(row["path"])
                if not p.exists():
                    raise ValueError(f"Путь недоступен: {row['path']}")
                members.append(p)

            try:
                with tarfile.open(arc_path, "w:gz") as tar:
                    for p in members:
                        arcname = p.name
                        if p.is_dir():
                            tar.add(p, arcname=arcname, recursive=True)
                        else:
                            tar.add(p, arcname=arcname, recursive=False)
            except OSError as e:
                if arc_path.exists():
                    arc_path.unlink(missing_ok=True)
                raise ValueError(f"Не удалось создать архив: {e}") from e

            self.set_last_backup_at(int(time.time()))
            pruned = self._prune_archives()
            return {
                "name": arc_path.name,
                "path": str(arc_path),
                "pruned_old": pruned,
            }

    def list_archives(self) -> list[dict]:
        d = self._storage_dir()
        if not d.is_dir():
            return []
        out: list[dict] = []
        for p in d.iterdir():
            if (
                p.is_file()
                and p.name.startswith("backup-")
                and p.name.endswith(".tar.gz")
            ):
                st = p.stat()
                out.append(
                    {
                        "name": p.name,
                        "size_bytes": st.st_size,
                        "modified_at": int(st.st_mtime),
                    }
                )
        out.sort(key=lambda x: -x["modified_at"])
        return out

    def safe_archive_path(self, name: str) -> Path | None:
        s = (name or "").strip()
        if not s or "/" in s or "\\" in s or ".." in s:
            return None
        if not re.match(r"^backup-[0-9]{8}-[0-9]{6}\.tar\.gz$", s):
            return None
        try:
            root = self._storage_dir().resolve()
            p = (root / s).resolve()
            p.relative_to(root)
        except (OSError, ValueError):
            return None
        if not p.is_file():
            return None
        return p

    def status(self) -> dict:
        paths = self.list_paths()
        archives = self.list_archives()
        interval = self.get_interval_seconds()
        last = self.get_last_backup_at()
        now = time.time()

        if not paths:
            next_ts = None
            seconds_until = None
        elif last is None:
            first_run = self._started_at + 60.0
            next_ts = int(first_run)
            seconds_until = max(0, int(first_run - now))
        else:
            nxt = last + interval
            if nxt <= now:
                next_ts = int(now)
                seconds_until = 0
            else:
                next_ts = int(nxt)
                seconds_until = int(nxt - now)

        return {
            "paths": paths,
            "settings": {
                "max_archives": self.get_max_archives(),
                "interval_hours": self.get_interval_seconds() // 3600,
                "interval_seconds": interval,
            },
            "archives": archives,
            "last_backup_at": last,
            "next_backup_at": next_ts,
            "seconds_until_next": seconds_until,
        }

    def tick(self) -> None:
        st = self.status()
        paths = st["paths"]
        if not paths:
            return
        interval = self.get_interval_seconds()
        last = self.get_last_backup_at()
        now = time.time()

        should_run = False
        if last is None:
            if now >= self._started_at + 60.0:
                should_run = True
        elif now >= last + interval:
            should_run = True

        if not should_run:
            return

        try:
            out = self.run_backup()
            logger.info(
                "backup: создан %s, удалено старых: %s",
                out.get("name"),
                out.get("pruned_old"),
            )
        except ValueError as e:
            logger.warning("backup: пропуск: %s", e)
        except Exception:
            logger.exception("backup: ошибка при создании архива")

    def _scheduler_loop(self) -> None:
        while True:
            time.sleep(60)
            try:
                self.tick()
            except Exception:
                logger.exception("backup: ошибка планировщика")

    def start_scheduler(self) -> None:
        if self._scheduler_thread is not None:
            return
        t = threading.Thread(target=self._scheduler_loop, daemon=True)
        t.start()
        self._scheduler_thread = t
        logger.debug("backup: планировщик запущен")


backup = BackupService()
