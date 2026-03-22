import re
from pathlib import Path
from urllib.parse import urlparse

from ..core.config import settings


class ZapretService:
    _alias_map = {"hosts": "zapret-hosts-user", "exclude": "zapret-hosts-user-exclude"}
    _list_name_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")

    def _normalize_domain(self, raw: str) -> str | None:
        s = (raw or "").strip().lower()
        if not s:
            return None
        parsed = urlparse(s if "://" in s else f"http://{s}")
        return parsed.hostname

    def _effective_stem(self, list_name: str) -> str:
        key = list_name.strip().lower()
        if ".." in key or "/" in key or "\\" in key:
            raise ValueError("Недопустимое имя списка")
        if not self._list_name_re.match(key):
            raise ValueError("Недопустимое имя списка")
        return self._alias_map.get(key, key)

    def _resolve_file(self, list_name: str) -> Path:
        effective = self._effective_stem(list_name)
        candidates = [
            settings.zapret_domains_dir / f"{effective}.txt",
            settings.zapret_ipset_dir / f"{effective}.txt",
        ]
        for path in candidates:
            if path.exists():
                return path
        candidates[0].parent.mkdir(parents=True, exist_ok=True)
        return candidates[0]

    def _resolve_file_scoped(self, list_name: str, scope: str) -> Path:
        effective = self._effective_stem(list_name)
        if scope == "domains":
            base = settings.zapret_domains_dir
        elif scope == "ipset":
            base = settings.zapret_ipset_dir
        else:
            raise ValueError("scope must be 'domains' or 'ipset'")
        path = base / f"{effective}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def list_txt_lists(self) -> list[dict]:
        """All *.txt in zapret domains and ipset dirs (for UI selection)."""
        out: list[dict] = []
        for scope, base in (
            ("domains", settings.zapret_domains_dir),
            ("ipset", settings.zapret_ipset_dir),
        ):
            if not base.is_dir():
                continue
            for p in sorted(base.glob("*.txt")):
                out.append(
                    {
                        "list_name": p.stem,
                        "filename": p.name,
                        "scope": scope,
                        "path": str(p),
                    }
                )
        return out

    def add_sites(
        self, list_name: str, sites: list[str], scope: str | None = None
    ) -> dict:
        if scope in ("domains", "ipset"):
            target = self._resolve_file_scoped(list_name, scope)
        else:
            target = self._resolve_file(list_name)
        normalized = [self._normalize_domain(s) for s in sites]
        valid = [d for d in normalized if d]
        if not valid:
            raise ValueError("At least one valid domain is required")
        existing = set()
        if target.exists():
            existing = {
                line.strip().lower()
                for line in target.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
        added = []
        already = []
        with target.open("a", encoding="utf-8") as f:
            for domain in valid:
                if domain in existing:
                    already.append(domain)
                else:
                    f.write(domain + "\n")
                    existing.add(domain)
                    added.append(domain)
        return {"file": str(target), "added": added, "existed": already}

    def find_site_all(self, site: str) -> tuple[str, list[dict]]:
        """Search all *.txt under zapret dirs; return (normalized_domain, matches)."""
        domain = self._normalize_domain(site)
        if not domain:
            raise ValueError("Invalid domain")
        matches: list[dict] = []
        for scope, base in (
            ("domains", settings.zapret_domains_dir),
            ("ipset", settings.zapret_ipset_dir),
        ):
            if not base.is_dir():
                continue
            for path in sorted(base.glob("*.txt")):
                if not path.is_file():
                    continue
                try:
                    content = path.read_text(encoding="utf-8")
                except OSError:
                    continue
                line_set = {
                    line.strip().lower()
                    for line in content.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                }
                if domain in line_set:
                    matches.append(
                        {
                            "path": str(path),
                            "filename": path.name,
                            "list_name": path.stem,
                            "scope": scope,
                        }
                    )
        return domain, matches

    def remove_sites(
        self, list_name: str, sites: list[str], scope: str | None = None
    ) -> dict:
        if scope in ("domains", "ipset"):
            target = self._resolve_file_scoped(list_name, scope)
        else:
            target = self._resolve_file(list_name)
        normalized = [self._normalize_domain(s) for s in sites]
        valid = list(dict.fromkeys([d for d in normalized if d]))
        if not valid:
            raise ValueError("At least one valid domain is required")
        want = set(valid)
        if not target.exists():
            return {
                "file": str(target),
                "removed": [],
                "not_in_file": valid,
            }
        raw_lines = target.read_text(encoding="utf-8").splitlines()
        removed: list[str] = []
        kept: list[str] = []
        for line in raw_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                kept.append(line)
                continue
            key = stripped.lower()
            if key in want:
                removed.append(key)
                continue
            kept.append(line)
        removed_unique = list(dict.fromkeys(removed))
        if removed:
            out = "\n".join(kept)
            target.write_text(out + ("\n" if out else ""), encoding="utf-8")
        still_missing = [d for d in valid if d not in set(removed)]
        return {
            "file": str(target),
            "removed": removed_unique,
            "not_in_file": still_missing,
        }


zapret_service = ZapretService()
