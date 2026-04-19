import base64
import ipaddress
import logging
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path

from .storage import storage
from ..core.config import settings

logger = logging.getLogger(__name__)


class AmneziaWGService:
    name_re = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")
    _WG_MANAGED_BEGIN = "### WEBPANEL-MANAGED-PEERS-BEGIN\n"
    _WG_MANAGED_END = "### WEBPANEL-MANAGED-PEERS-END\n"

    _PARAMS_KEY_ORDER: tuple[str, ...] = (
        "SERVER_PUB_IP",
        "SERVER_PUB_NIC",
        "SERVER_WG_NIC",
        "SERVER_WG_IPV4",
        "SERVER_WG_IPV6",
        "SERVER_PORT",
        "SERVER_PRIV_KEY",
        "SERVER_PUB_KEY",
        "CLIENT_DNS_1",
        "CLIENT_DNS_2",
        "ALLOWED_IPS",
    )

    def _is_valid_name(self, name: str) -> bool:
        return bool(self.name_re.match(name))

    def _next_ipv4(self) -> str:
        with storage.connection() as conn:
            rows = conn.execute("SELECT ipv4 FROM amneziawg_clients").fetchall()
        used = {int(r["ipv4"].split(".")[-1]) for r in rows if r["ipv4"].count(".") == 3}
        for n in range(2, 255):
            if n not in used:
                return f"10.66.66.{n}"
        raise ValueError("No available IPv4 addresses")

    def _next_ipv6(self) -> str:
        with storage.connection() as conn:
            rows = conn.execute("SELECT ipv6 FROM amneziawg_clients").fetchall()
        used = set()
        for row in rows:
            try:
                used.add(int(row["ipv6"].split(":")[-1], 16))
            except ValueError:
                continue
        for n in range(2, 255):
            if n not in used:
                return f"fd42:42:42::{n}"
        raise ValueError("No available IPv6 addresses")

    def _random_amneziawg_key(self) -> str:
        """32 random bytes as standard base64 with padding (wg-quick / official apps)."""
        return base64.b64encode(os.urandom(32)).decode("ascii")

    def _decode_wg_key_b64(self, raw: str) -> bytes | None:
        s = raw.strip()
        for decoder in (base64.standard_b64decode, base64.urlsafe_b64decode):
            for pad in ("", "=", "==", "==="):
                try:
                    out = decoder(s + pad)
                    if len(out) == 32:
                        return out
                except Exception:
                    continue
        return None

    def _pubkey_from_private(self, private_key: str) -> str | None:
        priv = private_key.strip()
        try:
            proc = subprocess.run(
                ["awg", "pubkey"],
                input=priv + "\n",
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        raw = self._decode_wg_key_b64(priv)
        if raw is None:
            return None
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
            )
            from cryptography.hazmat.primitives import serialization

            sk = X25519PrivateKey.from_private_bytes(raw)
            pub = sk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return base64.b64encode(pub).decode("ascii")
        except Exception:
            return None

    @staticmethod
    def _parse_client_conf_addresses(address_line: str) -> tuple[str | None, str | None]:
        ipv4: str | None = None
        ipv6: str | None = None
        for part in address_line.split(","):
            p = part.strip()
            if not p:
                continue
            if "/" in p:
                addr, _ = p.split("/", 1)
            else:
                addr = p
            addr = addr.strip()
            if ":" in addr:
                ipv6 = addr
            elif "." in addr:
                ipv4 = addr
        return ipv4, ipv6

    def _parse_client_conf_file(self, text: str) -> dict[str, str] | None:
        priv_m = re.search(
            r"^PrivateKey\s*=\s*(\S+)\s*$", text, re.MULTILINE | re.IGNORECASE
        )
        addr_m = re.search(
            r"^Address\s*=\s*(.+)$", text, re.MULTILINE | re.IGNORECASE
        )
        if not priv_m or not addr_m:
            return None
        ipv4, ipv6 = self._parse_client_conf_addresses(addr_m.group(1).strip())
        if not ipv4:
            return None
        psk_m = re.search(
            r"^PresharedKey\s*=\s*(\S+)\s*$", text, re.MULTILINE | re.IGNORECASE
        )
        preshared = psk_m.group(1).strip() if psk_m else ""
        return {
            "private_key": priv_m.group(1).strip(),
            "ipv4": ipv4,
            "ipv6": ipv6 or "",
            "preshared_key": preshared,
        }

    def import_clients_from_disk(self) -> dict[str, list]:
        """Импорт клиентов из каталога AWG-клиентов (`*.conf`) в БД (идемпотентно)."""
        iface = settings.amneziawg_iface
        clients_dir = settings.amneziawg_clients_dir
        imported: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []
        if not clients_dir.is_dir():
            return {"imported": imported, "skipped": skipped, "errors": errors}
        pat = re.compile(r"^(.+)\.conf$")
        for path in sorted(clients_dir.glob("*.conf")):
            if not path.is_file():
                continue
            m = pat.match(path.name)
            if not m:
                continue
            name = m.group(1)
            if name == iface:
                continue
            if not self._is_valid_name(name):
                errors.append(f"{path.name}: недопустимое имя клиента")
                continue
            with storage.connection() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM amneziawg_clients WHERE name = ?", (name,)
                ).fetchone()
            if exists:
                skipped.append(name)
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as e:
                errors.append(f"{path.name}: не прочитан ({e})")
                continue
            parsed = self._parse_client_conf_file(text)
            if not parsed:
                errors.append(f"{path.name}: нет PrivateKey/Address (IPv4)")
                continue
            public_key = self._pubkey_from_private(parsed["private_key"])
            if not public_key:
                errors.append(f"{path.name}: не удалось получить public key (wg/cryptography)")
                continue
            st = path.stat()
            created_at = int(st.st_mtime)
            try:
                with storage.connection() as conn:
                    conn.execute(
                        "INSERT INTO amneziawg_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            name,
                            parsed["ipv4"],
                            parsed["ipv6"],
                            public_key,
                            parsed["private_key"],
                            parsed["preshared_key"],
                            str(path.resolve()),
                            "import",
                            created_at,
                        ),
                    )
            except sqlite3.IntegrityError:
                skipped.append(name)
                continue
            imported.append(name)
        if imported:
            try:
                if self._server_conf_path().is_file():
                    self._sync_awg0_managed_peers()
                    self._try_awg_syncconf()
            except OSError as e:
                logger.debug("AmneziaWG: после импорта не обновлён awg0.conf: %s", e)
        if imported or errors:
            logger.debug(
                "AmneziaWG импорт с диска: добавлено %s, пропущено %s, ошибок %s",
                len(imported),
                len(skipped),
                len(errors),
            )
        return {"imported": imported, "skipped": skipped, "errors": errors}

    def list_clients(self) -> list[dict]:
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT name, ipv4, ipv6, public_key, config_file, created_by, created_at "
                "FROM amneziawg_clients ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_client_by_name(self, name: str) -> dict | None:
        if not self._is_valid_name(name):
            return None
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT name, ipv4, ipv6, public_key, config_file, created_by, created_at "
                "FROM amneziawg_clients WHERE name = ?",
                (name,),
            ).fetchone()
        if not row:
            return None
        c = dict(row)
        by_ip = self._wg_handshakes_by_ipv4()
        ip = c.get("ipv4") or ""
        hs = by_ip.get(ip) if by_ip else None
        c["last_handshake"] = hs
        return c

    def _wg_handshakes_by_ipv4(self) -> dict[str, int]:
        """Map client tunnel IPv4 -> latest handshake unix time from `wg show` (0 = never)."""
        iface = settings.amneziawg_iface
        try:
            proc = subprocess.run(
                ["awg", "show", iface, "dump"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}
        if proc.returncode != 0 or not proc.stdout.strip():
            return {}
        out: dict[str, int] = {}
        lines = proc.stdout.strip().splitlines()
        ipv4_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 6:
                continue
            allowed = parts[3]
            m = ipv4_re.search(allowed)
            if not m:
                continue
            ip = m.group(1)
            try:
                hs = int(parts[4])
            except ValueError:
                continue
            prev = out.get(ip, 0)
            if hs > prev:
                out[ip] = hs
        return out

    def list_clients_with_activity(self) -> list[dict]:
        clients = self.list_clients()
        by_ip = self._wg_handshakes_by_ipv4()
        for c in clients:
            ip = c.get("ipv4") or ""
            hs = by_ip.get(ip) if by_ip else None
            c["last_handshake"] = hs
        return clients

    def _server_conf_path(self) -> Path:
        return settings.amneziawg_dir / f"{settings.amneziawg_iface}.conf"

    def _read_server_interface_private_key(self) -> str | None:
        path = self._server_conf_path()
        if not path.is_file():
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        m = re.search(
            r"^\s*PrivateKey\s*=\s*(\S+)\s*$",
            text,
            re.MULTILINE | re.IGNORECASE,
        )
        return m.group(1).strip() if m else None

    def _server_public_key(self) -> str | None:
        priv = self._read_server_interface_private_key()
        if not priv:
            return None
        return self._pubkey_from_private(priv)

    def _params_path(self) -> Path:
        return settings.amneziawg_params_path

    def read_params(self) -> dict[str, str]:
        path = self._params_path()
        if not path.is_file():
            return {}
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return {}
        out: dict[str, str] = {}
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "=" not in s:
                continue
            k, v = s.split("=", 1)
            out[k.strip()] = v.strip()
        return out

    def _serialize_params(self, data: dict[str, str]) -> str:
        lines: list[str] = []
        seen: set[str] = set()
        for k in self._PARAMS_KEY_ORDER:
            if k in data:
                lines.append(f"{k}={data[k]}")
                seen.add(k)
        for k in sorted(data.keys()):
            if k not in seen:
                lines.append(f"{k}={data[k]}")
        return "\n".join(lines) + ("\n" if lines else "")

    def write_params_file(self, data: dict[str, str]) -> None:
        path = self._params_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = self._serialize_params(data)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(raw, encoding="utf-8")
        tmp.replace(path)

    def get_params_document(self) -> dict:
        path = self._params_path()
        exists = path.is_file()
        params = self.read_params()
        merged: dict[str, str] = {k: params.get(k, "") for k in self._PARAMS_KEY_ORDER}
        for k, v in params.items():
            if k not in merged:
                merged[k] = v
        return {
            "path": str(path),
            "exists": exists,
            "params": merged,
        }

    def save_params(
        self, incoming: dict[str, str], apply_to_clients: bool = False
    ) -> dict:
        current = self.read_params()
        merged = {**current, **incoming}
        self.write_params_file(merged)
        out: dict = {"saved": True, "path": str(self._params_path())}
        if apply_to_clients:
            out["clients_updated"] = self.rewrite_all_client_configs()
        return out

    def _format_endpoint(self, host: str, port: str) -> str | None:
        host = (host or "").strip()
        port = (port or "").strip()
        if not host or not port:
            return None
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                return f"[{host}]:{port}"
        except ValueError:
            pass
        return f"{host}:{port}"

    def _endpoint_from_params(self, params: dict[str, str]) -> str | None:
        return self._format_endpoint(
            params.get("SERVER_PUB_IP", ""),
            params.get("SERVER_PORT", ""),
        )

    def _peer_public_key_for_client(self, params: dict[str, str]) -> str | None:
        pk = (params.get("SERVER_PUB_KEY") or "").strip()
        if pk:
            return pk
        return self._server_public_key()

    def _allowed_ips_from_params(self, params: dict[str, str]) -> str:
        s = (params.get("ALLOWED_IPS") or "").strip()
        return s if s else "0.0.0.0/0"

    def _build_client_config_text(
        self,
        *,
        private_key: str,
        ipv4: str,
        ipv6: str,
        preshared_key: str,
        peer_public_key: str,
        endpoint: str,
        params: dict[str, str],
    ) -> str:
        dns1 = (params.get("CLIENT_DNS_1") or "").strip()
        dns2 = (params.get("CLIENT_DNS_2") or "").strip()
        dns_parts: list[str] = []
        for d in (dns1, dns2):
            if d and d not in dns_parts:
                dns_parts.append(d)
        allowed_ips = self._allowed_ips_from_params(params)
        lines = [
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {ipv4}/32",
        ]
        if dns_parts:
            lines.append(f"DNS = {', '.join(dns_parts)}")
        lines.extend(
            [
                "",
                "[Peer]",
                f"PublicKey = {peer_public_key}",
                f"PresharedKey = {preshared_key}",
                f"Endpoint = {endpoint}",
                f"AllowedIPs = {allowed_ips}",
                "",
            ]
        )
        return "\n".join(lines)

    def rewrite_all_client_configs(self) -> int:
        params = self.read_params()
        endpoint = self._endpoint_from_params(params)
        peer_pub = self._peer_public_key_for_client(params)
        if not endpoint or not peer_pub:
            raise ValueError(
                "Не заданы endpoint (SERVER_PUB_IP, SERVER_PORT) "
                "или публичный ключ сервера (SERVER_PUB_KEY или PrivateKey в awg0.conf)"
            )
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT ipv4, ipv6, private_key, preshared_key, config_file "
                "FROM amneziawg_clients ORDER BY name ASC"
            ).fetchall()
        n = 0
        for row in rows:
            cfg = Path(row["config_file"])
            text = self._build_client_config_text(
                private_key=row["private_key"],
                ipv4=row["ipv4"],
                ipv6=row["ipv6"],
                preshared_key=row["preshared_key"],
                peer_public_key=peer_pub,
                endpoint=endpoint,
                params=params,
            )
            cfg.write_text(text, encoding="utf-8")
            n += 1
        return n

    def _clients_for_server_sync(self) -> list[dict]:
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT name, ipv4, ipv6, public_key, preshared_key "
                "FROM amneziawg_clients ORDER BY name ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def _build_managed_peers_conf(self) -> str:
        lines: list[str] = []
        for c in self._clients_for_server_sync():
            lines.append("[Peer]")
            lines.append(f"# {c['name']}")
            lines.append(f"PublicKey = {c['public_key']}")
            psk = (c.get("preshared_key") or "").strip()
            if psk:
                lines.append(f"PresharedKey = {psk}")
            lines.append(f"AllowedIPs = {c['ipv4']}/32")
            lines.append("")
        return "\n".join(lines)

    def _sync_awg0_managed_peers(self) -> None:
        path = self._server_conf_path()
        if not path.is_file():
            raise FileNotFoundError(
                f"Нет файла конфигурации сервера AmneziaWG: {path}"
            )
        raw = path.read_text(encoding="utf-8")
        begin, end = self._WG_MANAGED_BEGIN, self._WG_MANAGED_END
        if begin in raw and end in raw:
            i = raw.index(begin)
            j = raw.index(end) + len(end)
            before = raw[:i].rstrip() + "\n"
            after = raw[j:].lstrip("\n")
        else:
            before = raw.rstrip() + "\n"
            after = ""
        managed = self._build_managed_peers_conf()
        out = before + begin + managed + end
        if after:
            out += "\n" + after
        path.write_text(out, encoding="utf-8")

    def _try_awg_syncconf(self) -> None:
        """Применить awg0.conf к работающему интерфейсу (если доступен awg)."""
        conf = self._server_conf_path()
        iface = settings.amneziawg_iface
        try:
            subprocess.run(
                ["awg", "syncconf", iface, str(conf)],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def add_client(self, name: str, actor: str) -> dict:
        if not self._is_valid_name(name):
            raise ValueError("Client name must match [a-zA-Z0-9_-] and be <= 15 chars")
        with storage.connection() as conn:
            exists = conn.execute(
                "SELECT 1 FROM amneziawg_clients WHERE name = ?", (name,)
            ).fetchone()
            if exists:
                raise ValueError(f"Client '{name}' already exists")
        ipv4 = self._next_ipv4()
        ipv6 = ""
        private_key = self._random_amneziawg_key()
        public_key = self._pubkey_from_private(private_key)
        if not public_key:
            raise ValueError(
                "Не удалось получить публичный ключ клиента (wg/cryptography)"
            )
        preshared_key = self._random_amneziawg_key()
        params = self.read_params()
        peer_pub = self._peer_public_key_for_client(params)
        endpoint = self._endpoint_from_params(params)
        if not endpoint:
            raise ValueError(
                "Укажите SERVER_PUB_IP и SERVER_PORT в "
                f"{self._params_path()} (или создайте файл через панель)"
            )
        if not peer_pub:
            raise ValueError(
                "Укажите SERVER_PUB_KEY в params или PrivateKey в [Interface] в "
                f"{self._server_conf_path()}"
            )
        clients_dir = settings.amneziawg_clients_dir
        clients_dir.mkdir(parents=True, exist_ok=True)
        config_file = clients_dir / f"{name}.conf"
        config_text = self._build_client_config_text(
            private_key=private_key,
            ipv4=ipv4,
            ipv6=ipv6,
            preshared_key=preshared_key,
            peer_public_key=peer_pub,
            endpoint=endpoint,
            params=params,
        )
        config_file.write_text(config_text, encoding="utf-8")
        try:
            with storage.connection() as conn:
                conn.execute(
                    "INSERT INTO amneziawg_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        name,
                        ipv4,
                        ipv6,
                        public_key,
                        private_key,
                        preshared_key,
                        str(config_file),
                        actor,
                        int(time.time()),
                    ),
                )
            self._sync_awg0_managed_peers()
            self._try_awg_syncconf()
        except Exception:
            with storage.connection() as conn:
                conn.execute("DELETE FROM amneziawg_clients WHERE name = ?", (name,))
            if config_file.exists():
                config_file.unlink()
            raise
        return {
            "name": name,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "public_key": public_key,
            "config_file": str(config_file),
        }

    def remove_client(self, name: str) -> bool:
        if not self._is_valid_name(name):
            raise ValueError("Недопустимое имя клиента")
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT config_file FROM amneziawg_clients WHERE name = ?", (name,)
            ).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM amneziawg_clients WHERE name = ?", (name,))
        cfg = Path(row["config_file"])
        if cfg.exists():
            cfg.unlink()
        try:
            self._sync_awg0_managed_peers()
            self._try_awg_syncconf()
        except FileNotFoundError:
            pass
        return True

    def rename_client(self, old_name: str, new_name: str) -> dict:
        if not self._is_valid_name(old_name) or not self._is_valid_name(new_name):
            raise ValueError("Both old_name and new_name must be valid client names")
        with storage.connection() as conn:
            old_row = conn.execute(
                "SELECT * FROM amneziawg_clients WHERE name = ?", (old_name,)
            ).fetchone()
            if not old_row:
                raise ValueError(f"Client '{old_name}' not found")
            new_exists = conn.execute(
                "SELECT 1 FROM amneziawg_clients WHERE name = ?", (new_name,)
            ).fetchone()
            if new_exists:
                raise ValueError(f"Client '{new_name}' already exists")
            new_cfg = str(
                settings.amneziawg_clients_dir / f"{new_name}.conf"
            )
            conn.execute("DELETE FROM amneziawg_clients WHERE name = ?", (old_name,))
            conn.execute(
                "INSERT INTO amneziawg_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    new_name,
                    old_row["ipv4"],
                    old_row["ipv6"],
                    old_row["public_key"],
                    old_row["private_key"],
                    old_row["preshared_key"],
                    new_cfg,
                    old_row["created_by"],
                    old_row["created_at"],
                ),
            )
        old_cfg_path = Path(old_row["config_file"])
        if old_cfg_path.exists():
            old_cfg_path.rename(new_cfg)
        try:
            self._sync_awg0_managed_peers()
            self._try_awg_syncconf()
        except FileNotFoundError:
            pass
        return {"success": True, "message": f"Renamed '{old_name}' to '{new_name}'"}

    def get_config(self, name: str) -> str | None:
        if not self._is_valid_name(name):
            raise ValueError("Недопустимое имя клиента")
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT config_file FROM amneziawg_clients WHERE name = ?", (name,)
            ).fetchone()
        if not row:
            return None
        cfg = Path(row["config_file"])
        if not cfg.exists():
            return None
        return cfg.read_text(encoding="utf-8")

    def get_stats(self, include_ip: bool = False) -> list[dict]:
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT name, ipv4 FROM amneziawg_clients ORDER BY name ASC"
            ).fetchall()
        stats = []
        for row in rows:
            item = {"name": row["name"], "activity": "unknown"}
            if include_ip:
                item["ip"] = row["ipv4"]
            stats.append(item)
        return stats


amneziawg = AmneziaWGService()
