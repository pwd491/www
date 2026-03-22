import base64
import logging
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from .storage import storage
from ..core.config import settings

logger = logging.getLogger(__name__)


class WireGuardService:
    name_re = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")
    _WG_MANAGED_BEGIN = "### WEBPANEL-MANAGED-PEERS-BEGIN\n"
    _WG_MANAGED_END = "### WEBPANEL-MANAGED-PEERS-END\n"

    def _is_valid_name(self, name: str) -> bool:
        return bool(self.name_re.match(name))

    def _next_ipv4(self) -> str:
        with storage.connection() as conn:
            rows = conn.execute("SELECT ipv4 FROM wireguard_clients").fetchall()
        used = {int(r["ipv4"].split(".")[-1]) for r in rows if r["ipv4"].count(".") == 3}
        for n in range(2, 255):
            if n not in used:
                return f"10.66.66.{n}"
        raise ValueError("No available IPv4 addresses")

    def _next_ipv6(self) -> str:
        with storage.connection() as conn:
            rows = conn.execute("SELECT ipv6 FROM wireguard_clients").fetchall()
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

    def _random_wireguard_key(self) -> str:
        """32-byte Curve25519 key material, base64 (WireGuard-compatible)."""
        return base64.b64encode(os.urandom(32)).decode("ascii").rstrip("=")

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
                ["wg", "pubkey"],
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
        if not ipv4 or not ipv6:
            return None
        psk_m = re.search(
            r"^PresharedKey\s*=\s*(\S+)\s*$", text, re.MULTILINE | re.IGNORECASE
        )
        preshared = psk_m.group(1).strip() if psk_m else ""
        return {
            "private_key": priv_m.group(1).strip(),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "preshared_key": preshared,
        }

    def import_clients_from_disk(self) -> dict[str, list]:
        """Импорт клиентов из `{wireguard_dir}/clients/{iface}-client-*.conf` в БД (идемпотентно)."""
        iface = settings.wireguard_iface
        clients_dir = settings.wireguard_dir / "clients"
        imported: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []
        if not clients_dir.is_dir():
            return {"imported": imported, "skipped": skipped, "errors": errors}
        pat = re.compile(rf"^{re.escape(iface)}-client-(.+)\.conf$")
        for path in sorted(clients_dir.glob(f"{iface}-client-*.conf")):
            if not path.is_file():
                continue
            m = pat.match(path.name)
            if not m:
                continue
            name = m.group(1)
            if not self._is_valid_name(name):
                errors.append(f"{path.name}: недопустимое имя клиента")
                continue
            with storage.connection() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM wireguard_clients WHERE name = ?", (name,)
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
                errors.append(f"{path.name}: нет PrivateKey/Address (IPv4+IPv6)")
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
                        "INSERT INTO wireguard_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    self._sync_wg0_managed_peers()
                    self._try_wg_syncconf()
            except OSError as e:
                logger.warning("WireGuard: после импорта не обновлён wg0.conf: %s", e)
        if imported or errors:
            logger.info(
                "WireGuard импорт с диска: добавлено %s, пропущено %s, ошибок %s",
                len(imported),
                len(skipped),
                len(errors),
            )
        return {"imported": imported, "skipped": skipped, "errors": errors}

    def list_clients(self) -> list[dict]:
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT name, ipv4, ipv6, public_key, config_file, created_by, created_at "
                "FROM wireguard_clients ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def _wg_handshakes_by_ipv4(self) -> dict[str, int]:
        """Map client tunnel IPv4 -> latest handshake unix time from `wg show` (0 = never)."""
        iface = settings.wireguard_iface
        try:
            proc = subprocess.run(
                ["wg", "show", iface, "dump"],
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
        return settings.wireguard_dir / f"{settings.wireguard_iface}.conf"

    def _clients_for_server_sync(self) -> list[dict]:
        with storage.connection() as conn:
            rows = conn.execute(
                "SELECT name, ipv4, ipv6, public_key, preshared_key "
                "FROM wireguard_clients ORDER BY name ASC"
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
            lines.append(f"AllowedIPs = {c['ipv4']}/32,{c['ipv6']}/128")
            lines.append("")
        return "\n".join(lines)

    def _sync_wg0_managed_peers(self) -> None:
        path = self._server_conf_path()
        if not path.is_file():
            raise FileNotFoundError(
                f"Нет файла конфигурации сервера WireGuard: {path}"
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

    def _try_wg_syncconf(self) -> None:
        """Применить wg0.conf к работающему интерфейсу (если доступны wg / wg-quick)."""
        conf = self._server_conf_path()
        iface = settings.wireguard_iface
        try:
            strip = subprocess.run(
                ["wg-quick", "strip", str(conf)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if strip.returncode != 0:
                return
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".conf",
                delete=False,
                encoding="utf-8",
            ) as tf:
                tf.write(strip.stdout)
                tmp = tf.name
            try:
                subprocess.run(
                    ["wg", "syncconf", iface, tmp],
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
            finally:
                Path(tmp).unlink(missing_ok=True)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def add_client(self, name: str, actor: str) -> dict:
        if not self._is_valid_name(name):
            raise ValueError("Client name must match [a-zA-Z0-9_-] and be <= 15 chars")
        with storage.connection() as conn:
            exists = conn.execute(
                "SELECT 1 FROM wireguard_clients WHERE name = ?", (name,)
            ).fetchone()
            if exists:
                raise ValueError(f"Client '{name}' already exists")
        ipv4 = self._next_ipv4()
        ipv6 = self._next_ipv6()
        private_key = self._random_wireguard_key()
        public_key = self._pubkey_from_private(private_key)
        if not public_key:
            raise ValueError(
                "Не удалось получить публичный ключ клиента (wg/cryptography)"
            )
        preshared_key = self._random_wireguard_key()
        clients_dir = settings.wireguard_dir / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        config_file = clients_dir / f"{settings.wireguard_iface}-client-{name}.conf"
        config_text = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {ipv4}/32,{ipv6}/128\n\n"
            "[Peer]\n"
            "PublicKey = SERVER_PUBLIC_KEY_PLACEHOLDER\n"
            f"PresharedKey = {preshared_key}\n"
            "Endpoint = SERVER_ENDPOINT_PLACEHOLDER\n"
            "AllowedIPs = 0.0.0.0/0,::/0\n"
        )
        config_file.write_text(config_text, encoding="utf-8")
        try:
            with storage.connection() as conn:
                conn.execute(
                    "INSERT INTO wireguard_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            self._sync_wg0_managed_peers()
            self._try_wg_syncconf()
        except Exception:
            with storage.connection() as conn:
                conn.execute("DELETE FROM wireguard_clients WHERE name = ?", (name,))
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
                "SELECT config_file FROM wireguard_clients WHERE name = ?", (name,)
            ).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM wireguard_clients WHERE name = ?", (name,))
        cfg = Path(row["config_file"])
        if cfg.exists():
            cfg.unlink()
        try:
            self._sync_wg0_managed_peers()
            self._try_wg_syncconf()
        except FileNotFoundError:
            pass
        return True

    def rename_client(self, old_name: str, new_name: str) -> dict:
        if not self._is_valid_name(old_name) or not self._is_valid_name(new_name):
            raise ValueError("Both old_name and new_name must be valid client names")
        with storage.connection() as conn:
            old_row = conn.execute(
                "SELECT * FROM wireguard_clients WHERE name = ?", (old_name,)
            ).fetchone()
            if not old_row:
                raise ValueError(f"Client '{old_name}' not found")
            new_exists = conn.execute(
                "SELECT 1 FROM wireguard_clients WHERE name = ?", (new_name,)
            ).fetchone()
            if new_exists:
                raise ValueError(f"Client '{new_name}' already exists")
            new_cfg = str(
                settings.wireguard_dir
                / "clients"
                / f"{settings.wireguard_iface}-client-{new_name}.conf"
            )
            conn.execute("DELETE FROM wireguard_clients WHERE name = ?", (old_name,))
            conn.execute(
                "INSERT INTO wireguard_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            self._sync_wg0_managed_peers()
            self._try_wg_syncconf()
        except FileNotFoundError:
            pass
        return {"success": True, "message": f"Renamed '{old_name}' to '{new_name}'"}

    def get_config(self, name: str) -> str | None:
        if not self._is_valid_name(name):
            raise ValueError("Недопустимое имя клиента")
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT config_file FROM wireguard_clients WHERE name = ?", (name,)
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
                "SELECT name, ipv4 FROM wireguard_clients ORDER BY name ASC"
            ).fetchall()
        stats = []
        for row in rows:
            item = {"name": row["name"], "activity": "unknown"}
            if include_ip:
                item["ip"] = row["ipv4"]
            stats.append(item)
        return stats


wireguard_service = WireGuardService()
