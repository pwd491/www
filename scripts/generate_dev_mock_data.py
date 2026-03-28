#!/usr/bin/env python3
"""
Генерирует backend/dev-mock/ со случайными данными для вёрстки и локального теста.
Пути в .env см. backend/dev-mock.env.example (после генерации скопируйте в .env).

Запуск из корня репозитория:
  uv run python scripts/generate_dev_mock_data.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MOCK_ROOT = REPO_ROOT / "backend" / "dev-mock"


def _wg_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    raw = os.urandom(32)
    priv_b64 = base64.b64encode(raw).decode("ascii")
    sk = X25519PrivateKey.from_private_bytes(raw)
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub).decode("ascii")
    return priv_b64, pub_b64


def _client_conf(
    *,
    name: str,
    client_priv: str,
    psk: str,
    server_pub: str,
    ipv4: str,
    ipv6: str,
    endpoint: str,
    dns1: str,
    dns2: str,
) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {client_priv}\n"
        f"Address = {ipv4}/32,{ipv6}/128\n"
        f"DNS = {dns1}, {dns2}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "\n"
    )


def main() -> None:
    MOCK_ROOT.mkdir(parents=True, exist_ok=True)
    wg_dir = MOCK_ROOT / "wireguard"
    clients_dir = wg_dir / "clients"
    adguard_dir = MOCK_ROOT / "adguard"
    adguard_data = adguard_dir / "data"
    zapret_domains = MOCK_ROOT / "zapret" / "domains"
    zapret_ipset = MOCK_ROOT / "zapret" / "ipset"

    for d in (clients_dir, adguard_data, zapret_domains, zapret_ipset):
        d.mkdir(parents=True, exist_ok=True)

    server_priv, server_pub = _wg_keypair()
    endpoint_host = "203.0.113.7"
    port = "51820"
    endpoint = f"{endpoint_host}:{port}"

    dns1, dns2 = "1.1.1.1", "8.8.8.8"
    clients_spec = [
        ("alice", "10.66.66.2", "fd42:42:42::2"),
        ("bob", "10.66.66.3", "fd42:42:42::3"),
        ("laptop", "10.66.66.4", "fd42:42:42::4"),
    ]

    params_lines = [
        f"SERVER_PUB_IP={endpoint_host}",
        "SERVER_PUB_NIC=eth0",
        "SERVER_WG_NIC=wg0",
        "SERVER_WG_IPV4=10.66.66.0/24",
        "SERVER_WG_IPV6=fd42:42:42::/64",
        f"SERVER_PORT={port}",
        f"SERVER_PRIV_KEY={server_priv}",
        f"SERVER_PUB_KEY={server_pub}",
        f"CLIENT_DNS_1={dns1}",
        f"CLIENT_DNS_2={dns2}",
        "ALLOWED_IPS=0.0.0.0/0, ::/0",
    ]
    (wg_dir / "params").write_text("\n".join(params_lines) + "\n", encoding="utf-8")

    wg0_conf = (
        "[Interface]\n"
        f"PrivateKey = {server_priv}\n"
        "Address = 10.66.66.1/24, fd42:42:42::1/64\n"
        f"ListenPort = {port}\n"
        "\n"
    )
    (wg_dir / "wg0.conf").write_text(wg0_conf, encoding="utf-8")

    iface = "wg0"
    for name, ipv4, ipv6 in clients_spec:
        c_priv, _c_pub = _wg_keypair()
        psk = base64.b64encode(os.urandom(32)).decode("ascii")
        text = _client_conf(
            name=name,
            client_priv=c_priv,
            psk=psk,
            server_pub=server_pub,
            ipv4=ipv4,
            ipv6=ipv6,
            endpoint=endpoint,
            dns1=dns1,
            dns2=dns2,
        )
        (clients_dir / f"{iface}-client-{name}.conf").write_text(text, encoding="utf-8")

    ag_yaml = {
        "clients": {
            "persistent": [
                {"name": "Домашний ПК", "ids": ["192.168.1.10"]},
                {"name": "Телефон", "ids": ["192.168.1.20", "fd00::1"]},
            ]
        }
    }
    (adguard_dir / "AdGuardHome.yaml").write_text(
        yaml.safe_dump(ag_yaml, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )

    keywords = ["tracker", "ads", "metrics", "analytics"]
    now = datetime.now(timezone.utc)
    query_lines = []
    samples = [
        ("tracker.cdn.example.com", "192.168.1.10"),
        ("ads.doubleclick.test", "192.168.1.10"),
        ("metrics.api.example.org", "192.168.1.20"),
        ("analytics.google-test.local", "192.168.1.20"),
        ("ok.plain.net", "10.0.0.5"),
    ]
    for i, (domain, ip) in enumerate(samples):
        ts = now.isoformat()
        query_lines.append(
            json.dumps(
                {"T": ts, "QH": domain, "IP": ip},
                ensure_ascii=False,
            )
        )
    (adguard_data / "querylog.json").write_text(
        "\n".join(query_lines) + "\n",
        encoding="utf-8",
    )

    (zapret_domains / "zapret-hosts-user.txt").write_text(
        "blocked-one.example\n"
        "blocked-two.org\n"
        "cdn.tracker.fake\n",
        encoding="utf-8",
    )
    (zapret_ipset / "custom-ip.txt").write_text(
        "10.11.12.13\n"
        "192.0.2.0/24\n",
        encoding="utf-8",
    )

    from backend.services.storage import storage

    with storage.connection() as conn:
        conn.execute("DELETE FROM wireguard_clients")
        for kw in keywords:
            conn.execute(
                "INSERT OR IGNORE INTO dns_keywords(keyword) VALUES (?)",
                (kw,),
            )

    example = REPO_ROOT / "backend" / "dev-mock.env.example"
    example.write_text(
        "# Скопируйте в .env в корне репозитория после генерации dev-mock.\n"
        f"WEBAPP_WIREGUARD_DIR={MOCK_ROOT.relative_to(REPO_ROOT)}/wireguard\n"
        f"WEBAPP_WIREGUARD_PARAMS_PATH={MOCK_ROOT.relative_to(REPO_ROOT)}/wireguard/params\n"
        f"WEBAPP_ADGUARD_DATA_DIR={MOCK_ROOT.relative_to(REPO_ROOT)}/adguard/data\n"
        f"WEBAPP_ADGUARD_HOME_YAML_PATH={MOCK_ROOT.relative_to(REPO_ROOT)}/adguard/AdGuardHome.yaml\n"
        f"WEBAPP_ZAPRET_DOMAINS_DIR={MOCK_ROOT.relative_to(REPO_ROOT)}/zapret/domains\n"
        f"WEBAPP_ZAPRET_IPSET_DIR={MOCK_ROOT.relative_to(REPO_ROOT)}/zapret/ipset\n",
        encoding="utf-8",
    )

    print(f"Готово: {MOCK_ROOT}")
    print("Очистка клиентов в SQLite выполнена; при следующем запуске приложения клиенты импортируются с диска.")
    print(f"Добавьте в .env переменные из {example.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
