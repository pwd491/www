from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Dashboard Web Console"
    cors_origins: list[str] = Field(default_factory=list)
    jwt_secret_key: str = Field("change-me-in-env", min_length=12)
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 5_256_000

    admin_username: str = "admin"
    admin_password: str = "admin123"

    data_dir: Path = Path("backend/data")
    app_db_path: Path = Path("backend/data/webapp.sqlite3")
    env_file_path: Path = Path(".env")

    wireguard_dir: Path = Path("/etc/wireguard")
    wireguard_iface: str = "wg0"
    wireguard_params_path: Path = Path("/etc/wireguard/params")
    amneziawg_dir: Path = Path("/etc/amnezia/amneziawg")
    amneziawg_iface: str = "awg0"
    amneziawg_clients_dir: Path = Path("/root/awg")
    amneziawg_params_path: Path = Path("/root/awg/awgsetup_cfg.init")
    adguard_data_dir: Path = Path("/opt/AdGuardHome/data")
    adguard_home_yaml_path: Path = Path("/opt/AdGuardHome/AdGuardHome.yaml")
    zapret_domains_dir: Path = Path("/etc/zapret/domains")
    zapret_ipset_dir: Path = Path("/opt/zapret/ipset")
    backup_storage_dir: Path = Path("backend/data/backups")

    model_config = SettingsConfigDict(env_file=".env", env_prefix="WEBAPP_", extra="ignore")


settings = Settings()
