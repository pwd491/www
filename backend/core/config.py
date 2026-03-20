from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Dashboard Web Console"
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
    adguard_querylog_path: Path = Path("/opt/AdGuardHome/data/querylog.json")
    adguard_home_yaml_path: Path = Path("/opt/AdGuardHome/AdGuardHome.yaml")
    zapret_domains_dir: Path = Path("/etc/zapret/domains")
    zapret_ipset_dir: Path = Path("/opt/zapret/ipset")

    model_config = SettingsConfigDict(env_file=".env", env_prefix="WEBAPP_", extra="ignore")


settings = Settings()
