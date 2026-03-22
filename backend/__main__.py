import argparse
import json
from pathlib import Path

import uvicorn

_LOG_CONFIG_PATH = Path(__file__).resolve().parent / "logging.json"


def _load_log_config(log_level: str) -> dict:
    """dictConfig как у Uvicorn (--log-config), плюс логгер приложения `backend`."""
    with _LOG_CONFIG_PATH.open(encoding="utf-8") as f:
        cfg: dict = json.load(f)
    level = log_level.upper()
    cfg.setdefault("loggers", {}).setdefault("backend", {})["level"] = level
    return cfg


def main(
    host: str,
    port: int,
    reload: bool,
    log_level: str,
    access_log: bool,
) -> None:
    log_config = _load_log_config(log_level) if _LOG_CONFIG_PATH.is_file() else None
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=reload,
        log_config=log_config,
        log_level=log_level,
        access_log=access_log,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dashboard Web Console")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to run the server on")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    parser.add_argument("--reload", action="store_true", help="Reload the server on code changes")
    parser.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=("critical", "error", "warning", "info", "debug", "trace"),
        help="Uvicorn / app log level (see uvicorn.dev settings — Logging)",
    )
    parser.add_argument(
        "--no-access-log",
        action="store_true",
        help="Disable HTTP access log (uvicorn --no-access-log)",
    )
    args = parser.parse_args()
    main(
        args.host,
        args.port,
        args.reload,
        log_level=args.log_level,
        access_log=not args.no_access_log,
    )
