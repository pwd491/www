import uvicorn
import argparse

def main(host: str, port: int, reload: bool) -> None:
    uvicorn.run("backend.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Userbot Web Console")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to run the server on")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    parser.add_argument("--reload", action="store_true", help="Reload the server on code changes")
    args = parser.parse_args()
    main(args.host, args.port, args.reload)
