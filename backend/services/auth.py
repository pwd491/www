from ..core.config import settings
from ..core.security import hash_password, verify_password
from .storage import storage


class AuthService:
    def __init__(self) -> None:
        self._ensure_default_admin()

    def _ensure_default_admin(self) -> None:
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT username FROM users WHERE username = ?",
                (settings.admin_username,),
            ).fetchone()
            if row:
                return
            conn.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (settings.admin_username, hash_password(settings.admin_password)),
            )

    def authenticate(self, username: str, password: str) -> bool:
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not row:
                return False
            return verify_password(password, row["password_hash"])


auth_service = AuthService()
