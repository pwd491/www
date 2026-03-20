from .storage import storage


class SettingsService:
    key = "KEEP_FORWARDED"

    def get_keep_forwarded(self) -> bool:
        with storage.connection() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?",
                (self.key,),
            ).fetchone()
        return bool(row and row["value"] == "1")

    def set_keep_forwarded(self, enabled: bool) -> bool:
        with storage.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO app_settings(key, value) VALUES (?, ?)",
                (self.key, "1" if enabled else "0"),
            )
        return enabled


settings_service = SettingsService()
