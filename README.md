
```bash
uv run python -m backend
```

```bash
cp dashboard.service /etc/systemd/system/dashboard.service
systemctl daemon-reload
systemctl enable dashboard.service
systemctl start dashboard.service
```