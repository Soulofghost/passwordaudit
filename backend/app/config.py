import os

PORT = int(os.getenv("PASSWORDAUDIT_PORT", "8000"))
DB_PATH = os.getenv("PASSWORDAUDIT_DB_PATH", "backend/data/passwordaudit.db")
