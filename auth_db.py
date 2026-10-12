import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = Path(__file__).resolve().parent / "users.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_auth_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)


def create_user(name, email, password):
    name = name.strip()
    email = email.strip().lower()

    password_hash = generate_password_hash(password)

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO users (name, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (name, email, password_hash)
        )
        return cursor.lastrowid


def get_user_by_email(email):
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email.strip().lower(),)
        ).fetchone()


def verify_password(user, password):
    return (
        user is not None
        and check_password_hash(user["password_hash"], password)
    )