
"""SQL Server connection helpers for local development and Docker."""

import os

import pyodbc


def _odbc_value(value: str) -> str:
    """Escape a value for an ODBC connection string."""
    return "{" + value.replace("}", "}}") + "}"


def get_connection():
    server = os.getenv(
        "PHISHGUARD_SQL_SERVER",
        r".\SQLEXPRESS",
    )
    database = os.getenv(
        "PHISHGUARD_SQL_DATABASE",
        "PhishGuardDB",
    )
    auth_mode = os.getenv(
        "PHISHGUARD_SQL_AUTH",
        "windows",
    ).strip().lower()

    installed = pyodbc.drivers()
    driver = next(
        (
            name
            for name in (
                "ODBC Driver 18 for SQL Server",
                "ODBC Driver 17 for SQL Server",
            )
            if name in installed
        ),
        None,
    )

    if driver is None:
        raise RuntimeError(
            "ODBC Driver 17 or 18 for SQL Server bulunamadı. "
            f"Installed drivers: {installed}"
        )

    parts = [
        f"DRIVER={{{driver}}}",
        f"SERVER={_odbc_value(server)}",
        f"DATABASE={_odbc_value(database)}",
        "Encrypt=yes",
        "TrustServerCertificate=yes",
    ]

    if auth_mode in ("windows", "trusted", "integrated"):
        parts.append("Trusted_Connection=yes")

    elif auth_mode in ("sql", "sqlserver", "password"):
        username = os.getenv("PHISHGUARD_SQL_USER")
        password = os.getenv("PHISHGUARD_SQL_PASSWORD")

        if not username or not password:
            raise RuntimeError(
                "SQL Authentication için "
                "PHISHGUARD_SQL_USER ve PHISHGUARD_SQL_PASSWORD gerekli."
            )

        parts.extend([
            f"UID={_odbc_value(username)}",
            f"PWD={_odbc_value(password)}",
        ])

    else:
        raise RuntimeError(
            "PHISHGUARD_SQL_AUTH windows veya sql olmalı."
        )

    connection_string = ";".join(parts) + ";"
    return pyodbc.connect(connection_string, timeout=5)


def check_connection() -> dict:
    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT DB_NAME(), SUSER_SNAME()")
        database_name, login_name = cursor.fetchone()
        cursor.close()

        return {
            "connected": True,
            "database": database_name,
            "login": login_name,
        }
    finally:
        connection.close()
