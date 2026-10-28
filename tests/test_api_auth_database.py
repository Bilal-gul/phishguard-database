import os
import time

os.environ["PHISHGUARD_SESSION_SECRET"] = "test-only-session-secret-value-32-chars-min"

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError

from PhishGuard.backend.auth import (
    COOKIE_NAME,
    SESSION_TTL_SECONDS,
    _hash_password,
    _make_cookie_token,
    _read_cookie_token,
    _set_session_cookie,
    _verify_password,
    get_current_user,
)
from PhishGuard.backend.database import _odbc_value
from PhishGuard.backend import database
from PhishGuard.backend import api
from PhishGuard.backend.schemas import DatabaseHealthResponse, URLAnalysisRequest


def test_url_request_validation_rejects_empty_and_overlong_values():
    with pytest.raises(ValidationError):
        URLAnalysisRequest(url="")
    with pytest.raises(ValidationError):
        URLAnalysisRequest(url="  ")
    with pytest.raises(ValidationError):
        URLAnalysisRequest(url="x" * 2049)


def test_password_hash_verification_and_signed_session_token():
    password_hash = _hash_password("correct horse battery")
    assert _verify_password("correct horse battery", password_hash)
    assert not _verify_password("wrong password", password_hash)

    token = _make_cookie_token(7, 11, issued_at=int(time.time()))
    assert _read_cookie_token(token) == (7, 11)
    with pytest.raises(HTTPException) as error:
        _read_cookie_token(token + "x")
    assert error.value.status_code == 401


def test_auth_cookie_is_http_only_lax_and_uses_configured_secure_flag():
    response = Response()
    _set_session_cookie(response, "signed-token")
    cookie = response.headers["set-cookie"].lower()
    assert f"{COOKIE_NAME}=signed-token" in cookie
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert f"max-age={SESSION_TTL_SECONDS}" in cookie


def test_missing_session_is_rejected_before_database_access():
    from starlette.requests import Request

    request = Request({"type": "http", "headers": [], "method": "GET", "path": "/auth/me", "query_string": b"", "server": ("test", 80), "client": ("test", 1), "scheme": "http"})
    with pytest.raises(HTTPException) as error:
        get_current_user(request)
    assert error.value.status_code == 401


def test_odbc_connection_values_are_braced_and_escape_closing_braces():
    assert _odbc_value("server};UID=attacker") == "{server}};UID=attacker}"


def test_database_health_response_does_not_include_server_identity(monkeypatch):
    class Cursor:
        def execute(self, query):
            assert query == "SELECT 1"

        def fetchone(self):
            return (1,)

        def close(self):
            pass

    class Connection:
        closed = False

        def cursor(self):
            return Cursor()

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(database, "get_connection", lambda: connection)
    health = database.check_connection()
    assert health == {"connected": True, "database": None, "login": None}
    assert DatabaseHealthResponse.model_validate(health).model_dump() == health
    health_route = next(route for route in api.router.routes if route.path == "/health/database")
    assert health_route.response_model is DatabaseHealthResponse
    assert connection.closed


def test_database_health_error_response_does_not_leak_exception_text(monkeypatch):
    monkeypatch.setattr(database, "check_connection", lambda: (_ for _ in ()).throw(RuntimeError("sensitive-login")))
    with pytest.raises(HTTPException) as error:
        api.database_health()
    assert error.value.status_code == 500
    assert "sensitive-login" not in error.value.detail


def test_trigger_aware_result_set_reader_skips_non_row_statements():
    class Cursor:
        description = None
        sets_advanced = 0

        def nextset(self):
            self.sets_advanced += 1
            self.description = [("id",)] if self.sets_advanced == 2 else None
            return self.sets_advanced <= 2

        def fetchone(self):
            return (42,)

    assert api._fetchone_from_result_sets(Cursor()) == (42,)


class _PredictionCursor:
    def __init__(self, fail_on_prediction=False):
        self.description = None
        self.row = None
        self.next_row = None
        self.calls = []
        self.fail_on_prediction = fail_on_prediction

    def execute(self, query, *parameters):
        self.calls.append((query, parameters))
        if "FROM dbo.users" in query:
            self.description, self.row = [("user_id",)], (7,)
        elif "FROM dbo.models" in query:
            self.description, self.row = [("model_id",)], (3,)
        elif "SELECT domain_id FROM dbo.domains" in query:
            self.description, self.row = [("domain_id",)], None
        elif "INSERT INTO dbo.predictions" in query and self.fail_on_prediction:
            raise RuntimeError("simulated persistence failure")
        elif "INSERT INTO dbo.domains" in query:
            self.description, self.row, self.next_row = None, None, (11,)
        elif "INSERT INTO dbo.user_urls" in query:
            self.description, self.row, self.next_row = None, None, (21,)
        elif "INSERT INTO dbo.predictions" in query:
            self.description, self.row, self.next_row = None, None, (31,)

    def nextset(self):
        if self.next_row is None:
            return False
        self.description, self.row = [("id",)], self.next_row
        self.next_row = None
        return True

    def fetchone(self):
        return self.row

    def close(self):
        pass


class _PredictionConnection:
    def __init__(self, fail_on_prediction=False):
        self.db_cursor = _PredictionCursor(fail_on_prediction)
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.db_cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


def _fake_prediction(url):
    return {
        "url": url,
        "prediction": 0,
        "result": "PHISHING",
        "phishing_probability": 87.0,
        "legitimate_probability": 13.0,
        "full_domain": "example.com",
    }


def test_prediction_write_commits_all_records_as_one_transaction(monkeypatch):
    connection = _PredictionConnection()
    monkeypatch.setattr(api, "_prediction_function", lambda: _fake_prediction)
    monkeypatch.setattr(api, "get_connection", lambda: connection)

    result = api.predict_url_endpoint(URLAnalysisRequest(url="https://example.com/login"), {"user_id": 7})

    assert result["database"]["saved"] is True
    assert result["database"]["probability_semantics"] == "confidence_in_predicted_class"
    assert connection.committed
    assert not connection.rolled_back
    inserted = [query for query, _ in connection.db_cursor.calls if "INSERT INTO" in query]
    assert len(inserted) == 3


def test_prediction_write_rolls_back_if_a_record_insert_fails(monkeypatch):
    connection = _PredictionConnection(fail_on_prediction=True)
    monkeypatch.setattr(api, "_prediction_function", lambda: _fake_prediction)
    monkeypatch.setattr(api, "get_connection", lambda: connection)

    with pytest.raises(HTTPException) as error:
        api.predict_url_endpoint(URLAnalysisRequest(url="https://example.com/login"), {"user_id": 7})

    assert error.value.status_code == 500
    assert "simulated persistence failure" not in error.value.detail
    assert connection.rolled_back
    assert not connection.committed
