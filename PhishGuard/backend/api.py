"""PhishGuard API router: URL prediction, user-scoped history, statistics, and alerts."""
from __future__ import annotations

from typing import Any

import pyodbc
from fastapi import APIRouter, Depends, HTTPException, Query

from .auth import get_current_user
from .database import get_connection
from .schemas import URLAnalysisRequest

router = APIRouter(tags=["PhishGuard"])


def _fetchone_from_result_sets(cursor):
    """Return one row from the first result set that actually has columns.

    pyodbc may first expose a non-row result from a DML statement or trigger.
    Advancing with nextset() avoids calling fetchone() while no query results exist.
    """
    while cursor.description is None:
        if not cursor.nextset():
            return None
    return cursor.fetchone()


def _active_model_id(cursor) -> int:
    cursor.execute("""
        SELECT TOP (1) model_id
        FROM dbo.models
        WHERE is_active = 1
        ORDER BY created_at DESC, model_id DESC
    """)
    row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=500, detail="dbo.models tablosunda aktif model kaydı bulunamadı.")
    return int(row[0])


def _get_or_create_domain(cursor, domain_name: str) -> int:
    cursor.execute("SELECT domain_id FROM dbo.domains WHERE domain_name = ?", domain_name)
    row = cursor.fetchone()
    if row:
        return int(row[0])

    cursor.execute("""
        DECLARE @InsertedDomainIds TABLE (domain_id INT);
        INSERT INTO dbo.domains (domain_name, tranco_rank)
        OUTPUT INSERTED.domain_id INTO @InsertedDomainIds (domain_id)
        VALUES (?, NULL);
        SELECT domain_id FROM @InsertedDomainIds;
    """, domain_name)
    row = _fetchone_from_result_sets(cursor)
    if row is None:
        raise RuntimeError("domain_id INSERT sonucundan alınamadı.")
    return int(row[0])


def _prediction_function():
    try:
        from predict import predict_url
        return predict_url
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"predict.py içindeki predict_url yüklenemedi: {exc}") from exc


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/database")
def database_health() -> dict[str, Any]:
    try:
        from .database import check_connection
        return check_connection()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SQL Server bağlantısı başarısız: {exc}") from exc


@router.post("/predict")
def predict_url_endpoint(
    request: URLAnalysisRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    predict_url = _prediction_function()
    try:
        result = predict_url(request.url)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"URL tahmini başarısız: {exc}") from exc

    predicted_label = int(result["prediction"])
    confidence_percent = (
        result["phishing_probability"] if predicted_label == 0 else result["legitimate_probability"]
    )
    confidence = float(confidence_percent) / 100.0
    domain_name = result.get("full_domain")
    if not domain_name:
        raise HTTPException(status_code=400, detail="URL domain bilgisi çıkarılamadı.")

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        user_id = int(current_user["user_id"])
        cursor.execute("SELECT user_id FROM dbo.users WHERE user_id = ? AND is_active = 1", user_id)
        if cursor.fetchone() is None:
            raise HTTPException(status_code=401, detail="Kullanıcı hesabı aktif değil.")

        model_id = _active_model_id(cursor)
        domain_id = _get_or_create_domain(cursor, domain_name)
        # OUTPUT without INTO is not allowed on tables with enabled triggers.
        # user_urls has an AFTER INSERT trigger, so capture the identity in a table variable.
        cursor.execute("""
            DECLARE @InsertedUrlIds TABLE (url_id INT);
            INSERT INTO dbo.user_urls (user_id, domain_id, url)
            OUTPUT INSERTED.url_id INTO @InsertedUrlIds (url_id)
            VALUES (?, ?, ?);
            SELECT url_id FROM @InsertedUrlIds;
        """, user_id, domain_id, result["url"])
        row = _fetchone_from_result_sets(cursor)
        if row is None:
            raise RuntimeError("url_id INSERT sonucundan alınamadı.")
        url_id = int(row[0])

        # predictions also has an AFTER INSERT trigger; use OUTPUT INTO here too.
        cursor.execute("""
            DECLARE @InsertedPredictionIds TABLE (prediction_id INT);
            INSERT INTO dbo.predictions (url_id, model_id, predicted_label, probability)
            OUTPUT INSERTED.prediction_id INTO @InsertedPredictionIds (prediction_id)
            VALUES (?, ?, ?, ?);
            SELECT prediction_id FROM @InsertedPredictionIds;
        """, url_id, model_id, predicted_label, confidence)
        row = _fetchone_from_result_sets(cursor)
        if row is None:
            raise RuntimeError("prediction_id INSERT sonucundan alınamadı.")
        prediction_id = int(row[0])

        connection.commit()
        result["confidence"] = round(confidence * 100.0, 2)
        result["database"] = {
            "saved": True,
            "user_id": user_id,
            "domain_id": domain_id,
            "url_id": url_id,
            "prediction_id": prediction_id,
            "model_id": model_id,
            "probability_semantics": "confidence_in_predicted_class",
        }
        return result
    except HTTPException:
        if connection is not None:
            connection.rollback()
        raise
    except Exception as exc:
        if connection is not None:
            connection.rollback()
        raise HTTPException(status_code=500, detail=f"Tahmin üretildi fakat veritabanına kaydedilemedi: {exc}") from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


@router.get("/history")
def analysis_history(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT TOP (?)
                u.url_id, u.url, d.domain_name,
                p.prediction_id, p.predicted_label, p.probability, p.predicted_at,
                m.model_name, m.version,
                sa.alert_id, sa.severity, sa.reason, sa.is_reviewed
            FROM dbo.user_urls AS u
            INNER JOIN dbo.domains AS d ON d.domain_id = u.domain_id
            INNER JOIN dbo.predictions AS p ON p.url_id = u.url_id
            INNER JOIN dbo.models AS m ON m.model_id = p.model_id
            LEFT JOIN dbo.suspicious_analyses AS sa ON sa.prediction_id = p.prediction_id
            WHERE u.user_id = ?
            ORDER BY p.predicted_at DESC, p.prediction_id DESC
        """, limit, int(current_user["user_id"]))
        columns = [column[0] for column in cursor.description]
        items = []
        for row in cursor.fetchall():
            item = dict(zip(columns, row))
            label = int(item["predicted_label"])
            item["predicted_label"] = label
            item["result"] = "PHISHING" if label == 0 else "LEGITIMATE"
            item["probability"] = float(item["probability"])
            item["confidence_percent"] = round(item["probability"] * 100, 2)
            if item["predicted_at"] is not None:
                item["predicted_at"] = item["predicted_at"].isoformat()
            if item["is_reviewed"] is not None:
                item["is_reviewed"] = bool(item["is_reviewed"])
            items.append(item)
        return {"user_id": int(current_user["user_id"]), "count": len(items), "items": items}
    except pyodbc.Error as exc:
        raise HTTPException(status_code=500, detail=f"Analiz geçmişi alınamadı: {exc}") from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


@router.get("/stats")
def analysis_stats(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    connection = None
    cursor = None
    user_id = int(current_user["user_id"])
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT
                COUNT_BIG(*) AS total,
                SUM(CASE WHEN p.predicted_label = 0 THEN 1 ELSE 0 END) AS phishing,
                SUM(CASE WHEN p.predicted_label = 1 THEN 1 ELSE 0 END) AS legitimate
            FROM dbo.user_urls AS u
            INNER JOIN dbo.predictions AS p ON p.url_id = u.url_id
            WHERE u.user_id = ?
        """, user_id)
        row = cursor.fetchone()
        total, phishing, legitimate = int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)

        cursor.execute("""
            SELECT COUNT_BIG(*)
            FROM dbo.user_urls AS u
            INNER JOIN dbo.predictions AS p ON p.url_id = u.url_id
            INNER JOIN dbo.suspicious_analyses AS sa ON sa.prediction_id = p.prediction_id
            WHERE u.user_id = ? AND sa.is_reviewed = 0
        """, user_id)
        unreviewed = int(cursor.fetchone()[0] or 0)
        return {
            "user_id": user_id,
            "total_analyses": total,
            "phishing": phishing,
            "legitimate": legitimate,
            "unreviewed_alerts": unreviewed,
        }
    except pyodbc.Error as exc:
        raise HTTPException(status_code=500, detail=f"İstatistikler alınamadı: {exc}") from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


@router.get("/alerts")
def suspicious_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT TOP (?)
                sa.alert_id, sa.prediction_id, sa.reason, sa.severity,
                sa.created_at, sa.is_reviewed, u.url, d.domain_name,
                p.predicted_label, p.probability
            FROM dbo.suspicious_analyses AS sa
            INNER JOIN dbo.predictions AS p ON p.prediction_id = sa.prediction_id
            INNER JOIN dbo.user_urls AS u ON u.url_id = p.url_id
            INNER JOIN dbo.domains AS d ON d.domain_id = u.domain_id
            WHERE u.user_id = ?
            ORDER BY sa.created_at DESC, sa.alert_id DESC
        """, limit, int(current_user["user_id"]))
        columns = [column[0] for column in cursor.description]
        items = []
        for row in cursor.fetchall():
            item = dict(zip(columns, row))
            item["probability"] = float(item["probability"])
            item["confidence_percent"] = round(item["probability"] * 100, 2)
            item["is_reviewed"] = bool(item["is_reviewed"])
            if item["created_at"] is not None:
                item["created_at"] = item["created_at"].isoformat()
            items.append(item)
        return {"user_id": int(current_user["user_id"]), "count": len(items), "items": items}
    except pyodbc.Error as exc:
        raise HTTPException(status_code=500, detail=f"Şüpheli analizler alınamadı: {exc}") from exc
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()
