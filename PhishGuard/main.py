"""PhishGuard FastAPI application entry point.

Run from the project root:
    python -m uvicorn main:app --reload
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="PhishGuard API",
    description="Phishing URL detection with ML, SQL Server persistence, and user sessions.",
    version="2.0.0",
)

from backend.auth import auth_router  # noqa: E402
from backend.api import router as backend_router  # noqa: E402

app.include_router(auth_router)
app.include_router(backend_router)


@app.get("/api-info", tags=["System"])
def api_info():
    return {
        "name": "PhishGuard",
        "status": "running",
        "docs": "/docs",
        "frontend": "/" if FRONTEND_DIR.is_dir() else None,
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon_not_found():
    return JSONResponse(status_code=404, content={"detail": "Favicon not configured"})


# Serve frontend last so the registered API endpoints are handled first.
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    @app.get("/", tags=["System"])
    def root():
        return {"name": "PhishGuard API", "status": "running", "message": "frontend/ folder not found", "docs": "/docs"}
