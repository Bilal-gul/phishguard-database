"""Pydantic request/response schemas used by the API."""
from pydantic import BaseModel, ConfigDict, Field


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Analiz edilecek URL")


class URLAnalysisResponse(BaseModel):
    url: str
    prediction: int
    result: str
    phishing_probability: float
    legitimate_probability: float
    full_domain: str | None = None
    confidence: float
    database: dict | None = None


class HealthResponse(BaseModel):
    status: str


class AnalysisHistoryItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    url_id: int
    url: str
    domain_name: str
    prediction_id: int
    predicted_label: int
    result: str
    probability: float
    confidence_percent: float
    predicted_at: str | None = None
    model_name: str | None = None
    version: str | None = None
    alert_id: int | None = None
    severity: str | None = None
    reason: str | None = None
    is_reviewed: bool | None = None


class AnalysisHistoryResponse(BaseModel):
    user_id: int
    count: int
    items: list[AnalysisHistoryItem]


class AnalysisStatsResponse(BaseModel):
    user_id: int
    total_analyses: int
    phishing: int
    legitimate: int
    unreviewed_alerts: int
