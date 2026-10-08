# PhishGuard Database

Relational database design for **PhishGuard**, a phishing URL analysis system. It stores users, submitted URLs, domains, ML models, predictions, suspicious alerts, and activity history while keeping ML inference outside the database.

## ER Diagram

![PhishGuard Database ER Diagram]([docs/Phishguard_db_diagram.png](https://github.com/Bilal-gul/phishguard-database/blob/main/e-r%20diagram/Phishguard_db_diagram.png))

## Schema

| Table | Purpose |
|---|---|
| `users` | User accounts and account status |
| `sessions` | Login sessions |
| `domains` | Domain information and Tranco rank |
| `user_urls` | URLs submitted by users |
| `models` | ML model registry |
| `features_dictionary` | Definitions of ML features |
| `model_features` | Model ↔ feature many-to-many mapping |
| `predictions` | Model prediction results |
| `suspicious_analyses` | Alerts for suspicious predictions |
| `activity_logs` | User activity audit trail |

### Main relationships

```text
users 1 ─── N sessions
users 1 ─── N user_urls
users 1 ─── N activity_logs

domains 1 ─── N user_urls

models M ─── N features_dictionary
          via model_features

user_urls 1 ─── N predictions
models    1 ─── N predictions
predictions 1 ─── N suspicious_analyses
```

## Constraints

**Primary keys:** Every table has a PK. `model_features` uses a composite PK: `(model_id, feature_id)`.

**Unique:**
- `users.username`
- `users.email`
- `domains.domain_name`
- `features_dictionary.feature_name`

**Checks:**
- `predictions.predicted_label` → `0` or `1`
- `predictions.probability` → `0 <= probability <= 1`
- `activity_logs.action` → `REGISTER`, `LOGIN`, `URL_ANALYSIS`, `LOGOUT`

**Foreign keys:**

```text
sessions.user_id              → users.user_id
user_urls.user_id             → users.user_id
user_urls.domain_id           → domains.domain_id
model_features.model_id      → models.model_id
model_features.feature_id    → features_dictionary.feature_id
predictions.url_id            → user_urls.url_id
predictions.model_id          → models.model_id
suspicious_analyses.prediction_id → predictions.prediction_id
activity_logs.user_id         → users.user_id
```

## Database Features

### Indexes

Indexes should be added to frequently queried foreign keys and history-related columns to improve query performance.

### View — `analysis_history`

Combines `user_urls`, `domains`, `predictions`, and `models` to provide a convenient URL analysis history without repeating the same joins.

### Triggers

**1. URL analysis logging**  
When a row is inserted into `user_urls`, an automatic `URL_ANALYSIS` entry is added to `activity_logs`.

**2. Suspicious prediction detection**  
When a prediction is inserted, an alert is created when:

```text
predicted_label = 0
AND domain.tranco_rank <= 10000
```

Example reason:

> Phishing prediction on a Top-10000 Tranco domain

### Stored Procedure — `record_url_analysis()`

Handles the database side of a URL analysis in one transaction:

```text
Ensure/create domain
      ↓
Create user_urls record
      ↓
Create prediction record
```

Feature extraction and ML inference are performed by the application, not by the procedure.

### Transactions

URL-analysis operations should be executed transactionally so that a failed operation does not leave incomplete or inconsistent records.

## Project Architecture

```text
Application / Web UI
        │
        ├── URL & Feature Extraction
        ├── ML Model Inference
        │
        ▼
   PhishGuard Database
        ├── Users & Sessions
        ├── URLs & Domains
        ├── Models & Features
        ├── Predictions
        ├── Alerts
        └── Activity Logs
```

## Goal

The database provides a structured and reliable backend for PhishGuard, supporting **analysis history, ML model management, suspicious-case detection, auditing, and data integrity**.
