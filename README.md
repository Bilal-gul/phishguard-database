# PhishGuard

**Machine learning–based phishing URL detection with a relational database backend.**

PhishGuard is a cybersecurity project that analyzes URLs to identify potential phishing threats using machine learning. It combines URL feature extraction, model inference, a web interface, and a Microsoft SQL Server database to analyze URLs and maintain prediction history.

The project also demonstrates how an ML-powered security application can be supported by a relational database with integrity constraints, stored procedures, triggers, views, and activity logging.

## Key Features

- **Phishing Detection:** Analyze submitted URLs using a trained machine learning model.
- **URL Feature Extraction:** Extract URL-based features for model inference.
- **Web Interface:** Interact with the application through its frontend.
- **Analysis History:** Store submitted URLs and their prediction results.
- **User Management:** Maintain user accounts, login sessions, and activity records.
- **Suspicious Activity Alerts:** Generate database alerts for configured suspicious prediction conditions.
- **Database Integrity:** Enforce relationships and data validity using relational constraints.
- **Model Management:** Maintain model metadata and the features associated with each model.

## How It Works

```text
URL Submission
      |
      v
URL Feature Extraction
      |
      v
Machine Learning Inference
      |
      v
Prediction Result
      |
      v
SQL Server Database
      |
      +-- Analysis History
      +-- Suspicious Alerts
      +-- Activity Logs
```

Feature extraction and ML inference are performed by the application. The database stores and manages the resulting records; it does not execute the ML model itself.

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Frontend | HTML, CSS, JavaScript |
| Database | Microsoft SQL Server |
| Database Management | SQL Server Management Studio (SSMS) |
| Machine Learning | Python, trained model, URL feature extraction |
| Containerization | Docker, Docker Compose |

## Database Design

The database manages user accounts, submitted URLs, domains, model predictions, suspicious-case alerts, and activity history through a relational schema.

### Entity-Relationship Diagram

<p align="center">
  <img src="e-r%20diagram/Phishguard_db_diagram.png" alt="PhishGuard Database ER Diagram" width="800">
</p>

<p align="center">
  <em>PhishGuard relational database schema.</em>
</p>

### Database Tables

| Table | Purpose |
|---|---|
| `users` | Stores user accounts and account status |
| `sessions` | Stores login session records |
| `domains` | Stores domain information and Tranco rank |
| `user_urls` | Records URLs submitted for analysis |
| `models` | Maintains machine learning model metadata |
| `features_dictionary` | Defines the features used by ML models |
| `model_features` | Maps models to their features using a many-to-many relationship |
| `predictions` | Stores model prediction results |
| `suspicious_analyses` | Records alerts associated with suspicious predictions |
| `activity_logs` | Maintains user activity and audit history |

### Relationships and Constraints

The schema uses primary keys and foreign keys to maintain relationships between users, URLs, domains, models, predictions, and alerts.

Additional constraints include:

- Unique usernames and email addresses.
- Unique domain names and feature names.
- A composite primary key on `model_features` (`model_id`, `feature_id`).
- Prediction labels restricted to `0` or `1`.
- Prediction probabilities restricted to the range `[0, 1]`.
- Activity types restricted to supported actions such as `REGISTER`, `LOGIN`, `URL_ANALYSIS`, and `LOGOUT`.

**Prediction labels:** `0` represents phishing, while `1` represents a legitimate URL.

### Database Objects

**View — `analysis_history`**

Combines URL submissions, domain information, predictions, and model records into a convenient analysis-history view.

**Triggers**

- **URL analysis logging:** Automatically creates a `URL_ANALYSIS` activity entry when a URL submission is inserted.
- **Suspicious prediction detection:** Creates an alert when a prediction is labeled as phishing and the associated domain meets the configured Tranco rank condition (`rank <= 10,000`).

**Stored Procedure — `record_url_analysis`**

Coordinates the database-side steps of a URL analysis, including ensuring the domain record exists and creating the URL and prediction records.

Feature extraction and machine learning inference remain the responsibility of the application.

**Data Integrity and Transactions**

Primary keys, foreign keys, unique constraints, and check constraints help preserve data consistency. Transactional operations can prevent failed analyses from leaving incomplete database records.

## Getting Started

### Prerequisites

- Git
- Python and pip
- Docker and Docker Compose
- Microsoft SQL Server

### 1. Clone the Repository

```bash
git clone https://github.com/Bilal-gul/phishguard-database.git
cd phishguard-database
```

### 2. Configure Environment Variables

Navigate to the application directory:

```powershell
cd PhishGuard
```

Create your local `.env` file from the example:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and configure the required database connection settings for your environment.

> **Security:** Never commit your `.env` file, database passwords, API keys, or other secrets to GitHub. Use `.env.example` to document the required configuration without exposing real credentials.

### 3. Start the Application

From the `PhishGuard` directory, build and start the Docker services:

```bash
docker compose up -d --build
```

Check the container status:

```bash
docker compose ps
```

View application logs if needed:

```bash
docker compose logs -f
```

Make sure SQL Server is running and that the connection settings in `.env` match your environment. The available services and their configuration are defined in `PhishGuard/docker-compose.yml`.

## Repository Structure

```text
phishguard-database/
├── README.md
├── e-r diagram/
│   └── Phishguard_db_diagram.png
├── sql/
│   ├── Phishguard_create_database.sql
│   ├── Phishguard_create_table.sql
│   ├── Phishguard_procedure.sql
│   ├── Phishguard_triggers.sql
│   └── Phishguard_view.sql
└── PhishGuard/
    ├── backend/
    ├── frontend/
    ├── data/
    │   └── best_model.pkl
    ├── main.py
    ├── predict.py
    ├── feature_extractor.py
    ├── requirements.txt
    ├── Dockerfile
    ├── docker-compose.yml
    ├── .dockerignore
    └── .env.example
```

## SQL Scripts

The `sql/` directory contains the scripts used to define and configure the database.

| Script | Purpose |
|---|---|
| `Phishguard_create_database.sql` | Creates the database |
| `Phishguard_create_table.sql` | Defines tables and relational constraints |
| `Phishguard_procedure.sql` | Defines stored procedures |
| `Phishguard_triggers.sql` | Defines database triggers |
| `Phishguard_view.sql` | Defines database views |

Execute the scripts against your SQL Server instance in the appropriate order, beginning with database creation and table definitions.

## Project Goals

PhishGuard brings together machine learning, web application development, and relational database design in a practical cybersecurity project.

The application focuses on phishing URL detection, while the database provides structured analysis history, model metadata, suspicious-case tracking, activity auditing, and data integrity.

---

**Author:** [Bilal-gul](https://github.com/Bilal-gul)

**Repository:** [phishguard-database](https://github.com/Bilal-gul/phishguard-database)
