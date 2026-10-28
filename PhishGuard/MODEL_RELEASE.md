# PhishGuard model release

This document describes two separately selectable model artifacts. The
optimized18 model is an optional candidate; it does not replace the legacy
model or become the application default automatically.

## Model choices

| Choice | Artifact | Selection behavior |
|---|---|---|
| Legacy model | `data/best_model.pkl` | Existing legacy artifact. Select explicitly with `PHISHGUARD_MODEL_PATH=data/best_model.pkl`. |
| Optimized18 Random Forest | `data/artifacts/candidates/optimized18-<release-tag>/phishguard_optimized18.joblib` | Optional release asset. Select explicitly with `PHISHGUARD_MODEL_PATH` after downloading and verifying it. |

When `PHISHGUARD_MODEL_PATH` is unset, the current application first looks for
`data/artifacts/phishguard_model.joblib`; if that file is absent, it falls
back to `data/best_model.pkl`. Set the variable explicitly when you need a
particular model.

Both artifacts use the application label contract `0 = phishing` and
`1 = legitimate`. The optimized18 bundle contains a 122-feature schema and a
`RandomForestClassifier` pipeline.

## Optimized18 artifact identity

- Training run: `optimized18-seed42-20261028T134959Z-b8548031a11c463c81153a338abfa022`
- Selected family: Random Forest
- Selected parameters: `n_estimators=200`, `max_depth=25`,
  `min_samples_leaf=2`, `max_features=sqrt`
- Selection criterion: validation phishing F1 for label 0
- Cross-validation: five-fold `StratifiedGroupKFold`, shuffled, seed 42,
  domain-grouped
- Training split recorded in the artifact: 577,045 rows and 334,830 domains
- Artifact format: `phishguard-model-bundle`, version 1
- Training environment recorded in the artifact: Python 3.14.0,
  scikit-learn 1.9.1, pandas 3.0.6
- Docker runtime configured in this project: Python 3.13; runtime requirements
  pin scikit-learn 1.9.1 and pandas 3.0.6. The project owner previously
  reported a successful synthetic-URL load and prediction smoke test in that
  Docker runtime.

The following metrics are read from the selected model bundle's embedded
training results. They have not been independently recomputed during this
release-document preparation. Phishing is the positive class (label 0).

| Evaluation | Phishing F1 | Precision | Recall | Accuracy |
|---|---:|---:|---:|---:|
| Cross-validation mean | 0.945978 | — | — | — |
| Validation | 0.951510 | 0.954419 | 0.948619 | 0.965680 |
| Held-out test | 0.976730 | 0.977018 | 0.976443 | 0.971891 |

The held-out test support recorded in the artifact is 3,396 phishing and 2,225
legitimate examples. The model was selected using validation phishing F1; the
test metrics are the recorded final evaluation, not the selection criterion.

## Download from a future GitHub Release

- Release tag/version: **PENDING CONFIRMATION**
- Release page URL: **PENDING CONFIRMATION**
- Asset filename: `phishguard_optimized18.joblib`

After the release tag and URL are confirmed and the asset is published, download
the asset from that release into a version-specific directory under
`PhishGuard/data/artifacts/candidates/`. For example, from the `PhishGuard/`
directory in PowerShell:

```powershell
$releaseAssetUrl = '<RELEASE_ASSET_URL_PENDING_CONFIRMATION>'
$candidateDir = 'data/artifacts/candidates/optimized18-<confirmed-release-tag>'
New-Item -ItemType Directory -Force -Path $candidateDir | Out-Null
Invoke-WebRequest -Uri $releaseAssetUrl -OutFile "$candidateDir/phishguard_optimized18.joblib"
```

Do not use the placeholder URL or tag literally. Obtain both from the confirmed
GitHub Release, and verify the downloaded file before loading it.

## Verify the downloaded file

The verified local training artifact is 332,144,789 bytes (316.76 MiB) with
this SHA-256 digest:

```text
1BA5A583D0A4ECE1CA69B4B444DEF82E67ACC198499627A21B154FD5EE7968C0
```

From `PhishGuard/`, compute and compare the checksum in PowerShell:

```powershell
$expected = '1BA5A583D0A4ECE1CA69B4B444DEF82E67ACC198499627A21B154FD5EE7968C0'
$artifact = 'data/artifacts/candidates/optimized18-<confirmed-release-tag>/phishguard_optimized18.joblib'
$actual = (Get-FileHash -Algorithm SHA256 $artifact).Hash
if ($actual -ne $expected) { throw 'SHA-256 mismatch; do not load this artifact.' }
```

Only continue if the digest matches. Joblib artifacts use pickle internally;
load only this trusted, checksum-verified release asset.

## Select the candidate model

For Docker Compose, set this in the local, untracked `PhishGuard/.env` file:

```dotenv
PHISHGUARD_MODEL_PATH=data/artifacts/candidates/optimized18-<confirmed-release-tag>/phishguard_optimized18.joblib
```

The Compose service passes this value to the application, where relative model
paths resolve from `/app`. The artifact must be present in the Docker build
context before building or rebuilding the image. Then start the application
from `PhishGuard/`:

```powershell
docker compose up --build -d
```

For a local PowerShell process started from `PhishGuard/`, set the same relative
path before launching the application:

```powershell
$env:PHISHGUARD_MODEL_PATH = 'data/artifacts/candidates/optimized18-<confirmed-release-tag>/phishguard_optimized18.joblib'
python -m uvicorn main:app --reload --env-file .env
```

Use the actual confirmed release tag in the path. Keep database credentials and
the session secret in the local environment file; do not put them in this
document or in a release asset.

## Roll back to the legacy model

To select the legacy artifact explicitly, set:

```dotenv
PHISHGUARD_MODEL_PATH=data/best_model.pkl
```

Restart/recreate the application after changing the variable. For Docker
Compose, run `docker compose up -d --force-recreate` from `PhishGuard/`. The
legacy model file is not replaced by downloading or selecting the candidate.

Alternatively, remove `PHISHGUARD_MODEL_PATH` to restore automatic selection.
That uses `data/artifacts/phishguard_model.joblib` if it exists and otherwise
falls back to `data/best_model.pkl`.
