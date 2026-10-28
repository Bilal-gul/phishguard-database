# PhishGuard

FastAPI application for URL feature extraction and phishing classification. SQL Server stores accounts, sessions, submissions and prediction history; the frontend is served by the same application.

## Runtime

Install `requirements.txt`, configure the `PHISHGUARD_SQL_*` values and `PHISHGUARD_SESSION_SECRET` in an untracked `.env` file (or the process environment), then run from this directory:

```powershell
python -m uvicorn main:app --reload --env-file .env
```

Set `PHISHGUARD_COOKIE_SECURE=true` when serving over HTTPS. The local HTTP default is intended for development. `/health/database` returns connection status only and does not disclose the SQL login or database name.

## Feature data and training

Extracted feature rows use the numeric columns in `feature_extractor.FEATURE_COLUMNS`, in that exact order. Labels are `0` for phishing and `1` for legitimate. `FullDomain` is the grouping key used to keep domains separate across train, validation and test. SQL Server certificate validation can be enabled with `PHISHGUARD_SQL_TRUST_SERVER_CERTIFICATE=false` when the server certificate is trusted; the default preserves local self-signed SQL Server setups.

From the repository root, install `requirements-training.txt` and create splits with:

```powershell
python preprocessing.py --input PhishGuard/data/features_data.csv --output-dir PhishGuard/data/splits
```

Then run the offline search:

```powershell
python fit.py --data-dir PhishGuard/data/splits
```

The preprocessing output directory and the `--data-dir` passed to `fit.py` or
`model.py` must be the same: preprocessing writes to `PhishGuard/data/splits`
when using the command above, while those commands otherwise default to
`PhishGuard/data`.

Training support commands live in `training/`. The benchmark and search-space
comparison require explicit dataset and report paths:

```powershell
python -m training.benchmark_training --data-dir PhishGuard/data/splits --train-only --report $env:TEMP/phishguard-benchmark.json
python -m training.compare_search_spaces --data-dir PhishGuard/data/splits --report $env:TEMP/phishguard-comparison.json
python -m training.train_optimized --data-dir PhishGuard/data/splits
```

The optimized training command runs a full 18-candidate search and writes to a
new candidate-artifact directory; estimate its resource cost before starting.
The root-level scripts with these names remain compatibility launchers for
existing commands.

To evaluate an already selected artifact without refitting it, use `python model.py --data-dir PhishGuard/data/splits --artifact PhishGuard/data/artifacts/phishguard_model.joblib`.

Training uses `StratifiedGroupKFold` for inner model selection and chooses among candidate models by validation phishing F1 (class 0). It reports test metrics once after model selection. The default output is a **new** versioned artifact at `PhishGuard/data/artifacts/phishguard_model.joblib`; existing files are not replaced unless `--overwrite-artifact` is supplied. Split creation also refuses to replace its output files unless `--overwrite` is supplied.

The serving process prefers the versioned default bundle
`data/artifacts/phishguard_model.joblib` when present, otherwise it loads the
legacy `data/best_model.pkl` file. Docker includes only these runtime artifacts
and the stable optional slot `data/runtime_model.joblib`; datasets, candidate
models, and other training outputs are excluded. Set `PHISHGUARD_MODEL_PATH` to
select a verified artifact. The optional GitHub Release download, checksum
verification, candidate selection, and rollback steps are documented in
[`MODEL_RELEASE.md`](MODEL_RELEASE.md). Joblib artifacts use pickle internally:
never load files supplied by untrusted users.

The training command performs 31 parameter configurations across five folds, plus one refit for each of five candidate families (about 160 estimator fits). It is not part of application startup and should be run only after estimating its resource cost for the dataset and machine.

## Tests

From the repository root:

```powershell
python -m pytest
```

The tests use small synthetic datasets and do not run the production hyperparameter search or modify the checked-in model/data files.
