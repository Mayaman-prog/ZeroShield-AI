# ZeroShield AI - Python, FastAPI and ML Environment Setup

## WBS Reference

- WBS: 12
- Product Backlog: ZS-012
- Task: Set up Python, FastAPI and ML development environment
- Environment: Windows development host

## Purpose

This environment provides the initial Python, FastAPI and machine-learning foundation required for the ZeroShield AI defensive research prototype. The setup is intentionally limited to environment verification and does not implement telemetry ingestion, authentication, persistence, detector services or dashboard functionality.

## Python Environment

- Python: 3.14.4
- pip: 26.0.1
- Virtual environment: `.venv/`
- Virtual environment location: repository root

The virtual environment is located at the repository root because Python is used by both the FastAPI service layer in `backend/` and the core ZeroShield security and machine-learning components outside the backend directory.

Create the environment:

```cmd
py -3.14 -m venv .venv
```

Activate it on Windows:

```cmd
.venv\Scripts\activate
```

## Initial Dependencies

The initial reproducible dependencies are pinned in the root `requirements.txt` file.

- FastAPI 0.141.1
- Uvicorn 0.52.4
- Pydantic 2.13.5
- NumPy 2.5.2
- pandas 3.0.5
- scikit-learn 1.9.0
- XGBoost 3.4.1
- joblib 1.5.3

Install the dependencies using:

```cmd
python -m pip install -r requirements.txt
```

SHAP and other heavier research dependencies are intentionally excluded from this initial environment and will be added only when required by later implementation work.

## FastAPI Verification

The minimum FastAPI application is located at:

`backend/app/main.py`

Start the local development service with:

```cmd
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Verify the health endpoint with:

```cmd
curl -i http://127.0.0.1:8000/health
```

Expected application response:

```json
{"status":"ok","service":"ZeroShield AI API"}
```

A successful verification must return HTTP 200 OK.

## Environment Verification

Run the reproducible environment check with:

```cmd
python scripts\verify_environment.py
```

The script verifies the active Python interpreter and imports the required initial FastAPI and machine-learning packages while reporting their installed versions.

## Git and Security Controls

The local `.venv/` directory is excluded from Git. The repository `.gitignore` also protects environment files, credentials, secrets, raw and processed datasets, generated machine-learning artefacts, experiment outputs, runtime logs and Python caches.

No credentials, datasets, secrets or generated model artefacts should be committed to the repository.

## Evidence

Reproducible WBS 12 verification evidence is stored in:

`docs/project-management/evidence/environment-setup/`

Current evidence:

- `environment_verification.txt`
- `fastapi_health_check.txt`

## Scope Boundary

This setup establishes only the development environment required by WBS 12. React setup, PostgreSQL, Docker/VM laboratory configuration, Suricata, dataset ingestion, XGBoost experiments, Isolation Forest experiments and other later ZeroShield functionality remain outside this task.
