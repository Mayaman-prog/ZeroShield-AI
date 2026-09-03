from importlib.metadata import version
import sys

PACKAGES = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "pydantic": "pydantic",
    "numpy": "numpy",
    "pandas": "pandas",
    "scikit-learn": "sklearn",
    "xgboost": "xgboost",
    "joblib": "joblib",
}

print("ZeroShield AI environment verification")
print(f"Python: {sys.version.split()[0]}")
print(f"Executable: {sys.executable}")
print()

for distribution, module in PACKAGES.items():
    __import__(module)
    print(f"{distribution}: {version(distribution)} [OK]")

print()
print("Environment verification PASSED")
