from fastapi import FastAPI

app = FastAPI(
    title="ZeroShield AI API",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "ZeroShield AI API"}
