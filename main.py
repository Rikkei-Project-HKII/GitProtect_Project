from fastapi import FastAPI
from app.core.config import settings
from app.api.v1 import api_v1_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Hệ thống Giám sát An toàn, Kết nối GitHub Repository & Quét Bí mật Mã nguồn Tự động (MVP Baseline v1.1 - GP-2026-SCRUM).",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.include_router(api_v1_router)

@app.get("/", tags=["Health Check"])
async def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
