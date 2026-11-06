from fastapi import APIRouter
from app.modules.ingestion.router import router as ingestion_router
from app.modules.engine.router import router as engine_router
from app.modules.alerts.router import router as alerts_router
from app.modules.dashboard.router import router as dashboard_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(ingestion_router)
api_v1_router.include_router(engine_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(dashboard_router)
