
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from ..config import get_settings
from ..storage.database import get_db_manager, init_db

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting IsoLog...")
    
    await init_db()
    
    from ..detection import DetectionEngine
    app.state.detection_engine = DetectionEngine()
    await app.state.detection_engine.initialize()
    
    settings = get_settings()
    if settings.blockchain.enabled:
        from ..blockchain import ChainManager
        app.state.chain_manager = ChainManager(
            str(settings.resolve_path(settings.blockchain.ledger_path))
        )
    
    logger.info("IsoLog started successfully")
    
    yield
    
    logger.info("Shutting down IsoLog...")
    db_manager = get_db_manager()
    await db_manager.close()

def create_app() -> FastAPI:
    settings = get_settings()
    
    app = FastAPI(
        title="IsoLog",
        description="Portable SIEM for isolated/air-gapped networks",
        version="0.1.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, restrict this
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    from .routes import events, alerts, dashboard, search, integrity, system, reports, ingestion
    from .websocket import websocket_endpoint
    
    app.include_router(events.router, prefix="/api/events", tags=["Events"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
    app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
    app.include_router(search.router, prefix="/api/search", tags=["Search"])
    app.include_router(integrity.router, prefix="/api/integrity", tags=["Integrity"])
    app.include_router(system.router, prefix="/api/system", tags=["System"])
    app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
    app.include_router(ingestion.router, prefix="/api/ingestion", tags=["Ingestion"])
    
    from fastapi import WebSocket
    
    @app.websocket("/ws/{channel}")
    async def ws_endpoint(websocket: WebSocket, channel: str = "all"):
        await websocket_endpoint(websocket, channel)
    
    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "isolog"}
    
    static_path = Path(__file__).parent.parent.parent / "ui" / "dist"
    if static_path.exists():
        app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
        
        @app.get("/")
        async def serve_frontend():
            return FileResponse(str(static_path / "index.html"))
    
    return app

app = create_app()
