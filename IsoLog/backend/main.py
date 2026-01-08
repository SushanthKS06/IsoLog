
import logging
import sys
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_settings

def setup_logging():
    settings = get_settings()
    
    log_path = settings.resolve_path(settings.logging.file_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    level = getattr(logging, settings.logging.level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(log_path)),
        ],
    )
    
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("watchdog").setLevel(logging.WARNING)

def main():
    setup_logging()
    logger = logging.getLogger(__name__)
    
    settings = get_settings()
    
    logger.info("=" * 60)
    logger.info("  IsoLog - Portable SIEM for Isolated Networks")
    logger.info("=" * 60)
    logger.info(f"  Host: {settings.server.host}")
    logger.info(f"  Port: {settings.server.port}")
    logger.info(f"  Debug: {settings.server.debug}")
    logger.info("=" * 60)
    
    data_dirs = [
        settings.resolve_path("data"),
        settings.resolve_path("data/logs"),
        settings.resolve_path("data/reports"),
        settings.resolve_path("logs"),
        settings.resolve_path("models"),
        settings.resolve_path("rules/sigma_rules"),
    ]
    
    for dir_path in data_dirs:
        dir_path.mkdir(parents=True, exist_ok=True)
    
    uvicorn.run(
        "backend.api.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.debug,
        workers=1 if settings.server.debug else settings.server.workers,
    )

if __name__ == "__main__":
    main()
