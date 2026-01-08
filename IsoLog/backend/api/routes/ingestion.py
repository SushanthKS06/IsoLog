
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException, UploadFile, File
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()

class WatchPathRequest(BaseModel):
    path: str

class ImportRequest(BaseModel):
    path: str
    recursive: bool = True

@router.get("/status")
async def get_ingestion_status():
    return {
        "syslog": {
            "enabled": True,
            "udp_port": 1514,
            "tcp_port": 1515,
            "events_received": 0,
        },
        "file_watcher": {
            "enabled": True,
            "paths": [],
            "files_tracked": 0,
        },
        "usb": {
            "last_import": None,
            "imports_count": 0,
        },
    }

@router.post("/watch")
async def add_watch_path(request: WatchPathRequest):
    from pathlib import Path
    
    path = Path(request.path)
    if not path.exists():
        raise HTTPException(400, f"Path does not exist: {request.path}")
    
    if not path.is_dir():
        raise HTTPException(400, f"Path is not a directory: {request.path}")
    
    return {
        "success": True,
        "path": str(path),
        "message": f"Added {path} to watch list",
    }

@router.delete("/watch")
async def remove_watch_path(path: str = Query(...)):
    return {
        "success": True,
        "path": path,
        "message": f"Removed {path} from watch list",
    }

@router.get("/usb/detect")
async def detect_usb_drives():
    try:
        from ...ingestion import USBImporter
        
        importer = USBImporter("./data/imports")
        devices = importer.detect_usb_drives()
        
        return {
            "devices": [
                {
                    "mount_point": d.mount_point,
                    "label": d.label,
                    "size_gb": round(d.size_bytes / (1024**3), 2),
                    "used_gb": round(d.used_bytes / (1024**3), 2),
                }
                for d in devices
            ]
        }
    except Exception as e:
        logger.error(f"USB detection error: {e}")
        return {"devices": [], "error": str(e)}

@router.post("/usb/import")
async def import_from_usb(request: ImportRequest):
    try:
        from ...ingestion import USBImporter
        
        importer = USBImporter("./data/imports")
        result = await importer.import_from_path(
            request.path,
            recursive=request.recursive,
        )
        
        return {
            "success": result.success,
            "files_imported": result.files_imported,
            "total_lines": result.total_lines,
            "errors": result.errors,
            "duration_seconds": result.duration_seconds,
        }
    except Exception as e:
        logger.error(f"USB import error: {e}")
        raise HTTPException(500, str(e))

@router.post("/upload")
async def upload_log_file(file: UploadFile = File(...)):
    import aiofiles
    from pathlib import Path
    
    upload_dir = Path("./data/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = upload_dir / file.filename
    
    try:
        async with aiofiles.open(file_path, "wb") as f:
            content = await file.read()
            await f.write(content)
        
        line_count = content.decode("utf-8", errors="replace").count("\n")
        
        return {
            "success": True,
            "filename": file.filename,
            "size_bytes": len(content),
            "lines": line_count,
            "path": str(file_path),
        }
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(500, str(e))

@router.post("/pcap")
async def process_pcap(path: str = Query(...)):
    try:
        from ...ingestion import PCAPProcessor
        from pathlib import Path
        
        if not Path(path).exists():
            raise HTTPException(404, f"PCAP file not found: {path}")
        
        processor = PCAPProcessor()
        flows = processor.process_file(path)
        
        return {
            "success": True,
            "flows_extracted": len(flows),
            "file": path,
        }
    except Exception as e:
        logger.error(f"PCAP processing error: {e}")
        raise HTTPException(500, str(e))
