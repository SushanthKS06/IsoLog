
import asyncio
import logging
import os
import platform
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

@dataclass
class USBDevice:
    mount_point: str
    label: Optional[str]
    size_bytes: int
    used_bytes: int
    filesystem: Optional[str]

@dataclass
class ImportResult:
    success: bool
    source_path: str
    files_imported: int
    total_lines: int
    errors: List[str]
    duration_seconds: float

class USBImporter:
    
    LOG_EXTENSIONS = [".log", ".txt", ".json", ".csv", ".evtx", ".jsonl"]
    
    def __init__(
        self,
        import_directory: str,
        on_file_imported: Optional[Callable[[str, List[str]], None]] = None,
        max_file_size_mb: int = 100,
    ):
        self.import_directory = Path(import_directory)
        self.import_directory.mkdir(parents=True, exist_ok=True)
        self.on_file_imported = on_file_imported
        self.max_file_size = max_file_size_mb * 1024 * 1024
        
        self._stats = {"imports": 0, "files": 0, "lines": 0}
    
    def detect_usb_drives(self) -> List[USBDevice]:
        devices = []
        system = platform.system()
        
        if system == "Windows":
            devices = self._detect_windows_usb()
        elif system == "Linux":
            devices = self._detect_linux_usb()
        elif system == "Darwin":  # macOS
            devices = self._detect_macos_usb()
        
        return devices
    
    def _detect_windows_usb(self) -> List[USBDevice]:
        devices = []
        
        try:
            import ctypes
            
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if bitmask & 1:
                    drive_path = f"{letter}:\\"
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                    
                    if drive_type == 2:
                        try:
                            usage = shutil.disk_usage(drive_path)
                            devices.append(USBDevice(
                                mount_point=drive_path,
                                label=None,
                                size_bytes=usage.total,
                                used_bytes=usage.used,
                                filesystem=None,
                            ))
                        except Exception:
                            pass
                
                bitmask >>= 1
                
        except Exception as e:
            logger.error(f"Windows USB detection error: {e}")
        
        return devices
    
    def _detect_linux_usb(self) -> List[USBDevice]:
        devices = []
        media_paths = ["/media", "/mnt", "/run/media"]
        
        for media_path in media_paths:
            path = Path(media_path)
            if not path.exists():
                continue
            
            for item in path.iterdir():
                if item.is_dir():
                    for mount in item.iterdir():
                        if mount.is_dir():
                            devices.append(self._get_device_info(mount))
        
        return [d for d in devices if d is not None]
    
    def _detect_macos_usb(self) -> List[USBDevice]:
        devices = []
        volumes_path = Path("/Volumes")
        
        if volumes_path.exists():
            for volume in volumes_path.iterdir():
                if volume.is_dir() and volume.name != "Macintosh HD":
                    device = self._get_device_info(volume)
                    if device:
                        devices.append(device)
        
        return devices
    
    def _get_device_info(self, path: Path) -> Optional[USBDevice]:
        try:
            usage = shutil.disk_usage(path)
            return USBDevice(
                mount_point=str(path),
                label=path.name,
                size_bytes=usage.total,
                used_bytes=usage.used,
                filesystem=None,
            )
        except Exception:
            return None
    
    def scan_for_logs(self, path: str, recursive: bool = True) -> List[Path]:
        path = Path(path)
        
        if not path.exists():
            return []
        
        log_files = []
        pattern = "**/*" if recursive else "*"
        
        for file_path in path.glob(pattern):
            if file_path.is_file():
                if file_path.suffix.lower() in self.LOG_EXTENSIONS:
                    if file_path.stat().st_size <= self.max_file_size:
                        log_files.append(file_path)
        
        return log_files
    
    async def import_from_path(
        self, 
        source_path: str,
        copy_files: bool = True,
        recursive: bool = True,
    ) -> ImportResult:
        start_time = datetime.utcnow()
        errors = []
        files_imported = 0
        total_lines = 0
        
        log_files = self.scan_for_logs(source_path, recursive)
        
        for file_path in log_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
                
                total_lines += len(lines)
                
                if copy_files:
                    dest_path = self.import_directory / file_path.name
                    counter = 1
                    while dest_path.exists():
                        dest_path = self.import_directory / f"{file_path.stem}_{counter}{file_path.suffix}"
                        counter += 1
                    shutil.copy2(file_path, dest_path)
                
                if self.on_file_imported:
                    self.on_file_imported(str(file_path), lines)
                
                files_imported += 1
                
            except Exception as e:
                errors.append(f"{file_path}: {str(e)}")
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        self._stats["imports"] += 1
        self._stats["files"] += files_imported
        self._stats["lines"] += total_lines
        
        logger.info(
            f"USB import complete: {files_imported} files, "
            f"{total_lines} lines, {duration:.2f}s"
        )
        
        return ImportResult(
            success=len(errors) == 0,
            source_path=source_path,
            files_imported=files_imported,
            total_lines=total_lines,
            errors=errors,
            duration_seconds=duration,
        )
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "import_directory": str(self.import_directory),
            "max_file_size_mb": self.max_file_size // (1024 * 1024),
        }
