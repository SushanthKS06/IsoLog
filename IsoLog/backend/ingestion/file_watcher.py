
import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

@dataclass
class FileEvent:
    path: str
    event_type: str  # created, modified, deleted
    timestamp: datetime
    size: int
    lines_added: int = 0

class FileWatcher:
    
    def __init__(
        self,
        watch_paths: List[str],
        extensions: List[str] = None,
        recursive: bool = True,
        poll_interval: float = 1.0,
        on_new_lines: Optional[Callable[[str, List[str]], None]] = None,
        on_file_event: Optional[Callable[[FileEvent], None]] = None,
    ):
        self.watch_paths = [Path(p) for p in watch_paths]
        self.extensions = extensions or [".log", ".txt", ".json", ".csv"]
        self.recursive = recursive
        self.poll_interval = poll_interval
        self.on_new_lines = on_new_lines
        self.on_file_event = on_file_event
        
        self._file_positions: Dict[str, int] = {}
        self._file_inodes: Dict[str, int] = {}
        self._known_files: Set[str] = set()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._stats = {"files_tracked": 0, "lines_read": 0, "errors": 0}
    
    async def start(self):
        self._running = True
        
        for path in self.watch_paths:
            if path.exists():
                self._scan_directory(path)
        
        self._task = asyncio.create_task(self._watch_loop())
        
        logger.info(f"File watcher started, monitoring {len(self.watch_paths)} paths")
    
    async def stop(self):
        self._running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("File watcher stopped")
    
    def _scan_directory(self, directory: Path):
        try:
            pattern = "**/*" if self.recursive else "*"
            
            for path in directory.glob(pattern):
                if path.is_file() and self._should_watch(path):
                    self._add_file(path)
                    
        except Exception as e:
            logger.error(f"Error scanning {directory}: {e}")
    
    def _should_watch(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions
    
    def _add_file(self, path: Path):
        path_str = str(path)
        
        if path_str not in self._known_files:
            self._known_files.add(path_str)
            
            try:
                stat = path.stat()
                self._file_positions[path_str] = stat.st_size  # Start at end
                self._file_inodes[path_str] = stat.st_ino
                self._stats["files_tracked"] += 1
                
                logger.debug(f"Now watching: {path_str}")
                
            except Exception as e:
                logger.debug(f"Cannot stat {path_str}: {e}")
    
    async def _watch_loop(self):
        while self._running:
            try:
                await self._check_files()
                await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watch loop error: {e}")
                self._stats["errors"] += 1
    
    async def _check_files(self):
        for path in self.watch_paths:
            if path.exists():
                self._scan_directory(path)
        
        files_to_remove = []
        
        for path_str in list(self._known_files):
            path = Path(path_str)
            
            if not path.exists():
                files_to_remove.append(path_str)
                if self.on_file_event:
                    self.on_file_event(FileEvent(
                        path=path_str,
                        event_type="deleted",
                        timestamp=datetime.utcnow(),
                        size=0,
                    ))
                continue
            
            try:
                stat = path.stat()
                current_size = stat.st_size
                current_inode = stat.st_ino
                previous_pos = self._file_positions.get(path_str, 0)
                previous_inode = self._file_inodes.get(path_str)
                
                if current_inode != previous_inode or current_size < previous_pos:
                    logger.info(f"File rotated: {path_str}")
                    self._file_positions[path_str] = 0
                    self._file_inodes[path_str] = current_inode
                    previous_pos = 0
                
                if current_size > previous_pos:
                    new_lines = await self._read_new_lines(path, previous_pos, current_size)
                    
                    if new_lines:
                        self._stats["lines_read"] += len(new_lines)
                        
                        if self.on_new_lines:
                            self.on_new_lines(path_str, new_lines)
                        
                        if self.on_file_event:
                            self.on_file_event(FileEvent(
                                path=path_str,
                                event_type="modified",
                                timestamp=datetime.utcnow(),
                                size=current_size,
                                lines_added=len(new_lines),
                            ))
                    
                    self._file_positions[path_str] = current_size
                    
            except Exception as e:
                logger.debug(f"Error checking {path_str}: {e}")
        
        for path_str in files_to_remove:
            self._known_files.discard(path_str)
            self._file_positions.pop(path_str, None)
            self._file_inodes.pop(path_str, None)
    
    async def _read_new_lines(self, path: Path, start: int, end: int) -> List[str]:
        lines = []
        
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(start)
                content = f.read(end - start)
                lines = content.splitlines()
        except Exception as e:
            logger.debug(f"Error reading {path}: {e}")
        
        return lines
    
    def read_entire_file(self, path: str) -> List[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
        except Exception as e:
            logger.error(f"Error reading {path}: {e}")
            return []
    
    def add_path(self, path: str):
        path_obj = Path(path)
        if path_obj not in self.watch_paths:
            self.watch_paths.append(path_obj)
            if path_obj.exists():
                self._scan_directory(path_obj)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "watched_paths": [str(p) for p in self.watch_paths],
            "running": self._running,
        }
