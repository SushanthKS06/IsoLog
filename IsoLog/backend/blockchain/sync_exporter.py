
import json
import logging
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .hash_computer import HashComputer
from .chain_manager import ChainManager

logger = logging.getLogger(__name__)

class SyncExporter:
    
    def __init__(
        self, 
        chain_manager: ChainManager,
        output_path: str,
    ):
        self.chain = chain_manager
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
    
    def export_sync_package(
        self,
        events: List[Dict[str, Any]],
        start_block: Optional[int] = None,
        end_block: Optional[int] = None,
        include_events: bool = True,
        include_chain: bool = True,
    ) -> Dict[str, Any]:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        package_name = f"isolog_sync_{timestamp}"
        package_dir = self.output_path / package_name
        package_dir.mkdir(exist_ok=True)
        
        manifest = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat(),
            "source_id": self._get_source_id(),
            "contents": [],
        }
        
        if include_events and events:
            events_file = package_dir / "events.jsonl"
            with open(events_file, "w") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")
            
            events_hash = HashComputer.hash_string(
                json.dumps(events, sort_keys=True, default=str)
            )
            manifest["contents"].append({
                "type": "events",
                "file": "events.jsonl",
                "count": len(events),
                "hash": events_hash,
            })
        
        if include_chain:
            blocks = self.chain.get_chain(start_block, end_block, limit=10000)
            chain_data = [
                {
                    "id": b.id,
                    "block_hash": b.block_hash,
                    "previous_hash": b.previous_hash,
                    "merkle_root": b.merkle_root,
                    "event_count": b.event_count,
                    "timestamp": b.timestamp.isoformat() if b.timestamp else None,
                }
                for b in blocks
            ]
            
            chain_file = package_dir / "blockchain.json"
            with open(chain_file, "w") as f:
                json.dump(chain_data, f, indent=2)
            
            chain_hash = HashComputer.hash_string(
                json.dumps(chain_data, sort_keys=True)
            )
            manifest["contents"].append({
                "type": "blockchain",
                "file": "blockchain.json",
                "block_count": len(blocks),
                "first_block": blocks[0].id if blocks else None,
                "last_block": blocks[-1].id if blocks else None,
                "hash": chain_hash,
            })
        
        manifest_file = package_dir / "manifest.json"
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)
        
        archive_path = self.output_path / f"{package_name}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(package_dir, arcname=package_name)
        
        import shutil
        shutil.rmtree(package_dir)
        
        with open(archive_path, "rb") as f:
            package_hash = HashComputer.hash_bytes(f.read())
        
        logger.info(f"Created sync package: {archive_path}")
        
        return {
            "success": True,
            "package_path": str(archive_path),
            "package_hash": package_hash,
            "manifest": manifest,
        }
    
    def _get_source_id(self) -> str:
        import platform
        import uuid
        
        machine_id = f"{platform.node()}-{platform.system()}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, machine_id))

class SyncImporter:
    
    def __init__(self, chain_manager: ChainManager):
        self.chain = chain_manager
    
    def verify_package(self, package_path: str) -> Dict[str, Any]:
        package_path = Path(package_path)
        
        if not package_path.exists():
            return {"valid": False, "error": "Package not found"}
        
        with tempfile.TemporaryDirectory() as temp_dir:
            with tarfile.open(package_path, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            extracted = list(Path(temp_dir).iterdir())[0]
            
            manifest_path = extracted / "manifest.json"
            if not manifest_path.exists():
                return {"valid": False, "error": "Missing manifest"}
            
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            errors = []
            for content in manifest.get("contents", []):
                file_path = extracted / content["file"]
                
                if not file_path.exists():
                    errors.append(f"Missing file: {content['file']}")
                    continue
                
                with open(file_path) as f:
                    file_content = f.read()
                
                if content["type"] == "events":
                    events = [json.loads(line) for line in file_content.strip().split("\n")]
                    computed_hash = HashComputer.hash_string(
                        json.dumps(events, sort_keys=True, default=str)
                    )
                elif content["type"] == "blockchain":
                    chain_data = json.loads(file_content)
                    computed_hash = HashComputer.hash_string(
                        json.dumps(chain_data, sort_keys=True)
                    )
                else:
                    continue
                
                if computed_hash != content["hash"]:
                    errors.append(f"Hash mismatch for {content['file']}")
            
            if errors:
                return {"valid": False, "errors": errors}
            
            return {
                "valid": True,
                "manifest": manifest,
                "source_id": manifest.get("source_id"),
                "created_at": manifest.get("created_at"),
            }
    
    def import_blockchain(
        self, 
        package_path: str,
        verify_continuity: bool = True,
    ) -> Dict[str, Any]:
        verification = self.verify_package(package_path)
        if not verification["valid"]:
            return {"success": False, **verification}
        
        with tempfile.TemporaryDirectory() as temp_dir:
            with tarfile.open(package_path, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            extracted = list(Path(temp_dir).iterdir())[0]
            chain_file = extracted / "blockchain.json"
            
            if not chain_file.exists():
                return {"success": False, "error": "No blockchain data in package"}
            
            with open(chain_file) as f:
                imported_chain = json.load(f)
            
            if verify_continuity:
                for i, block in enumerate(imported_chain):
                    if i > 0:
                        expected_prev = imported_chain[i - 1]["block_hash"]
                        if block["previous_hash"] != expected_prev:
                            return {
                                "success": False,
                                "error": f"Chain broken at block {block['id']}",
                            }
            
            return {
                "success": True,
                "blocks_imported": len(imported_chain),
                "first_block": imported_chain[0] if imported_chain else None,
                "last_block": imported_chain[-1] if imported_chain else None,
            }
