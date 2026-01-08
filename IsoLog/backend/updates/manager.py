
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .bundle import UpdateBundle
from .verifier import UpdateVerifier

logger = logging.getLogger(__name__)

class UpdateManager:
    
    def __init__(
        self,
        rules_path: str,
        models_path: str,
        backup_path: str,
        public_key_path: Optional[str] = None,
    ):
        self.rules_path = Path(rules_path)
        self.models_path = Path(models_path)
        self.backup_path = Path(backup_path)
        self.public_key_path = public_key_path
        
        self.verifier = UpdateVerifier(public_key_path)
        self._update_history: List[Dict[str, Any]] = []
    
    def apply_update(
        self,
        bundle_path: str,
        skip_verification: bool = False,
        create_backup: bool = True,
    ) -> Dict[str, Any]:
        result = {
            "success": False,
            "applied_at": datetime.utcnow().isoformat(),
            "changes": [],
            "backup_path": None,
        }
        
        if not skip_verification:
            verify_result = self.verifier.verify_bundle(bundle_path)
            if not verify_result["valid"]:
                result["error"] = f"Verification failed: {verify_result.get('errors', [])}"
                return result
            result["verification"] = verify_result
        
        if create_backup:
            backup_result = self._create_backup()
            result["backup_path"] = backup_result.get("path")
        
        try:
            bundle = UpdateBundle(bundle_path)
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                manifest = bundle.extract(temp_dir)
                extracted_path = Path(manifest["extracted_to"])
                
                for content in manifest.get("contents", []):
                    content_type = content["type"]
                    content_path = extracted_path / content["path"]
                    
                    if content_type == "sigma_rules":
                        change = self._apply_sigma_rules(content_path)
                        result["changes"].append(change)
                    
                    elif content_type == "models":
                        change = self._apply_models(content_path)
                        result["changes"].append(change)
                    
                    elif content_type == "mitre":
                        change = self._apply_mitre_data(content_path)
                        result["changes"].append(change)
                    
                    elif content_type == "intel":
                        change = self._apply_intel_data(content_path)
                        result["changes"].append(change)
                
                result["success"] = True
                result["manifest"] = manifest
                
                self._update_history.append({
                    "bundle": str(bundle_path),
                    "applied_at": result["applied_at"],
                    "manifest": manifest,
                })
                
                logger.info(f"Successfully applied update: {bundle_path}")
                
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Failed to apply update: {e}")
            
            if result["backup_path"]:
                self._restore_backup(result["backup_path"])
                result["restored_from_backup"] = True
        
        return result
    
    def _create_backup(self) -> Dict[str, Any]:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_dir = self.backup_path / f"backup_{timestamp}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        backed_up = []
        
        if self.rules_path.exists():
            rules_backup = backup_dir / "sigma_rules"
            shutil.copytree(self.rules_path, rules_backup)
            backed_up.append("sigma_rules")
        
        if self.models_path.exists():
            models_backup = backup_dir / "models"
            shutil.copytree(self.models_path, models_backup)
            backed_up.append("models")
        
        logger.info(f"Created backup at {backup_dir}")
        return {"path": str(backup_dir), "contents": backed_up}
    
    def _restore_backup(self, backup_path: str):
        backup_path = Path(backup_path)
        
        rules_backup = backup_path / "sigma_rules"
        if rules_backup.exists():
            if self.rules_path.exists():
                shutil.rmtree(self.rules_path)
            shutil.copytree(rules_backup, self.rules_path)
        
        models_backup = backup_path / "models"
        if models_backup.exists():
            if self.models_path.exists():
                shutil.rmtree(self.models_path)
            shutil.copytree(models_backup, self.models_path)
        
        logger.info(f"Restored from backup: {backup_path}")
    
    def _apply_sigma_rules(self, source: Path) -> Dict[str, Any]:
        if not source.exists():
            return {"type": "sigma_rules", "status": "skipped", "reason": "not found"}
        
        self.rules_path.mkdir(parents=True, exist_ok=True)
        
        new_count = 0
        updated_count = 0
        
        for rule_file in source.rglob("*.yml"):
            relative = rule_file.relative_to(source)
            target = self.rules_path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            
            if target.exists():
                updated_count += 1
            else:
                new_count += 1
            
            shutil.copy2(rule_file, target)
        
        return {
            "type": "sigma_rules",
            "status": "applied",
            "new": new_count,
            "updated": updated_count,
        }
    
    def _apply_models(self, source: Path) -> Dict[str, Any]:
        if not source.exists():
            return {"type": "models", "status": "skipped", "reason": "not found"}
        
        self.models_path.mkdir(parents=True, exist_ok=True)
        
        count = 0
        for model_file in source.rglob("*"):
            if model_file.suffix in [".pkl", ".onnx", ".joblib"]:
                relative = model_file.relative_to(source)
                target = self.models_path / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(model_file, target)
                count += 1
        
        return {"type": "models", "status": "applied", "count": count}
    
    def _apply_mitre_data(self, source: Path) -> Dict[str, Any]:
        mitre_path = self.rules_path.parent / "mitre"
        mitre_path.mkdir(parents=True, exist_ok=True)
        
        for json_file in source.rglob("*.json"):
            shutil.copy2(json_file, mitre_path / json_file.name)
        
        return {"type": "mitre", "status": "applied"}
    
    def _apply_intel_data(self, source: Path) -> Dict[str, Any]:
        intel_path = self.rules_path.parent / "intel"
        intel_path.mkdir(parents=True, exist_ok=True)
        
        for file in source.rglob("*"):
            if file.is_file():
                shutil.copy2(file, intel_path / file.name)
        
        return {"type": "intel", "status": "applied"}
    
    def get_update_history(self) -> List[Dict[str, Any]]:
        return self._update_history
    
    def check_for_updates(self, updates_dir: str) -> List[Dict[str, Any]]:
        updates_dir = Path(updates_dir)
        
        if not updates_dir.exists():
            return []
        
        updates = []
        for bundle_file in updates_dir.glob("*.tar.gz"):
            try:
                bundle = UpdateBundle(str(bundle_file))
                manifest = bundle.get_manifest()
                updates.append({
                    "path": str(bundle_file),
                    "manifest": manifest,
                    "size": bundle_file.stat().st_size,
                })
            except Exception as e:
                logger.warning(f"Could not read bundle {bundle_file}: {e}")
        
        return updates
