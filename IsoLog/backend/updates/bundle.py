
import json
import logging
import shutil
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class UpdateBundle:
    
    BUNDLE_VERSION = "1.0"
    
    def __init__(self, bundle_path: Optional[str] = None):
        self.bundle_path = Path(bundle_path) if bundle_path else None
        self.manifest: Dict[str, Any] = {}
    
    def create(
        self,
        output_dir: str,
        sigma_rules_path: Optional[str] = None,
        models_path: Optional[str] = None,
        mitre_path: Optional[str] = None,
        intel_path: Optional[str] = None,
        version: Optional[str] = None,
        description: str = "",
    ) -> str:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        bundle_name = f"isolog_update_{timestamp}"
        bundle_dir = output_dir / bundle_name
        bundle_dir.mkdir()
        
        manifest = {
            "bundle_version": self.BUNDLE_VERSION,
            "created_at": datetime.utcnow().isoformat(),
            "version": version or timestamp,
            "description": description,
            "contents": [],
        }
        
        if sigma_rules_path and Path(sigma_rules_path).exists():
            dest = bundle_dir / "sigma_rules"
            shutil.copytree(sigma_rules_path, dest)
            manifest["contents"].append({
                "type": "sigma_rules",
                "path": "sigma_rules",
                "count": len(list(dest.rglob("*.yml"))),
            })
            logger.info(f"Added Sigma rules from {sigma_rules_path}")
        
        if models_path and Path(models_path).exists():
            dest = bundle_dir / "models"
            shutil.copytree(models_path, dest)
            model_files = list(dest.rglob("*.pkl")) + list(dest.rglob("*.onnx"))
            manifest["contents"].append({
                "type": "models",
                "path": "models",
                "count": len(model_files),
            })
            logger.info(f"Added ML models from {models_path}")
        
        if mitre_path and Path(mitre_path).exists():
            dest = bundle_dir / "mitre"
            if Path(mitre_path).is_dir():
                shutil.copytree(mitre_path, dest)
            else:
                dest.mkdir()
                shutil.copy2(mitre_path, dest)
            manifest["contents"].append({
                "type": "mitre",
                "path": "mitre",
            })
            logger.info(f"Added MITRE data from {mitre_path}")
        
        if intel_path and Path(intel_path).exists():
            dest = bundle_dir / "intel"
            if Path(intel_path).is_dir():
                shutil.copytree(intel_path, dest)
            else:
                dest.mkdir()
                shutil.copy2(intel_path, dest)
            manifest["contents"].append({
                "type": "intel",
                "path": "intel",
            })
            logger.info(f"Added threat intel from {intel_path}")
        
        manifest_path = bundle_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        
        archive_path = output_dir / f"{bundle_name}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(bundle_dir, arcname=bundle_name)
        
        shutil.rmtree(bundle_dir)
        
        logger.info(f"Created update bundle: {archive_path}")
        return str(archive_path)
    
    def extract(self, target_dir: str) -> Dict[str, Any]:
        if not self.bundle_path or not self.bundle_path.exists():
            raise ValueError("No bundle path specified or bundle not found")
        
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        with tarfile.open(self.bundle_path, "r:gz") as tar:
            tar.extractall(target_dir)
        
        extracted_dirs = [d for d in target_dir.iterdir() if d.is_dir()]
        if not extracted_dirs:
            raise ValueError("No directory found in bundle")
        
        bundle_root = extracted_dirs[0]
        
        manifest_path = bundle_root / "manifest.json"
        if manifest_path.exists():
            with open(manifest_path) as f:
                self.manifest = json.load(f)
        
        self.manifest["extracted_to"] = str(bundle_root)
        return self.manifest
    
    def get_manifest(self) -> Dict[str, Any]:
        if not self.bundle_path or not self.bundle_path.exists():
            raise ValueError("No bundle path specified or bundle not found")
        
        with tarfile.open(self.bundle_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("manifest.json"):
                    f = tar.extractfile(member)
                    if f:
                        return json.load(f)
        
        return {}
