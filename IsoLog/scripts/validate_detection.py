#!/usr/bin/env python

import argparse
import asyncio
import json
import logging
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.detection.engine import DetectionEngine
from backend.parsers.formats.mordor import MordorParser

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    dataset_id: str
    dataset_title: str
    expected_techniques: Set[str]
    detected_techniques: Set[str]
    total_events: int
    events_with_alerts: int
    matched: bool
    
    @property
    def precision(self) -> float:
        if not self.detected_techniques:
            return 0.0
        matched = len(self.detected_techniques & self.expected_techniques)
        return matched / len(self.detected_techniques)
    
    @property
    def recall(self) -> float:
        if not self.expected_techniques:
            return 1.0
        matched = len(self.detected_techniques & self.expected_techniques)
        return matched / len(self.expected_techniques)

@dataclass
class ValidationReport:
    results: List[ValidationResult] = field(default_factory=list)
    
    @property
    def total_datasets(self) -> int:
        return len(self.results)
    
    @property
    def matched_datasets(self) -> int:
        return sum(1 for r in self.results if r.matched)
    
    @property
    def avg_precision(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.precision for r in self.results) / len(self.results)
    
    @property
    def avg_recall(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.recall for r in self.results) / len(self.results)
    
    def print_summary(self):
        print("\n" + "=" * 60)
        print("VALIDATION REPORT")
        print("=" * 60)
        print(f"Datasets Tested:  {self.total_datasets}")
        print(f"Datasets Matched: {self.matched_datasets} ({self.matched_datasets/max(1,self.total_datasets)*100:.1f}%)")
        print(f"Average Precision: {self.avg_precision*100:.1f}%")
        print(f"Average Recall:    {self.avg_recall*100:.1f}%")
        print("=" * 60)
        
        for result in self.results:
            status = "✓ PASS" if result.matched else "✗ FAIL"
            print(f"\n{status} | {result.dataset_id}: {result.dataset_title}")
            print(f"      Expected: {sorted(result.expected_techniques)}")
            print(f"      Detected: {sorted(result.detected_techniques)}")
            print(f"      Events: {result.total_events}, With Alerts: {result.events_with_alerts}")

class DetectionValidator:
    
    def __init__(self, datasets_path: Path, config_path: Optional[Path] = None):
        self.datasets_path = datasets_path
        self.metadata_path = datasets_path / "datasets" / "atomic" / "_metadata"
        self.parser = MordorParser()
        self.engine = DetectionEngine()
        self.report = ValidationReport()
    
    async def initialize(self):
        await self.engine.initialize()
        logger.info("Detection engine initialized")
    
    def load_metadata(self, yaml_path: Path) -> Dict[str, Any]:
        with open(yaml_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    
    def extract_expected_techniques(self, metadata: Dict[str, Any]) -> Set[str]:
        techniques = set()
        
        attack_mappings = metadata.get("attack_mappings", [])
        for mapping in attack_mappings:
            technique = mapping.get("technique", "")
            sub_technique = mapping.get("sub-technique", "")
            
            if technique:
                techniques.add(technique)
            if sub_technique:
                techniques.add(f"{technique}.{sub_technique}")
        
        return techniques
    
    def find_data_file(self, metadata: Dict[str, Any]) -> Optional[Path]:
        files = metadata.get("files", [])
        for file_info in files:
            if file_info.get("type") == "Host":
                url = file_info.get("link", "")
                if "datasets/" in url:
                    rel_path = url.split("datasets/")[-1]
                    full_path = self.datasets_path / "datasets" / rel_path
                    if full_path.exists():
                        return full_path
        return None
    
    def load_events_from_zip(self, zip_path: Path, max_events: int = 1000) -> List[Dict[str, Any]]:
        events = []
        
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    with zf.open(name) as f:
                        content = f.read().decode("utf-8")
                        for line in content.strip().split("\n"):
                            if line.strip():
                                try:
                                    event = json.loads(line)
                                    events.append(event)
                                    if len(events) >= max_events:
                                        return events
                                except json.JSONDecodeError:
                                    continue
        return events
    
    async def validate_dataset(self, metadata_path: Path, max_events: int = 10000) -> Optional[ValidationResult]:
        metadata = self.load_metadata(metadata_path)
        dataset_id = metadata.get("id", metadata_path.stem)
        dataset_title = metadata.get("title", "Unknown")
        
        logger.info(f"Validating: {dataset_id} - {dataset_title}")
        
        expected = self.extract_expected_techniques(metadata)
        if not expected:
            logger.warning(f"  No MITRE techniques in metadata, skipping")
            return None
        
        data_file = self.find_data_file(metadata)
        if not data_file:
            logger.warning(f"  Data file not found, skipping")
            return None
        
        events = self.load_events_from_zip(data_file, max_events)
        logger.info(f"  Loaded {len(events)} events")
        
        if not events:
            return None
        
        detected_techniques: Set[str] = set()
        events_with_alerts = 0
        
        for event_data in events:
            parsed = self.parser.parse_dict(event_data)
            if not parsed:
                continue
            
            detections = await self.engine.analyze(parsed)
            if detections:
                events_with_alerts += 1
                for detection in detections:
                    detected_techniques.update(detection.mitre_techniques)
        
        matched = bool(detected_techniques & expected)
        
        result = ValidationResult(
            dataset_id=dataset_id,
            dataset_title=dataset_title,
            expected_techniques=expected,
            detected_techniques=detected_techniques,
            total_events=len(events),
            events_with_alerts=events_with_alerts,
            matched=matched
        )
        
        logger.info(f"  Result: {'PASS' if matched else 'FAIL'} | Expected: {expected} | Detected: {detected_techniques}")
        
        return result
    
    async def validate_category(self, category: str, limit: int = 10) -> ValidationReport:
        category_path = self.datasets_path / "datasets" / "atomic" / "windows" / category
        
        if not category_path.exists():
            logger.error(f"Category path not found: {category_path}")
            return self.report
        
        metadata_files = []
        for yaml_file in self.metadata_path.glob("*.yaml"):
            metadata = self.load_metadata(yaml_file)
            files = metadata.get("files", [])
            for f in files:
                link = f.get("link", "")
                if f"/{category}/" in link:
                    metadata_files.append(yaml_file)
                    break
        
        logger.info(f"Found {len(metadata_files)} datasets for category '{category}'")
        
        for yaml_file in metadata_files[:limit]:
            result = await self.validate_dataset(yaml_file)
            if result:
                self.report.results.append(result)
        
        return self.report
    
    async def validate_single(self, dataset_id: str) -> ValidationReport:
        yaml_file = self.metadata_path / f"{dataset_id}.yaml"
        
        if not yaml_file.exists():
            logger.error(f"Metadata file not found: {yaml_file}")
            return self.report
        
        result = await self.validate_dataset(yaml_file)
        if result:
            self.report.results.append(result)
        
        return self.report

async def main():
    parser = argparse.ArgumentParser(
        description="Validate IsoLog detection using Security-Datasets"
    )
    parser.add_argument(
        "--datasets-path",
        type=Path,
        default=Path(__file__).parent.parent.parent / "Security-Datasets",
        help="Path to Security-Datasets repository"
    )
    parser.add_argument(
        "--category",
        type=str,
        help="Attack category to validate (e.g., credential_access, defense_evasion)"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        help="Single dataset ID to validate (e.g., SDWIN-190301125905)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Max datasets to validate per category"
    )
    
    args = parser.parse_args()
    
    if not args.datasets_path.exists():
        logger.error(f"Security-Datasets not found at: {args.datasets_path}")
        sys.exit(1)
    
    validator = DetectionValidator(args.datasets_path)
    await validator.initialize()
    
    if args.dataset:
        report = await validator.validate_single(args.dataset)
    elif args.category:
        report = await validator.validate_category(args.category, limit=args.limit)
    else:
        report = await validator.validate_category("credential_access", limit=args.limit)
    
    report.print_summary()

if __name__ == "__main__":
    asyncio.run(main())
