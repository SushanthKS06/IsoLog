"""
IsoLog MITRE ATT&CK Mapper

Maps detections to MITRE ATT&CK tactics and techniques.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine import Detection

logger = logging.getLogger(__name__)


class MitreMapper:
    """
    Maps detections to MITRE ATT&CK framework.
    
    Uses embedded ATT&CK Enterprise matrix data.
    """
    
    # Tactic order in ATT&CK matrix
    TACTIC_ORDER = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]
    
    # Common technique keywords for auto-mapping
    TECHNIQUE_KEYWORDS = {
        "T1110": ["brute force", "password spray", "credential stuffing"],
        "T1059": ["powershell", "cmd", "bash", "script", "command"],
        "T1078": ["valid account", "legitimate credential"],
        "T1046": ["port scan", "network scan", "service scan"],
        "T1003": ["credential dump", "lsass", "mimikatz", "hashdump"],
        "T1021": ["rdp", "ssh", "remote service", "winrm"],
        "T1048": ["exfil", "data transfer", "upload"],
        "T1486": ["encrypt", "ransom", "ransomware"],
        "T1070": ["log clear", "indicator removal", "evidence removal"],
        "T1055": ["process inject", "dll inject"],
        "T1053": ["scheduled task", "cron", "at job"],
        "T1547": ["registry run", "startup", "autorun"],
    }
    
    def __init__(self, attack_json_path: Optional[str] = None):
        """
        Initialize MITRE mapper.
        
        Args:
            attack_json_path: Path to ATT&CK STIX JSON file
        """
        self.attack_json_path = Path(attack_json_path) if attack_json_path else None
        self.techniques: Dict[str, Dict[str, Any]] = {}
        self.tactics: Dict[str, Dict[str, Any]] = {}
    
    def load(self):
        """Load MITRE ATT&CK data."""
        if self.attack_json_path and self.attack_json_path.exists():
            try:
                self._load_from_file()
                logger.info(f"Loaded {len(self.techniques)} MITRE techniques")
                return
            except Exception as e:
                logger.warning(f"Failed to load ATT&CK JSON: {e}")
        
        # Use embedded minimal data
        self._load_embedded_data()
        logger.info("Using embedded MITRE ATT&CK data")
    
    def _load_from_file(self):
        """Load from ATT&CK STIX JSON file."""
        with open(self.attack_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        for obj in data.get("objects", []):
            obj_type = obj.get("type")
            
            if obj_type == "attack-pattern":
                # Technique
                external_refs = obj.get("external_references", [])
                tech_id = None
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        break
                
                if tech_id:
                    kill_chain = obj.get("kill_chain_phases", [])
                    tactics = [
                        p.get("phase_name") 
                        for p in kill_chain 
                        if p.get("kill_chain_name") == "mitre-attack"
                    ]
                    
                    self.techniques[tech_id] = {
                        "id": tech_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactics": tactics,
                    }
            
            elif obj_type == "x-mitre-tactic":
                # Tactic
                external_refs = obj.get("external_references", [])
                tactic_id = None
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tactic_id = ref.get("external_id")
                        break
                
                short_name = obj.get("x_mitre_shortname", "")
                if tactic_id and short_name:
                    self.tactics[short_name] = {
                        "id": tactic_id,
                        "name": obj.get("name", ""),
                        "short_name": short_name,
                    }
    
    def _load_embedded_data(self):
        """Load minimal embedded ATT&CK data."""
        # Essential techniques for common detections
        self.techniques = {
            "T1110": {"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"]},
            "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"]},
            "T1059.001": {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"]},
            "T1078": {"id": "T1078", "name": "Valid Accounts", "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]},
            "T1046": {"id": "T1046", "name": "Network Service Discovery", "tactics": ["discovery"]},
            "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"]},
            "T1021": {"id": "T1021", "name": "Remote Services", "tactics": ["lateral-movement"]},
            "T1021.001": {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactics": ["lateral-movement"]},
            "T1048": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactics": ["exfiltration"]},
            "T1486": {"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"]},
            "T1070": {"id": "T1070", "name": "Indicator Removal", "tactics": ["defense-evasion"]},
            "T1070.001": {"id": "T1070.001", "name": "Clear Windows Event Logs", "tactics": ["defense-evasion"]},
            "T1055": {"id": "T1055", "name": "Process Injection", "tactics": ["defense-evasion", "privilege-escalation"]},
            "T1053": {"id": "T1053", "name": "Scheduled Task/Job", "tactics": ["execution", "persistence", "privilege-escalation"]},
            "T1547": {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactics": ["persistence", "privilege-escalation"]},
            "T1547.001": {"id": "T1547.001", "name": "Registry Run Keys", "tactics": ["persistence", "privilege-escalation"]},
            "T1087": {"id": "T1087", "name": "Account Discovery", "tactics": ["discovery"]},
            "T1098": {"id": "T1098", "name": "Account Manipulation", "tactics": ["persistence"]},
            "T1136": {"id": "T1136", "name": "Create Account", "tactics": ["persistence"]},
            "T1543": {"id": "T1543", "name": "Create or Modify System Process", "tactics": ["persistence", "privilege-escalation"]},
        }
        
        self.tactics = {
            "reconnaissance": {"id": "TA0043", "name": "Reconnaissance", "short_name": "reconnaissance"},
            "resource-development": {"id": "TA0042", "name": "Resource Development", "short_name": "resource-development"},
            "initial-access": {"id": "TA0001", "name": "Initial Access", "short_name": "initial-access"},
            "execution": {"id": "TA0002", "name": "Execution", "short_name": "execution"},
            "persistence": {"id": "TA0003", "name": "Persistence", "short_name": "persistence"},
            "privilege-escalation": {"id": "TA0004", "name": "Privilege Escalation", "short_name": "privilege-escalation"},
            "defense-evasion": {"id": "TA0005", "name": "Defense Evasion", "short_name": "defense-evasion"},
            "credential-access": {"id": "TA0006", "name": "Credential Access", "short_name": "credential-access"},
            "discovery": {"id": "TA0007", "name": "Discovery", "short_name": "discovery"},
            "lateral-movement": {"id": "TA0008", "name": "Lateral Movement", "short_name": "lateral-movement"},
            "collection": {"id": "TA0009", "name": "Collection", "short_name": "collection"},
            "command-and-control": {"id": "TA0011", "name": "Command and Control", "short_name": "command-and-control"},
            "exfiltration": {"id": "TA0010", "name": "Exfiltration", "short_name": "exfiltration"},
            "impact": {"id": "TA0040", "name": "Impact", "short_name": "impact"},
        }
    
    def enrich_detection(self, detection: "Detection"):
        """
        Enrich detection with MITRE ATT&CK mapping.
        
        Args:
            detection: Detection to enrich
        """
        # Ensure technique format is correct
        normalized_techniques = []
        for tech in detection.mitre_techniques:
            tech_upper = tech.upper()
            if not tech_upper.startswith("T"):
                tech_upper = f"T{tech_upper}"
            normalized_techniques.append(tech_upper)
        detection.mitre_techniques = normalized_techniques
        
        # Look up tactics from techniques
        for tech_id in detection.mitre_techniques:
            if tech_id in self.techniques:
                tech_data = self.techniques[tech_id]
                for tactic in tech_data.get("tactics", []):
                    if tactic not in detection.mitre_tactics:
                        detection.mitre_tactics.append(tactic)
        
        # Auto-map if no techniques specified
        if not detection.mitre_techniques:
            self._auto_map_techniques(detection)
    
    def _auto_map_techniques(self, detection: "Detection"):
        """Auto-map techniques based on rule name/description."""
        text = f"{detection.rule_name} {detection.rule_description}".lower()
        
        for tech_id, keywords in self.TECHNIQUE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    if tech_id not in detection.mitre_techniques:
                        detection.mitre_techniques.append(tech_id)
                        # Add tactics
                        if tech_id in self.techniques:
                            for tactic in self.techniques[tech_id].get("tactics", []):
                                if tactic not in detection.mitre_tactics:
                                    detection.mitre_tactics.append(tactic)
                    break
    
    def get_technique(self, tech_id: str) -> Optional[Dict[str, Any]]:
        """Get technique details by ID."""
        return self.techniques.get(tech_id.upper())
    
    def get_tactic(self, tactic_name: str) -> Optional[Dict[str, Any]]:
        """Get tactic details by short name."""
        return self.tactics.get(tactic_name.lower())
    
    def get_matrix_data(self) -> Dict[str, Any]:
        """Get data for MITRE ATT&CK matrix visualization."""
        matrix = []
        
        for tactic_name in self.TACTIC_ORDER:
            tactic_data = self.tactics.get(tactic_name)
            if not tactic_data:
                continue
            
            # Get techniques for this tactic
            tactic_techniques = [
                {"id": tech_id, "name": tech_data["name"]}
                for tech_id, tech_data in self.techniques.items()
                if tactic_name in tech_data.get("tactics", [])
            ]
            
            matrix.append({
                "tactic": tactic_data,
                "techniques": sorted(tactic_techniques, key=lambda x: x["id"]),
            })
        
        return {"matrix": matrix}
