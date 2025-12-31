"""
IsoLog Report Generator

Main report generation orchestrator.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from .exporters.pdf import PDFExporter
from .exporters.csv_exporter import CSVExporter
from .exporters.json_exporter import JSONExporter

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate security reports in multiple formats.
    
    Report types:
    - Executive summary
    - Alert details
    - Event timeline
    - MITRE coverage
    - Integrity verification
    """
    
    def __init__(self, output_directory: str):
        """
        Initialize report generator.
        
        Args:
            output_directory: Directory to save reports
        """
        self.output_dir = Path(output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.pdf_exporter = PDFExporter()
        self.csv_exporter = CSVExporter()
        self.json_exporter = JSONExporter()
    
    def generate_executive_summary(
        self,
        stats: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        period_days: int = 7,
        format: str = "pdf",
    ) -> str:
        """
        Generate executive summary report.
        
        Args:
            stats: Dashboard statistics
            alerts: Recent alerts
            period_days: Report period
            format: Output format (pdf, html)
            
        Returns:
            Path to generated report
        """
        report_data = {
            "title": "IsoLog Security Executive Summary",
            "generated_at": datetime.utcnow().isoformat(),
            "period": f"Last {period_days} days",
            "statistics": stats,
            "top_alerts": alerts[:20],
            "severity_breakdown": self._get_severity_breakdown(alerts),
        }
        
        filename = f"executive_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        if format == "pdf":
            path = self.output_dir / f"{filename}.pdf"
            self.pdf_exporter.export_executive_summary(report_data, str(path))
        else:
            path = self.output_dir / f"{filename}.json"
            self.json_exporter.export(report_data, str(path))
        
        logger.info(f"Generated executive summary: {path}")
        return str(path)
    
    def generate_alert_report(
        self,
        alerts: List[Dict[str, Any]],
        format: str = "csv",
        include_details: bool = True,
    ) -> str:
        """
        Generate detailed alert report.
        
        Args:
            alerts: Alert data
            format: Output format (csv, json, pdf)
            include_details: Include full alert details
            
        Returns:
            Path to generated report
        """
        filename = f"alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        if format == "csv":
            path = self.output_dir / f"{filename}.csv"
            self.csv_exporter.export_alerts(alerts, str(path))
        elif format == "json":
            path = self.output_dir / f"{filename}.json"
            self.json_exporter.export({"alerts": alerts}, str(path))
        else:  # pdf
            path = self.output_dir / f"{filename}.pdf"
            self.pdf_exporter.export_alerts(alerts, str(path))
        
        logger.info(f"Generated alert report: {path}")
        return str(path)
    
    def generate_event_report(
        self,
        events: List[Dict[str, Any]],
        format: str = "csv",
    ) -> str:
        """
        Generate event log report.
        
        Args:
            events: Event data
            format: Output format (csv, json)
            
        Returns:
            Path to generated report
        """
        filename = f"events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        if format == "csv":
            path = self.output_dir / f"{filename}.csv"
            self.csv_exporter.export_events(events, str(path))
        else:
            path = self.output_dir / f"{filename}.json"
            self.json_exporter.export({"events": events}, str(path))
        
        logger.info(f"Generated event report: {path}")
        return str(path)
    
    def generate_mitre_report(
        self,
        mitre_stats: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        format: str = "pdf",
    ) -> str:
        """
        Generate MITRE ATT&CK coverage report.
        
        Args:
            mitre_stats: MITRE statistics
            alerts: Related alerts
            format: Output format (pdf, json)
            
        Returns:
            Path to generated report
        """
        report_data = {
            "title": "MITRE ATT&CK Coverage Report",
            "generated_at": datetime.utcnow().isoformat(),
            "tactics": mitre_stats.get("tactics", {}),
            "techniques": mitre_stats.get("techniques", {}),
            "technique_alerts": self._group_alerts_by_technique(alerts),
        }
        
        filename = f"mitre_coverage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        if format == "pdf":
            path = self.output_dir / f"{filename}.pdf"
            self.pdf_exporter.export_mitre_report(report_data, str(path))
        else:
            path = self.output_dir / f"{filename}.json"
            self.json_exporter.export(report_data, str(path))
        
        logger.info(f"Generated MITRE report: {path}")
        return str(path)
    
    def generate_integrity_report(
        self,
        verification_result: Dict[str, Any],
        format: str = "pdf",
    ) -> str:
        """
        Generate log integrity verification report.
        
        Args:
            verification_result: Integrity verification data
            format: Output format (pdf, json)
            
        Returns:
            Path to generated report
        """
        report_data = {
            "title": "Log Integrity Verification Report",
            "generated_at": datetime.utcnow().isoformat(),
            **verification_result,
        }
        
        filename = f"integrity_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        if format == "pdf":
            path = self.output_dir / f"{filename}.pdf"
            self.pdf_exporter.export_integrity_report(report_data, str(path))
        else:
            path = self.output_dir / f"{filename}.json"
            self.json_exporter.export(report_data, str(path))
        
        logger.info(f"Generated integrity report: {path}")
        return str(path)
    
    def _get_severity_breakdown(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get alert count by severity."""
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        
        for alert in alerts:
            severity = alert.get("severity", "low").lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def _group_alerts_by_technique(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Group alerts by MITRE technique."""
        grouped = {}
        
        for alert in alerts:
            techniques = alert.get("mitre_techniques", [])
            for tech in techniques:
                if tech not in grouped:
                    grouped[tech] = []
                grouped[tech].append(alert)
        
        return grouped
