"""
IsoLog PDF Exporter

Export reports to PDF format using ReportLab.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Check if reportlab is available
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not installed. PDF export will be limited.")


class PDFExporter:
    """Export reports to PDF format."""
    
    # Color scheme
    COLORS = {
        "critical": (0.86, 0.15, 0.15),  # Red
        "high": (0.97, 0.45, 0.09),      # Orange
        "medium": (0.92, 0.70, 0.03),    # Yellow
        "low": (0.13, 0.77, 0.37),       # Green
        "info": (0.39, 0.45, 0.53),      # Gray
        "header": (0.13, 0.34, 0.60),    # Blue
    }
    
    def __init__(self):
        """Initialize PDF exporter."""
        self._available = REPORTLAB_AVAILABLE
    
    def is_available(self) -> bool:
        """Check if PDF export is available."""
        return self._available
    
    def export_executive_summary(self, data: Dict[str, Any], output_path: str):
        """
        Generate executive summary PDF.
        
        Args:
            data: Report data
            output_path: Output file path
        """
        if not self._available:
            self._write_fallback(data, output_path)
            return
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a365d'),
        )
        story.append(Paragraph(data.get("title", "Security Report"), title_style))
        
        # Metadata
        meta_style = styles['Normal']
        story.append(Paragraph(f"<b>Generated:</b> {data.get('generated_at', '')}", meta_style))
        story.append(Paragraph(f"<b>Period:</b> {data.get('period', '')}", meta_style))
        story.append(Spacer(1, 20))
        
        # Statistics summary
        stats = data.get("statistics", {})
        story.append(Paragraph("<b>Summary Statistics</b>", styles['Heading2']))
        story.append(Spacer(1, 10))
        
        stats_data = [
            ["Metric", "Value"],
            ["Total Alerts", str(stats.get("total_alerts", 0))],
            ["Critical Alerts", str(stats.get("critical_alerts", 0))],
            ["High Alerts", str(stats.get("high_alerts", 0))],
            ["Events Today", str(stats.get("events_today", 0))],
            ["Total Events", str(stats.get("total_events", 0))],
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # Severity breakdown
        breakdown = data.get("severity_breakdown", {})
        if breakdown:
            story.append(Paragraph("<b>Severity Distribution</b>", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            severity_data = [["Severity", "Count"]]
            for severity, count in breakdown.items():
                severity_data.append([severity.capitalize(), str(count)])
            
            severity_table = Table(severity_data, colWidths=[3*inch, 2*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ]))
            story.append(severity_table)
            story.append(Spacer(1, 20))
        
        # Top alerts
        top_alerts = data.get("top_alerts", [])
        if top_alerts:
            story.append(PageBreak())
            story.append(Paragraph("<b>Recent Critical Alerts</b>", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            for alert in top_alerts[:10]:
                severity = alert.get("severity", "low")
                story.append(Paragraph(
                    f"<b>[{severity.upper()}]</b> {alert.get('rule_name', 'Unknown')}",
                    meta_style
                ))
                story.append(Paragraph(
                    f"Time: {alert.get('created_at', '')} | Score: {alert.get('threat_score', 0):.1f}",
                    styles['Normal']
                ))
                story.append(Spacer(1, 10))
        
        doc.build(story)
        logger.info(f"Generated executive summary PDF: {output_path}")
    
    def export_alerts(self, alerts: List[Dict[str, Any]], output_path: str):
        """Generate alerts PDF report."""
        if not self._available:
            self._write_fallback({"alerts": alerts}, output_path)
            return
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph("Security Alerts Report", styles['Heading1']))
        story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        if not alerts:
            story.append(Paragraph("No alerts to report.", styles['Normal']))
        else:
            for i, alert in enumerate(alerts[:50], 1):
                story.append(Paragraph(
                    f"<b>Alert {i}: {alert.get('rule_name', 'Unknown')}</b>",
                    styles['Heading3']
                ))
                story.append(Paragraph(f"Severity: {alert.get('severity', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"Time: {alert.get('created_at', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"Score: {alert.get('threat_score', 0):.1f}", styles['Normal']))
                
                techniques = alert.get('mitre_techniques', [])
                if techniques:
                    story.append(Paragraph(f"MITRE: {', '.join(techniques)}", styles['Normal']))
                
                story.append(Spacer(1, 15))
        
        doc.build(story)
        logger.info(f"Generated alerts PDF: {output_path}")
    
    def export_mitre_report(self, data: Dict[str, Any], output_path: str):
        """Generate MITRE ATT&CK coverage PDF."""
        if not self._available:
            self._write_fallback(data, output_path)
            return
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph("MITRE ATT&CK Coverage Report", styles['Heading1']))
        story.append(Paragraph(f"Generated: {data.get('generated_at', '')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Tactics
        tactics = data.get("tactics", {})
        if tactics:
            story.append(Paragraph("<b>Tactics Detected</b>", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            tactics_data = [["Tactic", "Detections"]]
            for tactic, count in sorted(tactics.items(), key=lambda x: x[1], reverse=True):
                tactics_data.append([tactic.replace("-", " ").title(), str(count)])
            
            table = Table(tactics_data, colWidths=[4*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ]))
            story.append(table)
            story.append(Spacer(1, 20))
        
        # Techniques
        techniques = data.get("techniques", {})
        if techniques:
            story.append(Paragraph("<b>Top Techniques</b>", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            tech_data = [["Technique ID", "Detections"]]
            for tech, count in sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:20]:
                tech_data.append([tech, str(count)])
            
            table = Table(tech_data, colWidths=[2*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a365d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ]))
            story.append(table)
        
        doc.build(story)
        logger.info(f"Generated MITRE PDF: {output_path}")
    
    def export_integrity_report(self, data: Dict[str, Any], output_path: str):
        """Generate integrity verification PDF."""
        if not self._available:
            self._write_fallback(data, output_path)
            return
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph("Log Integrity Verification Report", styles['Heading1']))
        story.append(Paragraph(f"Generated: {data.get('generated_at', '')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Status
        is_valid = data.get("chain_valid", False)
        status_text = "✓ VERIFIED" if is_valid else "✗ INTEGRITY ISSUES DETECTED"
        status_color = colors.green if is_valid else colors.red
        
        status_style = ParagraphStyle(
            'Status',
            parent=styles['Heading2'],
            textColor=status_color,
        )
        story.append(Paragraph(status_text, status_style))
        story.append(Spacer(1, 20))
        
        # Statistics
        stats = data.get("statistics", {})
        if stats:
            story.append(Paragraph("<b>Chain Statistics</b>", styles['Heading3']))
            
            for key, value in stats.items():
                story.append(Paragraph(f"{key}: {value}", styles['Normal']))
        
        doc.build(story)
        logger.info(f"Generated integrity PDF: {output_path}")
    
    def _write_fallback(self, data: Dict[str, Any], output_path: str):
        """Write text fallback when reportlab not available."""
        import json
        
        # Change extension to .txt
        txt_path = output_path.replace('.pdf', '.txt')
        
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"Report: {data.get('title', 'IsoLog Report')}\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}\n")
            f.write("=" * 60 + "\n\n")
            f.write(json.dumps(data, indent=2, default=str))
        
        logger.warning(f"PDF not available, wrote text fallback: {txt_path}")
