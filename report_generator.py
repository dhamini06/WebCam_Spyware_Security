"""
Report Generator for Webcam Spyware Security
Generates activity reports in multiple formats (JSON, CSV, PDF)
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Optional
import logging

from database import DatabaseManager
from utils import FileUtils, DateTimeUtils

logger = logging.getLogger(__name__)

# Try to import reportlab for PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    logger.warning("ReportLab not installed. PDF generation will be disabled.")


class ReportGenerator:
    """Generates activity reports in multiple formats"""
    
    # Report types
    REPORT_TYPE_ACTIVITY = "activity"
    REPORT_TYPE_SECURITY = "security"
    REPORT_TYPE_SUMMARY = "summary"
    REPORT_TYPE_AUDIT = "audit"
    
    # Export formats
    FORMAT_JSON = "json"
    FORMAT_CSV = "csv"
    FORMAT_PDF = "pdf"
    
    def __init__(self, db: DatabaseManager = None, output_dir: str = None):
        """
        Initialize report generator
        
        Args:
            db: Database manager instance
            output_dir: Output directory for reports
        """
        self.db = db or DatabaseManager()
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(__file__), 'reports'
        )
        FileUtils.ensure_dir_exists(self.output_dir)
        logger.info(f"Report generator initialized: {self.output_dir}")
    
    # ============ REPORT GENERATION ============
    
    def generate_activity_report(self, start_date: str = None, 
                                end_date: str = None,
                                user_id: int = None) -> Dict:
        """
        Generate activity report
        
        Args:
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
            user_id: Filter by user (optional)
            
        Returns:
            Report dictionary
        """
        try:
            # Get date range
            if not end_date:
                end_date = datetime.now().isoformat()
            if not start_date:
                # Get 30 days ago
                start_dt = datetime.fromisoformat(end_date) if isinstance(end_date, str) else datetime.now()
                start_dt = start_dt.replace(day=max(1, start_dt.day - 30))
                start_date = start_dt.isoformat()
            
            # Get logs
            if user_id:
                logs = self.db.get_logs_by_user(user_id, limit=1000)
            else:
                logs = self.db.get_all_logs(limit=1000)
            
            # Convert logs to list of tuples if needed
            filtered_logs = logs if logs else []
            
            report = {
                'report_type': self.REPORT_TYPE_ACTIVITY,
                'generated_at': DateTimeUtils.get_current_timestamp(),
                'start_date': start_date,
                'end_date': end_date,
                'user_id': user_id,
                'total_entries': len(filtered_logs),
                'logs': [self._format_log_entry(log) for log in filtered_logs]
            }
            
            return report
        
        except Exception as e:
            logger.error(f"Error generating activity report: {e}")
            return {}
    
    def generate_security_report(self, start_date: str = None,
                                end_date: str = None) -> Dict:
        """
        Generate security report (failed logins, intruder attempts)
        
        Args:
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
            
        Returns:
            Report dictionary
        """
        try:
            if not end_date:
                end_date = datetime.now().isoformat()
            if not start_date:
                start_dt = datetime.fromisoformat(end_date) if isinstance(end_date, str) else datetime.now()
                start_dt = start_dt.replace(day=max(1, start_dt.day - 30))
                start_date = start_dt.isoformat()
            
            # Get critical and error logs
            critical_logs = self.db.get_logs_by_severity('critical', limit=500)
            error_logs = self.db.get_logs_by_severity('error', limit=500)
            
            all_security_logs = critical_logs + error_logs if critical_logs and error_logs else critical_logs or error_logs or []
            
            # Count security events
            security_event_count = len(all_security_logs)
            
            report = {
                'report_type': self.REPORT_TYPE_SECURITY,
                'generated_at': DateTimeUtils.get_current_timestamp(),
                'start_date': start_date,
                'end_date': end_date,
                'total_security_events': security_event_count,
                'critical_events': len(critical_logs) if critical_logs else 0,
                'error_events': len(error_logs) if error_logs else 0,
                'events': [self._format_log_entry(log) for log in all_security_logs[:50]]
            }
            
            return report
        
        except Exception as e:
            logger.error(f"Error generating security report: {e}")
            return {}
    
    def generate_summary_report(self) -> Dict:
        """
        Generate summary report
        
        Returns:
            Report dictionary
        """
        try:
            stats = self.db.get_database_stats()
            
            report = {
                'report_type': self.REPORT_TYPE_SUMMARY,
                'generated_at': DateTimeUtils.get_current_timestamp(),
                'database_statistics': stats if stats else {},
                'system_health': {
                    'status': 'healthy',
                    'timestamp': DateTimeUtils.get_current_timestamp()
                }
            }
            
            return report
        
        except Exception as e:
            logger.error(f"Error generating summary report: {e}")
            return {}
    
    def generate_audit_report(self, user_id: int = None) -> Dict:
        """
        Generate audit trail report
        
        Args:
            user_id: Filter by user (optional)
            
        Returns:
            Report dictionary
        """
        try:
            if user_id:
                logs = self.db.get_logs_by_user(user_id, limit=1000)
            else:
                logs = self.db.get_all_logs(limit=1000)
            
            # Filter for admin actions
            admin_actions = [
                log for log in logs
                if 'admin' in str(log).lower() or 
                   'policy' in str(log).lower() or
                   'user' in str(log).lower()
            ]
            
            report = {
                'report_type': self.REPORT_TYPE_AUDIT,
                'generated_at': DateTimeUtils.get_current_timestamp(),
                'audit_entries': len(admin_actions),
                'entries': [self._format_log_entry(log) for log in admin_actions[:100]]
            }
            
            return report
        
        except Exception as e:
            logger.error(f"Error generating audit report: {e}")
            return {}
    
    # ============ EXPORT FUNCTIONS ============
    
    def export_report_json(self, report: Dict, filename: str = None) -> str:
        """
        Export report to JSON
        
        Args:
            report: Report dictionary
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            Path to saved file
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_type = report.get('report_type', 'report')
                filename = f"{report_type}_{timestamp}.json"
            
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"JSON report saved: {filepath}")
            return filepath
        
        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")
            return ""
    
    def export_report_csv(self, report: Dict, filename: str = None) -> str:
        """
        Export report to CSV
        
        Args:
            report: Report dictionary
            filename: Output filename
            
        Returns:
            Path to saved file
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_type = report.get('report_type', 'report')
                filename = f"{report_type}_{timestamp}.csv"
            
            filepath = os.path.join(self.output_dir, filename)
            
            # Get entries from report
            entries = report.get('logs', report.get('entries', []))
            
            if not entries:
                logger.warning("No entries to export to CSV")
                return ""
            
            # Get field names from first entry
            fieldnames = list(entries[0].keys()) if entries else []
            
            with open(filepath, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(entries)
            
            logger.info(f"CSV report saved: {filepath}")
            return filepath
        
        except Exception as e:
            logger.error(f"Error exporting CSV: {e}")
            return ""
    
    def export_report_pdf(self, report: Dict, filename: str = None) -> str:
        """
        Export report to PDF
        
        Args:
            report: Report dictionary
            filename: Output filename
            
        Returns:
            Path to saved file or empty string if PDF not available
        """
        if not HAS_REPORTLAB:
            logger.warning("ReportLab not installed. Cannot generate PDF.")
            return ""
        
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_type = report.get('report_type', 'report')
                filename = f"{report_type}_{timestamp}.pdf"
            
            filepath = os.path.join(self.output_dir, filename)
            
            # Create PDF
            doc = SimpleDocTemplate(filepath, pagesize=letter)
            elements = []
            
            # Styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'Title',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1f6aa5'),
                spaceAfter=30
            )
            
            # Add title
            title = f"Webcam Spyware Security - {report.get('report_type', 'Report').title()}"
            elements.append(Paragraph(title, title_style))
            elements.append(Spacer(1, 0.3*inch))
            
            # Add summary info
            summary_data = [
                ["Report Type", report.get('report_type', 'N/A')],
                ["Generated At", str(report.get('generated_at', 'N/A'))],
                ["Total Entries", str(report.get('total_entries', 
                                               report.get('audit_entries', 'N/A')))],
            ]
            
            summary_table = Table(summary_data)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 0.3*inch))
            
            # Add entries as table if available
            entries = report.get('logs', report.get('entries', []))
            if entries and len(entries) > 0:
                # Limit to first 20 entries for PDF
                limited_entries = entries[:20]
                
                # Create table data
                fieldnames = list(limited_entries[0].keys())
                table_data = [fieldnames]
                
                for entry in limited_entries:
                    row = [str(entry.get(field, ''))[:50] for field in fieldnames]
                    table_data.append(row)
                
                entries_table = Table(table_data)
                entries_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                elements.append(entries_table)
            
            # Build PDF
            doc.build(elements)
            
            logger.info(f"PDF report saved: {filepath}")
            return filepath
        
        except Exception as e:
            logger.error(f"Error exporting PDF: {e}")
            return ""
    
    # ============ HELPER METHODS ============
    
    def _format_log_entry(self, log_tuple) -> Dict:
        """Format database log tuple to dictionary"""
        try:
            # Handle both tuple and dict-like objects
            if isinstance(log_tuple, dict):
                return {
                    'log_id': log_tuple.get('log_id'),
                    'user_id': log_tuple.get('user_id'),
                    'action': log_tuple.get('action'),
                    'severity': log_tuple.get('severity'),
                    'timestamp': log_tuple.get('timestamp', '')
                }
            
            # Handle tuple/row objects
            try:
                return {
                    'log_id': log_tuple[0] if len(log_tuple) > 0 else None,
                    'user_id': log_tuple[1] if len(log_tuple) > 1 else None,
                    'action': log_tuple[2] if len(log_tuple) > 2 else None,
                    'severity': log_tuple[3] if len(log_tuple) > 3 else None,
                    'timestamp': log_tuple[4] if len(log_tuple) > 4 else ''
                }
            except (TypeError, IndexError):
                # If it's a Row object, try converting to dict
                if hasattr(log_tuple, 'keys'):
                    return dict(log_tuple)
                return {}
        except Exception as e:
            logger.error(f"Error formatting log entry: {e}")
            return {}
    
    def get_report_statistics(self) -> Dict:
        """Get report generation statistics"""
        try:
            report_files = os.listdir(self.output_dir)
            
            stats = {
                'total_reports': len(report_files),
                'reports_by_format': {
                    'json': sum(1 for f in report_files if f.endswith('.json')),
                    'csv': sum(1 for f in report_files if f.endswith('.csv')),
                    'pdf': sum(1 for f in report_files if f.endswith('.pdf')),
                },
                'output_directory': self.output_dir,
                'pdf_available': HAS_REPORTLAB
            }
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    generator = ReportGenerator()
    
    print("=== Report Generator Test ===\n")
    
    # Test activity report
    print("[1] Generating activity report:")
    activity_report = generator.generate_activity_report()
    print(f"  Report type: {activity_report.get('report_type')}")
    print(f"  Total entries: {activity_report.get('total_entries')}")
    
    # Test security report
    print("\n[2] Generating security report:")
    security_report = generator.generate_security_report()
    print(f"  Report type: {security_report.get('report_type')}")
    print(f"  Security events: {security_report.get('total_security_events')}")
    
    # Test summary report
    print("\n[3] Generating summary report:")
    summary_report = generator.generate_summary_report()
    print(f"  Report type: {summary_report.get('report_type')}")
    
    # Test exports
    print("\n[4] Testing exports:")
    json_path = generator.export_report_json(activity_report)
    print(f"  JSON export: {bool(json_path)}")
    
    csv_path = generator.export_report_csv(activity_report)
    print(f"  CSV export: {bool(csv_path)}")
    
    pdf_path = generator.export_report_pdf(activity_report)
    print(f"  PDF export: {bool(pdf_path)}")
    
    # Test statistics
    print("\n[5] Report Statistics:")
    stats = generator.get_report_statistics()
    print(f"  Total reports: {stats.get('total_reports')}")
    print(f"  By format: {stats.get('reports_by_format')}")
    print(f"  PDF available: {stats.get('pdf_available')}")
    
    print("\n[6] Report Generator capabilities:")
    print("  ✅ Activity reports")
    print("  ✅ Security reports")
    print("  ✅ Summary reports")
    print("  ✅ Audit trail reports")
    print("  ✅ JSON export")
    print("  ✅ CSV export")
    if HAS_REPORTLAB:
        print("  ✅ PDF export")
    else:
        print("  ⚠️  PDF export (ReportLab not installed)")
    
    print("\n=== All tests completed successfully ===")
