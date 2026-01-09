"""
Cybersecurity Log Analyzer
A tool to parse, analyze, and report on security logs for threat detection.
"""

import re
import csv
import json
from datetime import datetime
from collections import defaultdict
from pathlib import Path


class LogAnalyzer:
    """Analyze security logs for suspicious activities and patterns."""
    
    def __init__(self, log_file):
        self.log_file = log_file
        self.logs = []
        self.alerts = []
        self.ip_stats = defaultdict(int)
        self.failed_logins = defaultdict(int)
        
    def parse_logs(self):
        """Parse log file and extract relevant information."""
        try:
            with open(self.log_file, 'r') as file:
                for line in file:
                    if line.strip():
                        parsed = self._parse_log_line(line)
                        if parsed:
                            self.logs.append(parsed)
            print(f"Successfully parsed {len(self.logs)} log entries")
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found")
        except Exception as e:
            print(f"Error parsing logs: {str(e)}")
    
    def _parse_log_line(self, line):
        """Extract fields from a single log line."""
        # Pattern: [timestamp] [level] [source_ip] [username] [action] [status]
        pattern = r'\[(.+?)\]\s+\[(.+?)\]\s+(\S+)\s+(\S+)\s+(.+?)\s+\[(.+?)\]'
        match = re.match(pattern, line)
        
        if match:
            return {
                'timestamp': match.group(1),
                'level': match.group(2),
                'source_ip': match.group(3),
                'username': match.group(4),
                'action': match.group(5),
                'status': match.group(6)
            }
        return None
    
    def detect_failed_logins(self, threshold=5):
        """Detect IPs with multiple failed login attempts."""
        for log in self.logs:
            if log['action'] == 'LOGIN_ATTEMPT' and log['status'] == 'FAILED':
                ip = log['source_ip']
                self.failed_logins[ip] += 1
        
        # Generate alerts for IPs exceeding threshold
        for ip, count in self.failed_logins.items():
            if count >= threshold:
                self.alerts.append({
                    'type': 'BRUTE_FORCE_ATTEMPT',
                    'severity': 'HIGH',
                    'ip': ip,
                    'failed_attempts': count,
                    'description': f"IP {ip} has {count} failed login attempts"
                })
    
    def detect_suspicious_ips(self):
        """Identify IPs with unusual activity patterns."""
        for log in self.logs:
            ip = log['source_ip']
            self.ip_stats[ip] += 1
        
        # Calculate average activity per IP
        if self.ip_stats:
            avg_activity = sum(self.ip_stats.values()) / len(self.ip_stats)
            threshold = avg_activity * 2
            
            for ip, count in self.ip_stats.items():
                if count > threshold:
                    self.alerts.append({
                        'type': 'UNUSUAL_ACTIVITY',
                        'severity': 'MEDIUM',
                        'ip': ip,
                        'activity_count': count,
                        'description': f"IP {ip} shows unusual activity level ({count} requests)"
                    })
    
    def analyze_patterns(self):
        """Analyze log patterns for security insights."""
        # Track action types
        action_count = defaultdict(int)
        status_count = defaultdict(int)
        
        for log in self.logs:
            action_count[log['action']] += 1
            status_count[log['status']] += 1
        
        return {
            'total_logs': len(self.logs),
            'action_distribution': dict(action_count),
            'status_distribution': dict(status_count),
            'unique_ips': len(self.ip_stats),
            'unique_users': len(set(log['username'] for log in self.logs))
        }
    
    def generate_report(self, output_file='report.json'):
        """Generate comprehensive security analysis report."""
        self.parse_logs()
        self.detect_failed_logins()
        self.detect_suspicious_ips()
        patterns = self.analyze_patterns()
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'log_file': str(self.log_file),
            'summary': patterns,
            'alerts': self.alerts,
            'top_ips': self._get_top_ips(5),
            'top_users': self._get_top_users(5)
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report generated: {output_file}")
            return report
        except Exception as e:
            print(f"Error writing report: {str(e)}")
            return None
    
    def _get_top_ips(self, n=5):
        """Get top N IPs by activity."""
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'count': count} for ip, count in sorted_ips[:n]]
    
    def _get_top_users(self, n=5):
        """Get top N users by activity."""
        user_count = defaultdict(int)
        for log in self.logs:
            user_count[log['username']] += 1
        sorted_users = sorted(user_count.items(), key=lambda x: x[1], reverse=True)
        return [{'username': user, 'count': count} for user, count in sorted_users[:n]]
    
    def export_alerts_csv(self, output_file='alerts.csv'):
        """Export alerts to CSV format."""
        if not self.alerts:
            print("No alerts to export")
            return
        
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.alerts[0].keys())
                writer.writeheader()
                writer.writerows(self.alerts)
            print(f"Alerts exported to: {output_file}")
        except Exception as e:
            print(f"Error exporting alerts: {str(e)}")


def main():
    """Main execution function."""
    # Example usage
    log_file = 'sample_logs.txt'
    
    # Create sample log file if it doesn't exist
    if not Path(log_file).exists():
        create_sample_logs(log_file)
    
    # Run analysis
    analyzer = LogAnalyzer(log_file)
    analyzer.generate_report('security_report.json')
    analyzer.export_alerts_csv('security_alerts.csv')
    
    # Print summary
    print("\n" + "="*60)
    print("SECURITY ANALYSIS SUMMARY")
    print("="*60)
    print(f"Total Logs Analyzed: {len(analyzer.logs)}")
    print(f"Total Alerts Generated: {len(analyzer.alerts)}")
    print(f"Unique IPs: {len(analyzer.ip_stats)}")
    print(f"High Severity Alerts: {sum(1 for a in analyzer.alerts if a['severity'] == 'HIGH')}")


def create_sample_logs(filename):
    """Create sample log file for testing."""
    sample_logs = [
        "[2024-01-15 08:30:22] [INFO] 192.168.1.100 admin LOGIN_ATTEMPT [SUCCESS]",
        "[2024-01-15 08:31:45] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
        "[2024-01-15 08:32:10] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
        "[2024-01-15 08:33:20] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
        "[2024-01-15 08:34:15] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
        "[2024-01-15 08:35:05] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
        "[2024-01-15 08:36:30] [WARNING] 192.168.1.102 user2 DATA_ACCESS [SUCCESS]",
        "[2024-01-15 08:37:45] [WARNING] 192.168.1.102 user2 DATA_ACCESS [SUCCESS]",
        "[2024-01-15 08:38:22] [INFO] 192.168.1.103 admin FILE_DELETION [SUCCESS]",
        "[2024-01-15 08:39:10] [ERROR] 192.168.1.104 unknown UNAUTHORIZED_ACCESS [FAILED]",
        "[2024-01-15 08:40:55] [ERROR] 192.168.1.104 unknown UNAUTHORIZED_ACCESS [FAILED]",
        "[2024-01-15 08:41:30] [ERROR] 192.168.1.104 unknown UNAUTHORIZED_ACCESS [FAILED]",
    ]
    
    with open(filename, 'w') as f:
        f.write('\n'.join(sample_logs))
    print(f"Sample log file created: {filename}")


if __name__ == '__main__':
    main()
