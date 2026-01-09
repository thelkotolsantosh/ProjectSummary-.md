"""
Unit tests for the Cybersecurity Log Analyzer
"""

import unittest
import json
from pathlib import Path
from log_analyzer import LogAnalyzer


class TestLogAnalyzer(unittest.TestCase):
    """Test cases for LogAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_log_file = 'test_logs.txt'
        self.create_test_logs()
        self.analyzer = LogAnalyzer(self.test_log_file)
    
    def tearDown(self):
        """Clean up test files"""
        if Path(self.test_log_file).exists():
            Path(self.test_log_file).unlink()
        if Path('test_report.json').exists():
            Path('test_report.json').unlink()
        if Path('test_alerts.csv').exists():
            Path('test_alerts.csv').unlink()
    
    def create_test_logs(self):
        """Create test log file"""
        test_logs = [
            "[2024-01-15 08:30:22] [INFO] 192.168.1.100 admin LOGIN_ATTEMPT [SUCCESS]",
            "[2024-01-15 08:31:45] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
            "[2024-01-15 08:32:10] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
            "[2024-01-15 08:33:20] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
            "[2024-01-15 08:34:15] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
            "[2024-01-15 08:35:05] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]",
        ]
        
        with open(self.test_log_file, 'w') as f:
            f.write('\n'.join(test_logs))
    
    def test_parse_logs(self):
        """Test log parsing functionality"""
        self.analyzer.parse_logs()
        self.assertEqual(len(self.analyzer.logs), 6)
        self.assertEqual(self.analyzer.logs[0]['username'], 'admin')
        self.assertEqual(self.analyzer.logs[0]['source_ip'], '192.168.1.100')
    
    def test_parse_log_line(self):
        """Test individual log line parsing"""
        line = "[2024-01-15 08:30:22] [INFO] 192.168.1.100 admin LOGIN_ATTEMPT [SUCCESS]"
        parsed = self.analyzer._parse_log_line(line)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['timestamp'], '2024-01-15 08:30:22')
        self.assertEqual(parsed['level'], 'INFO')
        self.assertEqual(parsed['source_ip'], '192.168.1.100')
        self.assertEqual(parsed['username'], 'admin')
        self.assertEqual(parsed['status'], 'SUCCESS')
    
    def test_detect_failed_logins(self):
        """Test brute force detection"""
        self.analyzer.parse_logs()
        self.analyzer.detect_failed_logins(threshold=5)
        
        brute_force_alerts = [a for a in self.analyzer.alerts 
                             if a['type'] == 'BRUTE_FORCE_ATTEMPT']
        self.assertEqual(len(brute_force_alerts), 1)
        self.assertEqual(brute_force_alerts[0]['ip'], '192.168.1.101')
        self.assertEqual(brute_force_alerts[0]['failed_attempts'], 5)
    
    def test_analyze_patterns(self):
        """Test pattern analysis"""
        self.analyzer.parse_logs()
        patterns = self.analyzer.analyze_patterns()
        
        self.assertEqual(patterns['total_logs'], 6)
        self.assertEqual(patterns['unique_ips'], 2)
        self.assertEqual(patterns['unique_users'], 2)
        self.assertIn('LOGIN_ATTEMPT', patterns['action_distribution'])
    
    def test_get_top_ips(self):
        """Test top IPs retrieval"""
        self.analyzer.parse_logs()
        self.analyzer.detect_suspicious_ips()
        top_ips = self.analyzer._get_top_ips(5)
        
        self.assertGreater(len(top_ips), 0)
        self.assertIn('ip', top_ips[0])
        self.assertIn('count', top_ips[0])
    
    def test_get_top_users(self):
        """Test top users retrieval"""
        self.analyzer.parse_logs()
        top_users = self.analyzer._get_top_users(5)
        
        self.assertGreater(len(top_users), 0)
        self.assertIn('username', top_users[0])
        self.assertIn('count', top_users[0])
    
    def test_generate_report(self):
        """Test report generation"""
        report = self.analyzer.generate_report('test_report.json')
        
        self.assertIsNotNone(report)
        self.assertIn('generated_at', report)
        self.assertIn('summary', report)
        self.assertIn('alerts', report)
        self.assertIn('top_ips', report)
        self.assertIn('top_users', report)
    
    def test_report_file_exists(self):
        """Test that report file is created"""
        self.analyzer.generate_report('test_report.json')
        self.assertTrue(Path('test_report.json').exists())
    
    def test_report_valid_json(self):
        """Test that report contains valid JSON"""
        self.analyzer.generate_report('test_report.json')
        
        with open('test_report.json', 'r') as f:
            data = json.load(f)
        
        self.assertIsInstance(data, dict)
        self.assertIn('summary', data)
    
    def test_export_alerts_csv(self):
        """Test CSV export"""
        self.analyzer.parse_logs()
        self.analyzer.detect_failed_logins()
        self.analyzer.export_alerts_csv('test_alerts.csv')
        
        self.assertTrue(Path('test_alerts.csv').exists())


class TestLogParsingEdgeCases(unittest.TestCase):
    """Test edge cases in log parsing"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_log_file = 'edge_case_logs.txt'
        self.analyzer = LogAnalyzer(self.test_log_file)
    
    def tearDown(self):
        """Clean up test files"""
        if Path(self.test_log_file).exists():
            Path(self.test_log_file).unlink()
    
    def test_parse_invalid_format(self):
        """Test parsing of malformed log lines"""
        invalid_log = "This is not a valid log format"
        parsed = self.analyzer._parse_log_line(invalid_log)
        self.assertIsNone(parsed)
    
    def test_parse_empty_lines(self):
        """Test handling of empty lines"""
        with open(self.test_log_file, 'w') as f:
            f.write("[2024-01-15 08:30:22] [INFO] 192.168.1.100 admin LOGIN_ATTEMPT [SUCCESS]\n")
            f.write("\n")
            f.write("[2024-01-15 08:31:45] [INFO] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]\n")
        
        self.analyzer.parse_logs()
        self.assertEqual(len(self.analyzer.logs), 2)


if __name__ == '__main__':
    unittest.main()
