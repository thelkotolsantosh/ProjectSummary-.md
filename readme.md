# Cybersecurity Log Analyzer

A lightweight Python tool for parsing, analyzing, and detecting suspicious patterns in security logs.

## Features

- **Log Parsing**: Extracts timestamps, IP addresses, usernames, actions, and status from log files
- **Brute Force Detection**: Identifies IPs with multiple failed login attempts
- **Anomaly Detection**: Detects unusual activity patterns based on statistical analysis
- **Alert Generation**: Generates security alerts with severity levels
- **Report Generation**: Creates comprehensive JSON reports and CSV alert exports
- **Data Analysis**: Tracks action distribution, user activity, and IP statistics

## Project Structure

```
cybersecurity-log-analyzer/
├── log_analyzer.py          # Main application
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── .gitignore              # Git ignore rules
├── LICENSE                 # MIT License
└── sample_logs.txt         # Sample log file (auto-generated)
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

#Basic Usage

```python
from log_analyzer import LogAnalyzer

# Initialize the analyzer
analyzer = LogAnalyzer('your_log_file.txt')

# Generate complete report
analyzer.generate_report('security_report.json')

# Export alerts to CSV
analyzer.export_alerts_csv('security_alerts.csv')
```

#Command Line

```bash
python log_analyzer.py
```

This will:
1. Create a sample log file if none exists
2. Analyze the logs
3. Generate `security_report.json` with detailed findings
4. Export `security_alerts.csv` with all detected alerts

## Log Format

The analyzer expects logs in the following format:

```
[YYYY-MM-DD HH:MM:SS] [LEVEL] SOURCE_IP USERNAME ACTION [STATUS]
```

Example:
```
[2024-01-15 08:30:22] [INFO] 192.168.1.100 admin LOGIN_ATTEMPT [SUCCESS]
[2024-01-15 08:31:45] [WARNING] 192.168.1.101 user1 LOGIN_ATTEMPT [FAILED]
```

#Log Fields

- **Timestamp**: Date and time of the event
- **Level**: Log severity (INFO, WARNING, ERROR)
- **Source IP**: IP address of the source
- **Username**: User account involved
- **Action**: Type of action (LOGIN_ATTEMPT, DATA_ACCESS, FILE_DELETION, etc.)
- **Status**: Result of the action (SUCCESS, FAILED)

## Alert Types

#1. Brute Force Attempt (HIGH)
- Triggered when an IP has 5+ failed login attempts
- Indicates potential password guessing or dictionary attacks

#2. Unusual Activity (MEDIUM)
- Triggered when IP activity exceeds 2x the average
- Indicates abnormal traffic patterns

## Output Files

#security_report.json
Contains:
- Analysis summary (total logs, unique IPs, users)
- All generated alerts with severity levels
- Top 5 most active IPs
- Top 5 most active users
- Generation timestamp

Example:
```json
{
  "generated_at": "2024-01-15T14:30:00",
  "log_file": "sample_logs.txt",
  "summary": {
    "total_logs": 12,
    "unique_ips": 5,
    "unique_users": 4
  },
  "alerts": [
    {
      "type": "BRUTE_FORCE_ATTEMPT",
      "severity": "HIGH",
      "ip": "192.168.1.101",
      "failed_attempts": 5
    }
  ]
}
```

#security_alerts.csv
CSV export of all alerts with columns:
- type
- severity
- ip
- failed_attempts / activity_count
- description

## Classes and Methods

#LogAnalyzer

**`__init__(log_file)`**
- Initialize analyzer with log file path

**`parse_logs()`**
- Parse log file and extract log entries

**`detect_failed_logins(threshold=5)`**
- Detect brute force attempts based on failed login threshold

**`detect_suspicious_ips()`**
- Identify IPs with anomalous activity levels

**`analyze_patterns()`**
- Analyze overall log patterns and statistics

**`generate_report(output_file='report.json')`**
- Generate comprehensive security analysis report

**`export_alerts_csv(output_file='alerts.csv')`**
- Export alerts to CSV format

## Requirements

- Python 3.7+
- pandas (for data analysis)
- matplotlib (for potential future visualizations)

## Use Cases

1. **Security Operations Center (SOC)**: Automated threat detection and alerting
2. **Compliance Auditing**: Generate audit reports from system logs
3. **Forensics Investigation**: Analyze historical logs for breach investigations
4. **System Monitoring**: Continuous monitoring of authentication failures
5. **Incident Response**: Quick identification of suspicious patterns

## Customization

#Add Custom Rules

Modify the `LogAnalyzer` class to add custom detection rules:

```python
def detect_custom_threat(self):
    """Add your custom threat detection logic"""
    for log in self.logs:
        if your_condition:
            self.alerts.append({
                'type': 'CUSTOM_THREAT',
                'severity': 'HIGH',
                'description': 'Your description'
            })
```

#Adjust Thresholds

Modify detection thresholds in the methods:
- `detect_failed_logins(threshold=5)` - Change the number of failed attempts
- `detect_suspicious_ips()` - Modify the multiplier for activity threshold

## Performance

- Efficiently handles logs with 10,000+ entries
- O(n) time complexity for parsing and analysis
- Minimal memory footprint with streaming approach for large files

## Known Limitations

- Log format must match the expected pattern
- Currently single-threaded (can be improved for very large files)
- Requires properly formatted timestamps

## Future Enhancements

- [ ] Multi-threaded log parsing
- [ ] Visualization dashboards
- [ ] Machine learning-based anomaly detection
- [ ] Real-time log streaming support
- [ ] Multiple log format support
- [ ] Database integration
- [ ] Email alerting system

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created as a data analysis and cybersecurity tool.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

## Disclaimer

This tool is provided for educational and authorized security analysis purposes only. Users are responsible for ensuring they have proper authorization before analyzing logs from systems they do not own.
