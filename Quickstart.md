# Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer

# Install dependencies
pip install -r requirements.txt
```

## Run the Analyzer

```bash
# Run with default sample logs
python log_analyzer.py

# This will create:
# - sample_logs.txt (if not exists)
# - security_report.json
# - security_alerts.csv
```

## Use as a Module

```python
from log_analyzer import LogAnalyzer

# Analyze your own log file
analyzer = LogAnalyzer('your_logs.txt')
analyzer.generate_report('my_report.json')
analyzer.export_alerts_csv('my_alerts.csv')
```

## Run Tests

```bash
python -m unittest discover -s . -p 'test_*.py' -v
```

## Understanding the Output

### security_report.json
```json
{
  "generated_at": "2024-01-15T14:30:00",
  "summary": {
    "total_logs": 12,
    "unique_ips": 5,
    "unique_users": 4,
    "action_distribution": {...},
    "status_distribution": {...}
  },
  "alerts": [
    {
      "type": "BRUTE_FORCE_ATTEMPT",
      "severity": "HIGH",
      "ip": "192.168.1.101",
      "failed_attempts": 5
    }
  ],
  "top_ips": [...],
  "top_users": [...]
}
```

### security_alerts.csv
```
type,severity,ip,failed_attempts,description
BRUTE_FORCE_ATTEMPT,HIGH,192.168.1.101,5,IP 192.168.1.101 has 5 failed login attempts
```

## Customizing Log Format

If your logs use a different format, modify the regex pattern in `_parse_log_line()`:

```python
# Current pattern
pattern = r'\[(.+?)\]\s+\[(.+?)\]\s+(\S+)\s+(\S+)\s+(.+?)\s+\[(.+?)\]'

# Your custom pattern
pattern = r'YOUR_CUSTOM_PATTERN_HERE'
```

## Key Features

✓ Brute Force Detection (5+ failed logins)
✓ Anomaly Detection (unusual activity levels)
✓ JSON Report Generation
✓ CSV Alert Export
✓ IP Statistics
✓ User Activity Tracking
✓ Comprehensive Test Suite

## Requirements

- Python 3.7+
- pandas >= 2.0.0
- matplotlib >= 3.7.0
