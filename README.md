# IsoLog - Portable SIEM for Isolated Networks

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**IsoLog** is a lightweight, offline-capable Security Information and Event Management (SIEM) system designed for air-gapped and isolated networks.

## Features

- **Multi-source Log Collection**: Syslog, file watchers, USB import
- **ECS-compliant Parsing**: Linux syslog, Windows events, JSON, CSV, firewall logs
- **Detection Engine**: 
  - Sigma rule matching
  - MITRE ATT&CK TTP mapping
  - ML anomaly detection (Isolation Forest)
  - Threat scoring
- **Blockchain Integrity**: Tamper-evident log hashing with Merkle trees
- **Offline Updates**: Signed update bundles for rules, models, and intel
- **Web Dashboard**: React-based UI with event streams, alerts, and MITRE heatmap

## Quick Start

### Option 1: Development Mode

```bash
# Clone and setup
git clone https://github.com/your-org/isolog.git
cd isolog

# Backend
cd backend
pip install -r requirements.txt
python main.py

# Frontend (new terminal)
cd ui
npm install
npm run dev
```

Access at `http://localhost:8000` (backend) or `http://localhost:3000` (frontend dev)

### Option 2: Docker

```bash
cd docker
docker-compose up -d
```

Access at `http://localhost:8000` (backend) or `http://localhost:3000` (frontend)

### Option 3: Portable Binary

```bash
# Build portable package
python build.py portable

# Run
cd dist/isolog-portable
./start.sh  # Linux/Mac
start.bat   # Windows
```

## Project Structure

```
IsoLog/
├── backend/
│   ├── api/           # FastAPI routes
│   ├── config/        # Configuration management
│   ├── storage/       # SQLite + SQLAlchemy models
│   ├── parsers/       # Log format parsers
│   ├── detection/     # Sigma, MITRE, ML detection
│   ├── blockchain/    # Hash chain integrity
│   ├── updates/       # Offline update system
│   └── main.py        # Entry point
├── ui/                # React frontend
├── rules/             # Sigma detection rules
├── docker/            # Docker configuration
├── config.yml         # Main configuration
└── build.py           # Build script
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/events` | Query log events |
| `GET /api/alerts` | Query security alerts |
| `GET /api/dashboard/stats` | Dashboard statistics |
| `POST /api/search` | Full-text search |
| `GET /api/integrity/verify` | Verify blockchain |
| `GET /api/system/status` | System health |

## Detection Capabilities

### Sigma Rules
Place YAML rules in `rules/sigma_rules/`. Example:
```yaml
title: Brute Force Attack
detection:
  selection:
    event.action: ssh_login
    event.outcome: failure
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1110
```

### MITRE ATT&CK
Automatic mapping of detections to ATT&CK tactics and techniques.

### ML Anomaly Detection
Isolation Forest model trains on event patterns and flags anomalies.

## Offline Updates

1. Create update bundle:
```python
from backend.updates import UpdateBundle
bundle = UpdateBundle()
path = bundle.create(
    output_dir="./updates",
    sigma_rules_path="./new_rules",
)
```

2. Apply update via UI Settings page or API

## Configuration

Edit `config.yml`:
```yaml
server:
  host: 0.0.0.0
  port: 8000

detection:
  sigma:
    enabled: true
  anomaly:
    enabled: true
    threshold: 0.85

blockchain:
  enabled: true
  batch_size: 100
```

## License

MIT License - See [LICENSE](LICENSE) for details.
