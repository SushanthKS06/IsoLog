# IsoLog User Guide

## Introduction

IsoLog is a portable SIEM designed for isolated/air-gapped networks. It provides:
- Log collection and parsing
- Threat detection with Sigma rules and ML
- MITRE ATT&CK mapping
- Tamper-evident log integrity
- Offline updates

## Getting Started

### Navigation

The sidebar provides access to all views:

| Page | Description |
|------|-------------|
| **Dashboard** | Overview stats, timeline, recent alerts |
| **Events** | Browse and search all log events |
| **Alerts** | Security alerts with filtering |
| **MITRE ATT&CK** | Technique coverage heatmap |
| **Settings** | System status and configuration |

### Dashboard

The dashboard shows:
- **Stats Cards**: Total alerts, critical/high counts, events today
- **Timeline Chart**: Alert activity over 24 hours
- **Recent Alerts**: Latest detections with quick actions

### Events Page

Browse all ingested log events:
1. Use the search box to find specific events
2. Filter by action type or time range
3. Export to CSV for external analysis

### Alerts Page

Manage security alerts:
1. Filter by severity or status
2. Click eye icon to view details
3. Click checkmark to acknowledge
4. Export as JSON or CSV

### MITRE ATT&CK View

Visual heatmap showing:
- Tactics across the top (14 columns)
- Techniques color-coded by detection count
- Click cells to see technique details

### Settings

System management:
- **Status**: Check component health
- **Blockchain**: Verify log integrity
- **Configuration**: View current settings

## Adding Detection Rules

Place Sigma rules in `rules/sigma_rules/`:

```yaml
title: My Detection Rule
detection:
  selection:
    event.action: suspicious_action
  condition: selection
level: high
tags:
  - attack.t1059
```

Use Settings > Reload Rules to activate.

## Offline Updates

1. Place `.tar.gz` bundle in `updates/` folder
2. Go to Settings page
3. Apply update (rules, models, intel)
4. Automatic backup created before changes

## Data Export

### Events
- CSV format with timestamp, host, user, action, message

### Alerts
- JSON with full detection details
- CSV summary format

### Integrity Report
- Blockchain verification results
- Chain statistics

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No events showing | Check file watcher paths in config.yml |
| No alerts | Verify Sigma rules exist in rules/sigma_rules/ |
| ML not detecting | Wait for 1000+ events for model training |
| Blockchain errors | Run integrity verification to locate issues |
