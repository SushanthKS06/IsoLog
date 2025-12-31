# IsoLog API Reference

## Base URL

```
http://localhost:8000/api
```

## Authentication

Currently optional for isolated deployments. Configure in `config.yml`.

---

## Events

### List Events
```http
GET /events
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `start_time` | datetime | Filter events after this time |
| `end_time` | datetime | Filter events before this time |
| `host_name` | string | Filter by host (partial match) |
| `source_ip` | string | Filter by source IP |
| `user_name` | string | Filter by user |
| `event_action` | string | Filter by action type |
| `page` | int | Page number (default: 1) |
| `page_size` | int | Items per page (default: 50) |

**Response:**
```json
{
  "events": [...],
  "total": 1234,
  "page": 1,
  "page_size": 50
}
```

### Get Event by ID
```http
GET /events/{event_id}
```

### Get Event Statistics
```http
GET /events/stats
```

---

## Alerts

### List Alerts
```http
GET /alerts
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | critical, high, medium, low |
| `status` | string | new, acknowledged, resolved |
| `rule_id` | string | Filter by rule ID |
| `detection_type` | string | sigma, ml, heuristic |
| `min_threat_score` | float | Minimum score |

### Get Alert Counts
```http
GET /alerts/count
```

### Get Alert Timeline
```http
GET /alerts/timeline?start_time=...&end_time=...&bucket_minutes=60
```

### Get MITRE Statistics
```http
GET /alerts/mitre
```

### Acknowledge Alert
```http
POST /alerts/{alert_id}/acknowledge
```
```json
{
  "acknowledged_by": "analyst",
  "status": "acknowledged"
}
```

---

## Dashboard

### Get Stats
```http
GET /dashboard/stats
```

### Get Recent Alerts
```http
GET /dashboard/recent-alerts?limit=10
```

### Get Timeline
```http
GET /dashboard/timeline?hours=24
```

---

## Search

### Full-text Search
```http
POST /search
```
```json
{
  "query": "search term",
  "limit": 50
}
```

### Get Suggestions
```http
GET /search/suggestions?q=prefix
```

---

## Integrity

### Verify Chain
```http
GET /integrity/verify
```

### Get Report
```http
GET /integrity/report
```

### Get Chain Blocks
```http
GET /integrity/chain?start_block=1&end_block=100
```

### Export Chain
```http
GET /integrity/export
```

---

## System

### Get Status
```http
GET /system/status
```

### Get Config
```http
GET /system/config
```

### Get MITRE Matrix
```http
GET /system/mitre/matrix
```

### Reload Rules
```http
POST /system/reload-rules
```

---

## Health Check

```http
GET /health
```
```json
{
  "status": "healthy",
  "service": "isolog"
}
```
