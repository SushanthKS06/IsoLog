const API_BASE = '/api'

export async function fetchDashboardStats() {
    const response = await fetch(`${API_BASE}/dashboard/stats`)
    if (!response.ok) throw new Error('Failed to fetch stats')
    return response.json()
}

export async function fetchRecentAlerts(limit = 10) {
    const response = await fetch(`${API_BASE}/dashboard/recent-alerts?limit=${limit}`)
    if (!response.ok) throw new Error('Failed to fetch alerts')
    return response.json()
}

export async function fetchAlertTimeline(hours = 24) {
    const response = await fetch(`${API_BASE}/dashboard/timeline?hours=${hours}`)
    if (!response.ok) throw new Error('Failed to fetch timeline')
    return response.json()
}

export async function fetchAlerts(params = {}) {
    const query = new URLSearchParams(params).toString()
    const response = await fetch(`${API_BASE}/alerts?${query}`)
    if (!response.ok) throw new Error('Failed to fetch alerts')
    return response.json()
}

export async function fetchAlertCounts() {
    const response = await fetch(`${API_BASE}/alerts/count`)
    if (!response.ok) throw new Error('Failed to fetch counts')
    return response.json()
}

export async function fetchMitreStats() {
    const response = await fetch(`${API_BASE}/alerts/mitre`)
    if (!response.ok) throw new Error('Failed to fetch MITRE stats')
    return response.json()
}

export async function fetchEvents(params = {}) {
    const query = new URLSearchParams(params).toString()
    const response = await fetch(`${API_BASE}/events?${query}`)
    if (!response.ok) throw new Error('Failed to fetch events')
    return response.json()
}

export async function fetchEventStats() {
    const response = await fetch(`${API_BASE}/events/stats`)
    if (!response.ok) throw new Error('Failed to fetch event stats')
    return response.json()
}

export async function searchEvents(query, options = {}) {
    const response = await fetch(`${API_BASE}/search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, ...options }),
    })
    if (!response.ok) throw new Error('Search failed')
    return response.json()
}

export async function acknowledgeAlert(alertId, acknowledgedBy) {
    const response = await fetch(`${API_BASE}/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ acknowledged_by: acknowledgedBy }),
    })
    if (!response.ok) throw new Error('Failed to acknowledge alert')
    return response.json()
}

export async function fetchSystemStatus() {
    const response = await fetch(`${API_BASE}/system/status`)
    if (!response.ok) throw new Error('Failed to fetch status')
    return response.json()
}

export async function fetchIntegrityReport() {
    const response = await fetch(`${API_BASE}/integrity/report`)
    if (!response.ok) throw new Error('Failed to fetch integrity report')
    return response.json()
}

export async function fetchMitreMatrix() {
    const response = await fetch(`${API_BASE}/system/mitre/matrix`)
    if (!response.ok) throw new Error('Failed to fetch MITRE matrix')
    return response.json()
}

export async function exportData(format, params = {}) {
    const query = new URLSearchParams({ format, ...params }).toString()
    const response = await fetch(`${API_BASE}/reports/export?${query}`)
    if (!response.ok) throw new Error('Export failed')
    return response.blob()
}
