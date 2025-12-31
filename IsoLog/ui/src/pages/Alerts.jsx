import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, X, Eye, Download } from 'lucide-react'
import { fetchAlerts, fetchAlertCounts, acknowledgeAlert } from '../services/api'
import { format } from 'date-fns'

export default function Alerts() {
    const [page, setPage] = useState(1)
    const [severityFilter, setSeverityFilter] = useState('')
    const [statusFilter, setStatusFilter] = useState('')
    const [selectedAlert, setSelectedAlert] = useState(null)

    const queryClient = useQueryClient()

    const { data: counts } = useQuery({
        queryKey: ['alert-counts'],
        queryFn: fetchAlertCounts,
    })

    const { data, isLoading, refetch } = useQuery({
        queryKey: ['alerts', page, severityFilter, statusFilter],
        queryFn: () => fetchAlerts({
            page,
            page_size: 50,
            severity: severityFilter || undefined,
            status: statusFilter || undefined,
        }),
    })

    const acknowledgeMutation = useMutation({
        mutationFn: ({ alertId }) => acknowledgeAlert(alertId, 'analyst'),
        onSuccess: () => {
            queryClient.invalidateQueries(['alerts'])
            queryClient.invalidateQueries(['alert-counts'])
        },
    })

    const getSeverityClass = (severity) => {
        const map = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', informational: 'info' }
        return map[severity] || 'info'
    }

    const formatTime = (timestamp) => {
        try {
            return format(new Date(timestamp), 'yyyy-MM-dd HH:mm:ss')
        } catch {
            return timestamp
        }
    }

    const handleExport = (format) => {
        const alerts = data?.alerts || []
        if (format === 'json') {
            const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: 'application/json' })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `alerts_${new Date().toISOString().slice(0, 10)}.json`
            a.click()
        } else if (format === 'csv') {
            const csv = alerts.map(a =>
                `${a.created_at},${a.severity},${a.rule_name},${a.status}`
            ).join('\n')
            const blob = new Blob([`timestamp,severity,rule,status\n${csv}`], { type: 'text/csv' })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `alerts_${new Date().toISOString().slice(0, 10)}.csv`
            a.click()
        }
    }

    return (
        <div className="fade-in">
            <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1 style={{ fontSize: '28px', fontWeight: '700', marginBottom: '8px' }}>
                        Security Alerts
                    </h1>
                    <p style={{ color: 'var(--text-muted)' }}>
                        {data?.total?.toLocaleString() || 0} alerts detected
                    </p>
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                    <button className="btn btn-secondary" onClick={() => handleExport('csv')}>
                        <Download size={16} />
                        Export CSV
                    </button>
                    <button className="btn btn-primary" onClick={() => handleExport('json')}>
                        <Download size={16} />
                        Export JSON
                    </button>
                </div>
            </div>

            {/* Severity Summary */}
            <div className="stats-grid" style={{ marginBottom: '24px' }}>
                {['critical', 'high', 'medium', 'low'].map((severity) => (
                    <div
                        key={severity}
                        className={`stat-card ${severity}`}
                        style={{ cursor: 'pointer' }}
                        onClick={() => setSeverityFilter(severity === severityFilter ? '' : severity)}
                    >
                        <div className="stat-label">{severity}</div>
                        <div className="stat-value">{counts?.[severity] || 0}</div>
                    </div>
                ))}
            </div>

            {/* Filters */}
            <div className="filters">
                <select
                    className="filter-select"
                    value={severityFilter}
                    onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
                >
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <select
                    className="filter-select"
                    value={statusFilter}
                    onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
                >
                    <option value="">All Statuses</option>
                    <option value="new">New</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                </select>
            </div>

            {/* Alerts Table */}
            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Rule Name</th>
                                <th>Detection Type</th>
                                <th>MITRE</th>
                                <th>Score</th>
                                <th>Time</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {isLoading ? (
                                <tr>
                                    <td colSpan={8} style={{ textAlign: 'center', padding: '60px' }}>
                                        <div className="loading">Loading alerts...</div>
                                    </td>
                                </tr>
                            ) : data?.alerts?.length > 0 ? (
                                data.alerts.map((alert) => (
                                    <tr key={alert.id}>
                                        <td>
                                            <span className={`badge ${getSeverityClass(alert.severity)}`}>
                                                {alert.severity}
                                            </span>
                                        </td>
                                        <td style={{ color: 'var(--text-primary)', fontWeight: '500' }}>
                                            {alert.rule_name}
                                        </td>
                                        <td>
                                            <span style={{
                                                padding: '2px 8px',
                                                background: 'var(--bg-tertiary)',
                                                borderRadius: '4px',
                                                fontSize: '12px',
                                                textTransform: 'uppercase'
                                            }}>
                                                {alert.detection_type || 'sigma'}
                                            </span>
                                        </td>
                                        <td style={{ fontSize: '12px' }}>
                                            {alert.mitre_techniques?.slice(0, 2).join(', ') || '-'}
                                        </td>
                                        <td>
                                            <span style={{
                                                color: alert.threat_score >= 70 ? 'var(--critical)' :
                                                    alert.threat_score >= 50 ? 'var(--warning)' : 'var(--text-secondary)',
                                                fontWeight: '600'
                                            }}>
                                                {alert.threat_score?.toFixed(0) || '-'}
                                            </span>
                                        </td>
                                        <td style={{ whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: '12px' }}>
                                            {formatTime(alert.created_at)}
                                        </td>
                                        <td>
                                            <span style={{
                                                color: alert.status === 'new' ? 'var(--warning)' :
                                                    alert.status === 'resolved' ? 'var(--success)' : 'var(--text-muted)'
                                            }}>
                                                {alert.status}
                                            </span>
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', gap: '8px' }}>
                                                <button
                                                    onClick={() => setSelectedAlert(alert)}
                                                    style={{
                                                        background: 'none',
                                                        border: 'none',
                                                        cursor: 'pointer',
                                                        color: 'var(--text-muted)',
                                                        padding: '4px'
                                                    }}
                                                    title="View Details"
                                                >
                                                    <Eye size={16} />
                                                </button>
                                                {alert.status === 'new' && (
                                                    <button
                                                        onClick={() => acknowledgeMutation.mutate({ alertId: alert.id })}
                                                        style={{
                                                            background: 'none',
                                                            border: 'none',
                                                            cursor: 'pointer',
                                                            color: 'var(--success)',
                                                            padding: '4px'
                                                        }}
                                                        title="Acknowledge"
                                                    >
                                                        <Check size={16} />
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan={8} style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
                                        No alerts found. Adjust filters or check detection rules.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Alert Detail Modal */}
            {selectedAlert && (
                <div style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    background: 'rgba(0,0,0,0.7)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 1000,
                }} onClick={() => setSelectedAlert(null)}>
                    <div className="card" style={{ maxWidth: '600px', width: '90%' }} onClick={e => e.stopPropagation()}>
                        <div className="card-header">
                            <span className="card-title">{selectedAlert.rule_name}</span>
                            <button onClick={() => setSelectedAlert(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                                <X size={20} />
                            </button>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            <div>
                                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Description</span>
                                <p>{selectedAlert.rule_description || 'No description available'}</p>
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                                <div>
                                    <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Severity</span>
                                    <p><span className={`badge ${getSeverityClass(selectedAlert.severity)}`}>{selectedAlert.severity}</span></p>
                                </div>
                                <div>
                                    <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Threat Score</span>
                                    <p style={{ fontWeight: '600' }}>{selectedAlert.threat_score?.toFixed(1)}</p>
                                </div>
                            </div>
                            {selectedAlert.mitre_techniques?.length > 0 && (
                                <div>
                                    <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>MITRE ATT&CK</span>
                                    <p>{selectedAlert.mitre_techniques.join(', ')}</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}
