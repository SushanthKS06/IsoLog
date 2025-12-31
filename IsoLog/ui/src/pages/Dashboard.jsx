import { useQuery } from '@tanstack/react-query'
import {
    AlertTriangle,
    Shield,
    Activity,
    TrendingUp,
    TrendingDown,
    Clock,
    Monitor
} from 'lucide-react'
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer
} from 'recharts'
import { fetchDashboardStats, fetchRecentAlerts, fetchAlertTimeline } from '../services/api'
import { format } from 'date-fns'

export default function Dashboard() {
    const { data: stats, isLoading: statsLoading } = useQuery({
        queryKey: ['dashboard-stats'],
        queryFn: fetchDashboardStats,
    })

    const { data: recentAlerts, isLoading: alertsLoading } = useQuery({
        queryKey: ['recent-alerts'],
        queryFn: () => fetchRecentAlerts(8),
    })

    const { data: timeline } = useQuery({
        queryKey: ['alert-timeline'],
        queryFn: () => fetchAlertTimeline(24),
    })

    const statCards = [
        {
            label: 'Total Alerts',
            value: stats?.total_alerts || 0,
            icon: AlertTriangle,
            className: '',
            change: stats?.alerts_today || 0,
            changeLabel: 'today',
        },
        {
            label: 'Critical',
            value: stats?.critical_alerts || 0,
            icon: Shield,
            className: 'critical',
            change: null,
        },
        {
            label: 'High',
            value: stats?.high_alerts || 0,
            icon: Activity,
            className: 'high',
            change: null,
        },
        {
            label: 'Events Today',
            value: stats?.events_today || 0,
            icon: Monitor,
            className: 'success',
            change: stats?.total_events || 0,
            changeLabel: 'total',
        },
    ]

    const getSeverityClass = (severity) => {
        const map = {
            critical: 'critical',
            high: 'high',
            medium: 'medium',
            low: 'low',
            informational: 'info',
        }
        return map[severity] || 'info'
    }

    const formatTime = (timestamp) => {
        try {
            return format(new Date(timestamp), 'HH:mm:ss')
        } catch {
            return timestamp
        }
    }

    return (
        <div className="fade-in">
            <div style={{ marginBottom: '24px' }}>
                <h1 style={{ fontSize: '28px', fontWeight: '700', marginBottom: '8px' }}>
                    Security Dashboard
                </h1>
                <p style={{ color: 'var(--text-muted)' }}>
                    Real-time threat monitoring and analysis
                </p>
            </div>

            {/* Stats Grid */}
            <div className="stats-grid">
                {statCards.map(({ label, value, icon: Icon, className, change, changeLabel }) => (
                    <div key={label} className={`stat-card ${className}`}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                            <div>
                                <div className="stat-label">{label}</div>
                                <div className="stat-value">
                                    {statsLoading ? '...' : value.toLocaleString()}
                                </div>
                                {change !== null && (
                                    <div className="stat-change positive">
                                        <TrendingUp size={14} />
                                        {change.toLocaleString()} {changeLabel}
                                    </div>
                                )}
                            </div>
                            <Icon size={24} style={{ color: 'var(--text-muted)', opacity: 0.5 }} />
                        </div>
                    </div>
                ))}
            </div>

            {/* Charts Row */}
            <div className="data-grid">
                {/* Timeline Chart */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Alert Timeline (24h)</span>
                        <Clock size={16} style={{ color: 'var(--text-muted)' }} />
                    </div>
                    <div className="timeline-chart">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={timeline?.timeline || []}>
                                <defs>
                                    <linearGradient id="criticalGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <XAxis
                                    dataKey="timestamp"
                                    tickFormatter={(t) => format(new Date(t), 'HH:mm')}
                                    stroke="var(--text-muted)"
                                    fontSize={11}
                                />
                                <YAxis stroke="var(--text-muted)" fontSize={11} />
                                <Tooltip
                                    contentStyle={{
                                        background: 'var(--bg-card)',
                                        border: '1px solid var(--border-color)',
                                        borderRadius: '8px',
                                    }}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="critical"
                                    stroke="#dc2626"
                                    fill="url(#criticalGrad)"
                                    stackId="1"
                                />
                                <Area
                                    type="monotone"
                                    dataKey="high"
                                    stroke="#f97316"
                                    fill="url(#highGrad)"
                                    stackId="1"
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Quick Stats */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Detection Summary</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        {[
                            { label: 'Sigma Rules', value: 'Active', color: 'var(--success)' },
                            { label: 'ML Detection', value: 'Learning', color: 'var(--warning)' },
                            { label: 'Blockchain', value: 'Verified', color: 'var(--success)' },
                            { label: 'Last Update', value: 'Today', color: 'var(--info)' },
                        ].map(({ label, value, color }) => (
                            <div key={label} style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                padding: '12px',
                                background: 'var(--bg-tertiary)',
                                borderRadius: '8px',
                            }}>
                                <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                                <span style={{ color, fontWeight: '600' }}>{value}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Recent Alerts */}
            <div className="card">
                <div className="card-header">
                    <span className="card-title">Recent Alerts</span>
                    <button className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '12px' }}>
                        View All
                    </button>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Rule</th>
                                <th>Host</th>
                                <th>Time</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {alertsLoading ? (
                                <tr>
                                    <td colSpan={5} style={{ textAlign: 'center', padding: '40px' }}>
                                        <div className="loading">Loading alerts...</div>
                                    </td>
                                </tr>
                            ) : recentAlerts?.alerts?.length > 0 ? (
                                recentAlerts.alerts.map((alert) => (
                                    <tr key={alert.id}>
                                        <td>
                                            <span className={`badge ${getSeverityClass(alert.severity)}`}>
                                                {alert.severity}
                                            </span>
                                        </td>
                                        <td style={{ color: 'var(--text-primary)' }}>{alert.rule_name}</td>
                                        <td>{alert.event_summary?.host || '-'}</td>
                                        <td>{formatTime(alert.created_at)}</td>
                                        <td style={{ color: alert.status === 'new' ? 'var(--warning)' : 'var(--text-muted)' }}>
                                            {alert.status}
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan={5} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                                        No alerts detected. System is monitoring.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}
