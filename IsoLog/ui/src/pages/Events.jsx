import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Filter, Download, RefreshCw } from 'lucide-react'
import { fetchEvents } from '../services/api'
import { format } from 'date-fns'

export default function Events() {
    const [page, setPage] = useState(1)
    const [searchQuery, setSearchQuery] = useState('')
    const [filters, setFilters] = useState({})

    const { data, isLoading, refetch } = useQuery({
        queryKey: ['events', page, filters],
        queryFn: () => fetchEvents({ page, page_size: 50, ...filters }),
    })

    const formatTime = (timestamp) => {
        try {
            return format(new Date(timestamp), 'yyyy-MM-dd HH:mm:ss')
        } catch {
            return timestamp
        }
    }

    const handleExport = () => {
        // Export functionality
        const csv = data?.events?.map(e =>
            `${e.timestamp},${e.host?.name || ''},${e.user?.name || ''},${e.event?.action || ''},${e.message || ''}`
        ).join('\n')

        const blob = new Blob([`timestamp,host,user,action,message\n${csv}`], { type: 'text/csv' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `events_export_${format(new Date(), 'yyyyMMdd_HHmmss')}.csv`
        a.click()
    }

    return (
        <div className="fade-in">
            <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1 style={{ fontSize: '28px', fontWeight: '700', marginBottom: '8px' }}>
                        Event Stream
                    </h1>
                    <p style={{ color: 'var(--text-muted)' }}>
                        {data?.total?.toLocaleString() || 0} total events
                    </p>
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                    <button className="btn btn-secondary" onClick={() => refetch()}>
                        <RefreshCw size={16} />
                        Refresh
                    </button>
                    <button className="btn btn-primary" onClick={handleExport}>
                        <Download size={16} />
                        Export CSV
                    </button>
                </div>
            </div>

            {/* Filters */}
            <div className="filters">
                <div className="search-box" style={{ flex: 1 }}>
                    <Search size={18} style={{ color: 'var(--text-muted)' }} />
                    <input
                        type="text"
                        placeholder="Search events by message, host, user..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>
                <select className="filter-select" onChange={(e) => setFilters({ ...filters, event_action: e.target.value || undefined })}>
                    <option value="">All Actions</option>
                    <option value="ssh_login">SSH Login</option>
                    <option value="file_access">File Access</option>
                    <option value="process_start">Process Start</option>
                    <option value="connection">Network Connection</option>
                </select>
                <select className="filter-select">
                    <option value="1h">Last 1 hour</option>
                    <option value="24h" selected>Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                </select>
            </div>

            {/* Events Table */}
            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Host</th>
                                <th>User</th>
                                <th>Action</th>
                                <th>Source IP</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {isLoading ? (
                                <tr>
                                    <td colSpan={6} style={{ textAlign: 'center', padding: '60px' }}>
                                        <div className="loading">Loading events...</div>
                                    </td>
                                </tr>
                            ) : data?.events?.length > 0 ? (
                                data.events.map((event) => (
                                    <tr key={event.id}>
                                        <td style={{ whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: '12px' }}>
                                            {formatTime(event.timestamp)}
                                        </td>
                                        <td style={{ color: 'var(--accent-primary)' }}>
                                            {event.host?.name || '-'}
                                        </td>
                                        <td>{event.user?.name || '-'}</td>
                                        <td>
                                            <span style={{
                                                padding: '2px 8px',
                                                background: 'var(--bg-tertiary)',
                                                borderRadius: '4px',
                                                fontSize: '12px'
                                            }}>
                                                {event.event?.action || '-'}
                                            </span>
                                        </td>
                                        <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                                            {event.source?.ip || '-'}
                                        </td>
                                        <td style={{
                                            maxWidth: '300px',
                                            overflow: 'hidden',
                                            textOverflow: 'ellipsis',
                                            whiteSpace: 'nowrap'
                                        }}>
                                            {event.message || '-'}
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan={6} style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
                                        No events found. Start collecting logs to see events here.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>

                {/* Pagination */}
                {data?.total > 50 && (
                    <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '16px 0',
                        borderTop: '1px solid var(--border-color)',
                        marginTop: '16px'
                    }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
                            Page {page} of {Math.ceil(data.total / 50)}
                        </span>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <button
                                className="btn btn-secondary"
                                onClick={() => setPage(p => Math.max(1, p - 1))}
                                disabled={page === 1}
                                style={{ padding: '8px 16px' }}
                            >
                                Previous
                            </button>
                            <button
                                className="btn btn-secondary"
                                onClick={() => setPage(p => p + 1)}
                                disabled={page * 50 >= data.total}
                                style={{ padding: '8px 16px' }}
                            >
                                Next
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}
