import { useQuery } from '@tanstack/react-query'
import {
    Settings as SettingsIcon,
    Database,
    Shield,
    Activity,
    RefreshCw,
    CheckCircle,
    AlertCircle,
    HardDrive
} from 'lucide-react'
import { fetchSystemStatus, fetchIntegrityReport } from '../services/api'

export default function Settings() {
    const { data: status, isLoading: statusLoading } = useQuery({
        queryKey: ['system-status'],
        queryFn: fetchSystemStatus,
    })

    const { data: integrity, isLoading: integrityLoading, refetch: refetchIntegrity } = useQuery({
        queryKey: ['integrity-report'],
        queryFn: fetchIntegrityReport,
    })

    const StatusIcon = ({ healthy }) => healthy ?
        <CheckCircle size={16} style={{ color: 'var(--success)' }} /> :
        <AlertCircle size={16} style={{ color: 'var(--error)' }} />

    return (
        <div className="fade-in">
            <div style={{ marginBottom: '24px' }}>
                <h1 style={{ fontSize: '28px', fontWeight: '700', marginBottom: '8px' }}>
                    System Settings
                </h1>
                <p style={{ color: 'var(--text-muted)' }}>
                    Configuration and system status
                </p>
            </div>

            <div className="data-grid">
                {/* System Status */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">System Status</span>
                        <Activity size={16} style={{ color: 'var(--success)' }} />
                    </div>

                    {statusLoading ? (
                        <div className="loading" style={{ padding: '40px', textAlign: 'center' }}>
                            Loading status...
                        </div>
                    ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '12px',
                                background: 'var(--bg-tertiary)',
                                borderRadius: '8px',
                            }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <Database size={18} style={{ color: 'var(--text-muted)' }} />
                                    <span>Database</span>
                                </div>
                                <StatusIcon healthy={status?.components?.database === 'healthy'} />
                            </div>

                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '12px',
                                background: 'var(--bg-tertiary)',
                                borderRadius: '8px',
                            }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <Shield size={18} style={{ color: 'var(--text-muted)' }} />
                                    <span>Detection Engine</span>
                                </div>
                                <StatusIcon healthy={status?.components?.detection_engine?.status === 'healthy'} />
                            </div>

                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '12px',
                                background: 'var(--bg-tertiary)',
                                borderRadius: '8px',
                            }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <HardDrive size={18} style={{ color: 'var(--text-muted)' }} />
                                    <span>Blockchain</span>
                                </div>
                                <StatusIcon healthy={status?.components?.blockchain?.status !== 'disabled'} />
                            </div>

                            <div style={{ marginTop: '8px', padding: '12px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Version</span>
                                    <span>{status?.version || 'Unknown'}</span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Sigma Rules</span>
                                    <span>{status?.components?.detection_engine?.sigma_rule_count || 0}</span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Blockchain Integrity */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Blockchain Integrity</span>
                        <button
                            className="btn btn-secondary"
                            style={{ padding: '6px 12px', fontSize: '12px' }}
                            onClick={() => refetchIntegrity()}
                        >
                            <RefreshCw size={14} />
                            Verify
                        </button>
                    </div>

                    {integrityLoading ? (
                        <div className="loading" style={{ padding: '40px', textAlign: 'center' }}>
                            Verifying chain...
                        </div>
                    ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            <div style={{
                                padding: '20px',
                                background: integrity?.chain_valid ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                                borderRadius: '8px',
                                textAlign: 'center',
                                border: `1px solid ${integrity?.chain_valid ? 'var(--success)' : 'var(--error)'}`,
                            }}>
                                {integrity?.chain_valid ? (
                                    <>
                                        <CheckCircle size={32} style={{ color: 'var(--success)', marginBottom: '8px' }} />
                                        <div style={{ fontWeight: '600', color: 'var(--success)' }}>Chain Verified</div>
                                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                                            All {integrity?.blocks_verified || 0} blocks validated
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        <AlertCircle size={32} style={{ color: 'var(--error)', marginBottom: '8px' }} />
                                        <div style={{ fontWeight: '600', color: 'var(--error)' }}>Integrity Issue</div>
                                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                                            {integrity?.errors?.length || 0} errors detected
                                        </div>
                                    </>
                                )}
                            </div>

                            <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Status</span>
                                    <span>{integrity?.status || 'Unknown'}</span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Blocks</span>
                                    <span>{integrity?.statistics?.total_blocks || 0}</span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Last Check</span>
                                    <span style={{ fontSize: '12px' }}>{integrity?.timestamp?.slice(0, 19) || '-'}</span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Configuration Info */}
            <div className="card" style={{ marginTop: '24px' }}>
                <div className="card-header">
                    <span className="card-title">Configuration</span>
                    <SettingsIcon size={16} style={{ color: 'var(--text-muted)' }} />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
                    <div style={{ padding: '16px', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>Detection</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '13px' }}>
                            <div>Sigma: <span style={{ color: 'var(--success)' }}>Enabled</span></div>
                            <div>MITRE: <span style={{ color: 'var(--success)' }}>Enabled</span></div>
                            <div>ML Anomaly: <span style={{ color: 'var(--success)' }}>Enabled</span></div>
                        </div>
                    </div>
                    <div style={{ padding: '16px', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>Ingestion</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '13px' }}>
                            <div>File Watcher: <span style={{ color: 'var(--success)' }}>Enabled</span></div>
                            <div>Syslog: <span style={{ color: 'var(--warning)' }}>Pending</span></div>
                            <div>USB Import: <span style={{ color: 'var(--warning)' }}>Pending</span></div>
                        </div>
                    </div>
                    <div style={{ padding: '16px', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>Storage</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '13px' }}>
                            <div>Database: SQLite</div>
                            <div>Blockchain: <span style={{ color: 'var(--success)' }}>Enabled</span></div>
                            <div>Retention: 90 days</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
