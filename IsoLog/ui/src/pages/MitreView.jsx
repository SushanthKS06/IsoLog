import { useQuery } from '@tanstack/react-query'
import { fetchMitreStats, fetchMitreMatrix } from '../services/api'

const TACTICS = [
    'Reconnaissance',
    'Resource Dev',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Esc',
    'Defense Eva',
    'Cred Access',
    'Discovery',
    'Lateral Move',
    'Collection',
    'C2',
    'Exfiltration',
    'Impact',
]

const SAMPLE_TECHNIQUES = {
    'Execution': ['T1059', 'T1059.001', 'T1053'],
    'Persistence': ['T1547', 'T1547.001', 'T1136'],
    'Privilege Esc': ['T1548', 'T1055'],
    'Cred Access': ['T1110', 'T1003'],
    'Discovery': ['T1046', 'T1087'],
    'Lateral Move': ['T1021', 'T1021.001'],
    'Defense Eva': ['T1070', 'T1070.001'],
    'Impact': ['T1486'],
}

export default function MitreView() {
    const { data: stats } = useQuery({
        queryKey: ['mitre-stats'],
        queryFn: fetchMitreStats,
    })

    const { data: matrix } = useQuery({
        queryKey: ['mitre-matrix'],
        queryFn: fetchMitreMatrix,
    })

    const getTechniqueLevel = (techId) => {
        const count = stats?.techniques?.[techId] || 0
        if (count >= 10) return 4
        if (count >= 5) return 3
        if (count >= 2) return 2
        if (count >= 1) return 1
        return 0
    }

    return (
        <div className="fade-in">
            <div style={{ marginBottom: '24px' }}>
                <h1 style={{ fontSize: '28px', fontWeight: '700', marginBottom: '8px' }}>
                    MITRE ATT&CK Coverage
                </h1>
                <p style={{ color: 'var(--text-muted)' }}>
                    Threat detection mapped to ATT&CK framework
                </p>
            </div>

            {/* Legend */}
            <div className="card" style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', gap: '24px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '14px' }}>Alert Density:</span>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <div style={{ width: '20px', height: '20px', background: 'var(--bg-tertiary)', borderRadius: '4px' }}></div>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>None</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <div style={{ width: '20px', height: '20px', background: 'rgba(34, 197, 94, 0.3)', borderRadius: '4px' }}></div>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Low (1-2)</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <div style={{ width: '20px', height: '20px', background: 'rgba(234, 179, 8, 0.4)', borderRadius: '4px' }}></div>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Medium (3-5)</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <div style={{ width: '20px', height: '20px', background: 'rgba(249, 115, 22, 0.5)', borderRadius: '4px' }}></div>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>High (6-10)</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <div style={{ width: '20px', height: '20px', background: 'rgba(220, 38, 38, 0.6)', borderRadius: '4px' }}></div>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Critical (10+)</span>
                    </div>
                </div>
            </div>

            {/* Matrix */}
            <div className="card" style={{ overflowX: 'auto' }}>
                <div style={{ minWidth: '1000px' }}>
                    {/* Tactic Headers */}
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(14, 1fr)',
                        gap: '4px',
                        marginBottom: '12px'
                    }}>
                        {TACTICS.map((tactic) => (
                            <div
                                key={tactic}
                                style={{
                                    background: 'var(--accent-gradient)',
                                    padding: '8px 4px',
                                    borderRadius: '6px',
                                    fontSize: '10px',
                                    fontWeight: '600',
                                    textAlign: 'center',
                                    color: 'white',
                                }}
                            >
                                {tactic}
                            </div>
                        ))}
                    </div>

                    {/* Technique Grid */}
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(14, 1fr)',
                        gap: '4px'
                    }}>
                        {TACTICS.map((tactic) => (
                            <div key={tactic} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                {(SAMPLE_TECHNIQUES[tactic] || ['T0000']).map((tech, idx) => {
                                    const level = getTechniqueLevel(tech)
                                    return (
                                        <div
                                            key={`${tactic}-${idx}`}
                                            className={`mitre-cell ${level > 0 ? `level-${level}` : ''}`}
                                            title={`${tech}: ${stats?.techniques?.[tech] || 0} alerts`}
                                            style={{
                                                height: '40px',
                                                fontSize: '9px',
                                                fontWeight: level > 0 ? '600' : '400',
                                                color: level > 0 ? 'white' : 'var(--text-muted)',
                                            }}
                                        >
                                            {tech}
                                        </div>
                                    )
                                })}
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Summary Stats */}
            <div className="data-grid" style={{ marginTop: '24px' }}>
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Top Techniques Detected</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {Object.entries(stats?.techniques || {})
                            .sort((a, b) => b[1] - a[1])
                            .slice(0, 10)
                            .map(([tech, count]) => (
                                <div
                                    key={tech}
                                    style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        padding: '8px 12px',
                                        background: 'var(--bg-tertiary)',
                                        borderRadius: '6px',
                                    }}
                                >
                                    <span style={{ fontFamily: 'monospace', color: 'var(--accent-primary)' }}>{tech}</span>
                                    <span style={{ fontWeight: '600' }}>{count}</span>
                                </div>
                            ))}
                        {Object.keys(stats?.techniques || {}).length === 0 && (
                            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                                No technique detections yet
                            </p>
                        )}
                    </div>
                </div>

                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Top Tactics</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {Object.entries(stats?.tactics || {})
                            .sort((a, b) => b[1] - a[1])
                            .slice(0, 8)
                            .map(([tactic, count]) => (
                                <div
                                    key={tactic}
                                    style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        padding: '8px 12px',
                                        background: 'var(--bg-tertiary)',
                                        borderRadius: '6px',
                                    }}
                                >
                                    <span style={{ textTransform: 'capitalize' }}>{tactic.replace(/-/g, ' ')}</span>
                                    <span style={{ fontWeight: '600' }}>{count}</span>
                                </div>
                            ))}
                        {Object.keys(stats?.tactics || {}).length === 0 && (
                            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                                No tactic detections yet
                            </p>
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}
