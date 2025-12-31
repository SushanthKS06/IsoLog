import { Outlet, NavLink } from 'react-router-dom'
import {
    LayoutDashboard,
    FileText,
    AlertTriangle,
    Grid3X3,
    Settings,
    Shield,
    Activity
} from 'lucide-react'

const navItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/events', icon: FileText, label: 'Events' },
    { path: '/alerts', icon: AlertTriangle, label: 'Alerts' },
    { path: '/mitre', icon: Grid3X3, label: 'MITRE ATT&CK' },
    { path: '/settings', icon: Settings, label: 'Settings' },
]

export default function Layout() {
    return (
        <div className="app-container">
            <aside className="sidebar">
                <div className="logo">
                    <div className="logo-icon">
                        <Shield size={24} />
                    </div>
                    <span className="logo-text">IsoLog</span>
                </div>

                <nav className="nav-menu">
                    {navItems.map(({ path, icon: Icon, label }) => (
                        <NavLink
                            key={path}
                            to={path}
                            className={({ isActive }) =>
                                `nav-item ${isActive ? 'active' : ''}`
                            }
                            end={path === '/'}
                        >
                            <Icon size={20} />
                            <span>{label}</span>
                        </NavLink>
                    ))}
                </nav>

                <div style={{
                    padding: '16px',
                    borderTop: '1px solid var(--border-color)',
                    fontSize: '12px',
                    color: 'var(--text-muted)'
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Activity size={14} style={{ color: 'var(--success)' }} />
                        <span>System Online</span>
                    </div>
                    <div style={{ marginTop: '4px', opacity: 0.7 }}>
                        v0.1.0 • Offline Mode
                    </div>
                </div>
            </aside>

            <main className="main-content">
                <Outlet />
            </main>
        </div>
    )
}
