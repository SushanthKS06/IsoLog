/**
 * Dashboard Component Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import Dashboard from '../pages/Dashboard';

// Mock API
vi.mock('../services/api', () => ({
    api: {
        getDashboardStats: vi.fn().mockResolvedValue({
            total_alerts: 150,
            critical_alerts: 10,
            high_alerts: 25,
            events_today: 5000,
        }),
        getRecentAlerts: vi.fn().mockResolvedValue([
            { id: '1', rule_name: 'Test Alert', severity: 'high', created_at: new Date().toISOString() },
        ]),
        getAlertTimeline: vi.fn().mockResolvedValue([
            { hour: 0, count: 5 },
            { hour: 1, count: 3 },
        ]),
    },
}));

const createWrapper = () => {
    const queryClient = new QueryClient({
        defaultOptions: {
            queries: { retry: false },
        },
    });

    return ({ children }) => (
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>
                {children}
            </BrowserRouter>
        </QueryClientProvider>
    );
};

describe('Dashboard', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('renders dashboard title', async () => {
        render(<Dashboard />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByText(/Dashboard/i)).toBeInTheDocument();
        });
    });

    it('displays statistics cards', async () => {
        render(<Dashboard />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByText(/Total Alerts/i)).toBeInTheDocument();
        });
    });

    it('shows loading state initially', () => {
        render(<Dashboard />, { wrapper: createWrapper() });

        // Should show loading or skeleton initially
        expect(document.querySelector('.card, .loading')).toBeInTheDocument();
    });
});
