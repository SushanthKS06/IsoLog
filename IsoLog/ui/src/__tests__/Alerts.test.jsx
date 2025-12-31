/**
 * Alerts Page Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import Alerts from '../pages/Alerts';

// Mock API
vi.mock('../services/api', () => ({
    api: {
        getAlerts: vi.fn().mockResolvedValue({
            alerts: [
                {
                    id: '1',
                    rule_name: 'Brute Force Attack',
                    severity: 'critical',
                    status: 'new',
                    threat_score: 85,
                    created_at: new Date().toISOString(),
                    mitre_techniques: ['T1110'],
                },
                {
                    id: '2',
                    rule_name: 'Suspicious Process',
                    severity: 'high',
                    status: 'acknowledged',
                    threat_score: 65,
                    created_at: new Date().toISOString(),
                    mitre_techniques: ['T1059'],
                },
            ],
            total: 2,
        }),
        getAlertCounts: vi.fn().mockResolvedValue({
            critical: 1,
            high: 1,
            medium: 0,
            low: 0,
        }),
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

describe('Alerts Page', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('renders alerts page', async () => {
        render(<Alerts />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByText(/Alerts/i)).toBeInTheDocument();
        });
    });

    it('displays severity badges', async () => {
        render(<Alerts />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByText(/critical/i)).toBeInTheDocument();
        });
    });

    it('shows alert rule names', async () => {
        render(<Alerts />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByText(/Brute Force Attack/i)).toBeInTheDocument();
        });
    });
});
