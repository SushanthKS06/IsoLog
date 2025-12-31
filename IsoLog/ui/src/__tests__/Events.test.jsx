/**
 * Events Page Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import Events from '../pages/Events';

// Mock API
vi.mock('../services/api', () => ({
    api: {
        getEvents: vi.fn().mockResolvedValue({
            events: [
                {
                    id: '1',
                    timestamp: new Date().toISOString(),
                    host: { name: 'server1' },
                    user: { name: 'admin' },
                    event: { action: 'login' },
                    message: 'User logged in',
                },
                {
                    id: '2',
                    timestamp: new Date().toISOString(),
                    host: { name: 'server2' },
                    user: { name: 'root' },
                    event: { action: 'sudo' },
                    message: 'Sudo command executed',
                },
            ],
            total: 2,
            page: 1,
            page_size: 50,
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

describe('Events Page', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('renders events page', async () => {
        render(<Events />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByText(/Events/i)).toBeInTheDocument();
        });
    });

    it('displays events in table', async () => {
        render(<Events />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByText(/server1/i)).toBeInTheDocument();
        });
    });

    it('has search input', async () => {
        render(<Events />, { wrapper: createWrapper() });

        await waitFor(() => {
            expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument();
        });
    });
});
