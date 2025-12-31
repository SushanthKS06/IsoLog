/**
 * API Service Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';

// Mock fetch
global.fetch = vi.fn();

describe('API Service', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('getDashboardStats', () => {
        it('fetches dashboard stats', async () => {
            const mockData = { total_alerts: 100, events_today: 5000 };
            global.fetch.mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockData),
            });

            const result = await api.getDashboardStats();

            expect(fetch).toHaveBeenCalledWith('/api/dashboard/stats');
            expect(result).toEqual(mockData);
        });
    });

    describe('getEvents', () => {
        it('fetches events with filters', async () => {
            const mockData = { events: [], total: 0 };
            global.fetch.mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockData),
            });

            await api.getEvents({ page: 1, pageSize: 50 });

            expect(fetch).toHaveBeenCalled();
        });
    });

    describe('getAlerts', () => {
        it('fetches alerts', async () => {
            const mockData = { alerts: [], total: 0 };
            global.fetch.mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockData),
            });

            await api.getAlerts({});

            expect(fetch).toHaveBeenCalled();
        });
    });

    describe('search', () => {
        it('performs search', async () => {
            const mockData = { results: [] };
            global.fetch.mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve(mockData),
            });

            await api.search('test query');

            expect(fetch).toHaveBeenCalledWith('/api/search', expect.objectContaining({
                method: 'POST',
            }));
        });
    });

    describe('error handling', () => {
        it('handles fetch errors', async () => {
            global.fetch.mockRejectedValueOnce(new Error('Network error'));

            await expect(api.getDashboardStats()).rejects.toThrow();
        });
    });
});
