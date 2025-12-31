/**
 * IsoLog Global Store
 * 
 * Simple context-based state management
 */

import React, { createContext, useContext, useReducer, useCallback } from 'react';

// Initial state
const initialState = {
    // UI state
    sidebarCollapsed: false,
    theme: 'dark',

    // Filters
    eventFilters: {
        timeRange: '24h',
        severity: null,
        search: '',
    },
    alertFilters: {
        severity: null,
        status: 'all',
        search: '',
    },

    // Selected items
    selectedEvent: null,
    selectedAlert: null,

    // Notifications
    notifications: [],

    // System status
    systemStatus: null,
};

// Action types
const actions = {
    SET_SIDEBAR_COLLAPSED: 'SET_SIDEBAR_COLLAPSED',
    SET_THEME: 'SET_THEME',
    SET_EVENT_FILTERS: 'SET_EVENT_FILTERS',
    SET_ALERT_FILTERS: 'SET_ALERT_FILTERS',
    SET_SELECTED_EVENT: 'SET_SELECTED_EVENT',
    SET_SELECTED_ALERT: 'SET_SELECTED_ALERT',
    ADD_NOTIFICATION: 'ADD_NOTIFICATION',
    REMOVE_NOTIFICATION: 'REMOVE_NOTIFICATION',
    SET_SYSTEM_STATUS: 'SET_SYSTEM_STATUS',
    RESET: 'RESET',
};

// Reducer
function reducer(state, action) {
    switch (action.type) {
        case actions.SET_SIDEBAR_COLLAPSED:
            return { ...state, sidebarCollapsed: action.payload };

        case actions.SET_THEME:
            return { ...state, theme: action.payload };

        case actions.SET_EVENT_FILTERS:
            return { ...state, eventFilters: { ...state.eventFilters, ...action.payload } };

        case actions.SET_ALERT_FILTERS:
            return { ...state, alertFilters: { ...state.alertFilters, ...action.payload } };

        case actions.SET_SELECTED_EVENT:
            return { ...state, selectedEvent: action.payload };

        case actions.SET_SELECTED_ALERT:
            return { ...state, selectedAlert: action.payload };

        case actions.ADD_NOTIFICATION:
            return {
                ...state,
                notifications: [...state.notifications, { id: Date.now(), ...action.payload }],
            };

        case actions.REMOVE_NOTIFICATION:
            return {
                ...state,
                notifications: state.notifications.filter(n => n.id !== action.payload),
            };

        case actions.SET_SYSTEM_STATUS:
            return { ...state, systemStatus: action.payload };

        case actions.RESET:
            return initialState;

        default:
            return state;
    }
}

// Context
const StoreContext = createContext(null);

// Provider component
export function StoreProvider({ children }) {
    const [state, dispatch] = useReducer(reducer, initialState);

    // Action creators
    const store = {
        state,
        dispatch,

        // UI actions
        toggleSidebar: useCallback(() => {
            dispatch({ type: actions.SET_SIDEBAR_COLLAPSED, payload: !state.sidebarCollapsed });
        }, [state.sidebarCollapsed]),

        setTheme: useCallback((theme) => {
            dispatch({ type: actions.SET_THEME, payload: theme });
        }, []),

        // Filter actions
        setEventFilters: useCallback((filters) => {
            dispatch({ type: actions.SET_EVENT_FILTERS, payload: filters });
        }, []),

        setAlertFilters: useCallback((filters) => {
            dispatch({ type: actions.SET_ALERT_FILTERS, payload: filters });
        }, []),

        // Selection actions
        selectEvent: useCallback((event) => {
            dispatch({ type: actions.SET_SELECTED_EVENT, payload: event });
        }, []),

        selectAlert: useCallback((alert) => {
            dispatch({ type: actions.SET_SELECTED_ALERT, payload: alert });
        }, []),

        // Notification actions
        addNotification: useCallback((notification) => {
            dispatch({ type: actions.ADD_NOTIFICATION, payload: notification });
            // Auto-remove after 5 seconds
            setTimeout(() => {
                dispatch({ type: actions.REMOVE_NOTIFICATION, payload: notification.id || Date.now() });
            }, 5000);
        }, []),

        removeNotification: useCallback((id) => {
            dispatch({ type: actions.REMOVE_NOTIFICATION, payload: id });
        }, []),

        // System actions
        setSystemStatus: useCallback((status) => {
            dispatch({ type: actions.SET_SYSTEM_STATUS, payload: status });
        }, []),
    };

    return (
        <StoreContext.Provider value={store}>
            {children}
        </StoreContext.Provider>
    );
}

// Hook for using store
export function useStore() {
    const context = useContext(StoreContext);
    if (!context) {
        throw new Error('useStore must be used within a StoreProvider');
    }
    return context;
}

// Selector hooks
export function useEventFilters() {
    const { state, setEventFilters } = useStore();
    return [state.eventFilters, setEventFilters];
}

export function useAlertFilters() {
    const { state, setAlertFilters } = useStore();
    return [state.alertFilters, setAlertFilters];
}

export function useNotifications() {
    const { state, addNotification, removeNotification } = useStore();
    return {
        notifications: state.notifications,
        addNotification,
        removeNotification,
    };
}
