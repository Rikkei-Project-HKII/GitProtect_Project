import axios from 'axios';

const api = axios.create({ baseURL: '/api/v1' });

export const getMetrics = () => api.get('/dashboard/metrics').then((r) => r.data);
export const getRepoBreakdown = () => api.get('/dashboard/repo-breakdown').then((r) => r.data);
export const getTrend = (granularity = 'day') =>
  api.get('/dashboard/trend', { params: { granularity } }).then((r) => r.data);

// Dùng lại API MOD-03
export const getAlerts = (params) =>
  api.get('/alerts', { params: Object.fromEntries(Object.entries(params).filter(([, v]) => v !== '' && v != null)) })
    .then((r) => r.data);
export const getAlert = (id) => api.get(`/alerts/${id}`).then((r) => r.data);
export const getAlertHistory = (id) => api.get(`/alerts/${id}/history`).then((r) => r.data);