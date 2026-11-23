import axiosClient from './axiosClient';

export const getMetrics = () => axiosClient.get('/dashboard/metrics');

export const getRepoBreakdown = () => axiosClient.get('/dashboard/repo-breakdown');

export const getTrend = (granularity = 'day') =>
  axiosClient.get('/dashboard/trend', { params: { granularity } });

// Dùng lại API MOD-03
export const getAlerts = (params = {}) =>
  axiosClient.get('/alerts', {
    params: Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== '' && v != null)
    ),
  });

export const getAlert = (id) => axiosClient.get(`/alerts/${id}`);

export const getAlertHistory = (id) => axiosClient.get(`/alerts/${id}/history`);

export const updateAlertStatus = (id, payload) =>
  axiosClient.patch(`/alerts/${id}/status`, payload);
