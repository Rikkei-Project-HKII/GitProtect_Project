import axiosClient from './axiosClient';

export const dashboardApi = {
  getMetrics: (params = {}) => axiosClient.get('/dashboard/metrics', { params }),
};
