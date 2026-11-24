import axiosClient from './axiosClient';

export const dashboardApi = {
  getMetrics: (params = {}) => axiosClient.get('/dashboard/metrics', { params }),
  getRepoBreakdown: () => axiosClient.get('/dashboard/repo-breakdown'),
  getTrend: (params = {}) => axiosClient.get('/dashboard/trend', { params }),
  exportReport: (format = 'csv') =>
    axiosClient.get('/dashboard/export', {
      params: { format },
      responseType: format === 'pdf' ? 'blob' : 'text',
    }),
};
