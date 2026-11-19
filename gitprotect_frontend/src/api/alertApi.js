import axiosClient from './axiosClient';

export const alertApi = {
  getAlerts: (params = {}) => axiosClient.get('/alerts', { params }),
  getAlertDetail: (id) => axiosClient.get(`/alerts/${id}`),
  updateAlertStatus: (id, payload) => axiosClient.patch(`/alerts/${id}/status`, payload),
  getAlertHistory: (id) => axiosClient.get(`/alerts/${id}/history`),
};

