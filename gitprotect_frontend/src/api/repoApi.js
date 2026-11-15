import axiosClient from './axiosClient';

export const repoApi = {
  getRepos: (params = {}) => axiosClient.get('/repos', { params }),
  connectRepo: (payload) => axiosClient.post('/repos/connect', payload),
};
