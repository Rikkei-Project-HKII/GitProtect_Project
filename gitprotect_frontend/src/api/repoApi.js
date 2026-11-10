import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const apiClient = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

export const repoApi = {
    // GET /api/v1/repos
    getRepos: async () => {
        const response = await apiClient.get('/repos');
        return response.data;
    },

    // POST /api/v1/repos/connect
    connectRepo: async (repoUrl, githubPat) => {
        const response = await apiClient.post('/repos/connect', {
            repo_url: repoUrl,
            github_pat: githubPat,
        });
        return response.data;
    },
};