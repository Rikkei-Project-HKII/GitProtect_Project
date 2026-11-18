import axios from 'axios';
import { extractApiError } from '../utils/formatters';

const axiosClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

axiosClient.interceptors.response.use(
  (response) => response.data,
  (error) => Promise.reject(new Error(extractApiError(error)))
);

export default axiosClient;
