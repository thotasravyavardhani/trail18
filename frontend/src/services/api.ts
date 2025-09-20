import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Email API functions
export const emailAPI = {
  getInbox: () => api.get('/emails/inbox'),
  getSent: () => api.get('/emails/sent'),
  getOutbox: () => api.get('/emails/outbox'),
  
  composeEmail: (emailData: FormData) => api.post('/emails/compose', emailData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  
  retryOutbox: () => api.post('/emails/retry-outbox'),
};

// Settings API functions
export const settingsAPI = {
  getSettings: () => api.get('/settings'),
  updateSettings: (settings: FormData) => api.post('/settings', settings, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
};

// Authentication API functions
export const authAPI = {
  localLogin: (email: string, password: string) => {
    const formData = new URLSearchParams();
    formData.append('email', email);
    formData.append('password', password);
    return api.post('/auth/local/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
  },
  
  localRegister: (email: string, password: string) => {
    const formData = new URLSearchParams();
    formData.append('email', email);
    formData.append('password', password);
    return api.post('/auth/local/register', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
  },
  
  googleLogin: () => api.get('/auth/google/login'),
  
  googleCallback: (code: string, state: string) => {
    const formData = new URLSearchParams();
    formData.append('code', code);
    formData.append('state', state);
    return api.post('/auth/google/callback', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
  }
};

// Health check
export const healthAPI = {
  check: () => api.get('/health'),
};