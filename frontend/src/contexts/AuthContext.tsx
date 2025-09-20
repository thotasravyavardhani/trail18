import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api, authAPI } from '../services/api';

interface User {
  email: string;
  km_session_id: string;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  startOAuthLogin: () => Promise<{ authorization_url: string; state: string }>;
  completeOAuthLogin: (code: string, state: string) => Promise<void>;
  localLogin: (email: string, password: string) => Promise<void>;
  localRegister: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  loading: boolean;
}


const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already authenticated
    const token = localStorage.getItem('access_token');
    if (token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchCurrentUser();
    } else {
      setLoading(false);
    }
  }, []);

  const fetchCurrentUser = async () => {
    try {
      const response = await api.get('/auth/me');
      setUser(response.data);
    } catch (error) {
      // Token is invalid
      localStorage.removeItem('access_token');
      delete api.defaults.headers.common['Authorization'];
    } finally {
      setLoading(false);
    }
  };

  const startOAuthLogin = async () => {
    try {
      const response = await authAPI.googleLogin();
      return response.data; // { authorization_url, state }
    } catch (error: any) {
      console.error('OAuth initiation failed:', error);
      if (error.response?.status === 501) {
        throw new Error('Google OAuth is temporarily unavailable. Please use email/password login below.');
      }
      throw new Error('Failed to start OAuth login');
    }
  };

  const completeOAuthLogin = async (code: string, state: string) => {
    try {
      const response = await authAPI.googleCallback(code, state);
      
      const { access_token, user: userData } = response.data;
      
      localStorage.setItem('access_token', access_token);
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
    } catch (error: any) {
      let errorMessage = 'OAuth login failed';
      if (error.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error.message) {
        errorMessage = error.message;
      }
      console.error('OAuth completion error:', error);
      throw new Error(errorMessage);
    }
  };

  const localLogin = async (email: string, password: string) => {
    try {
      const response = await authAPI.localLogin(email, password);
      
      const { access_token, user: userData } = response.data;
      
      localStorage.setItem('access_token', access_token);
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
    } catch (error: any) {
      let errorMessage = 'Login failed';
      if (error.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error.message) {
        errorMessage = error.message;
      }
      console.error('Local login error:', error);
      throw new Error(errorMessage);
    }
  };

  const localRegister = async (email: string, password: string) => {
    try {
      await authAPI.localRegister(email, password);
    } catch (error: any) {
      let errorMessage = 'Registration failed';
      if (error.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error.message) {
        errorMessage = error.message;
      }
      console.error('Registration error:', error);
      throw new Error(errorMessage);
    }
  };

  const logout = async () => {
    try {
      // Call backend logout to blacklist token
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('access_token');
      delete api.defaults.headers.common['Authorization'];
      setUser(null);
    }
  };

  const value = {
    user,
    isAuthenticated: !!user,
    startOAuthLogin,
    completeOAuthLogin,
    localLogin,
    localRegister,
    logout,
    loading,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};