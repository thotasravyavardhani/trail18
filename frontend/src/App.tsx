import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { KeyVaultProvider } from './contexts/KeyVaultContext';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Inbox from './pages/Inbox';
import Compose from './pages/Compose';
import Sent from './pages/Sent';
import Outbox from './pages/Outbox';
import Settings from './pages/Settings';
import Layout from './components/Layout';

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
};

const App: React.FC = () => {
  return (
    <AuthProvider>
      <KeyVaultProvider>
        <Router>
        <div className="min-h-screen bg-gray-50">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <Layout>
                    <Routes>
                      <Route path="/" element={<Navigate to="/inbox" replace />} />
                      <Route path="/dashboard" element={<Dashboard />} />
                      <Route path="/inbox" element={<Inbox />} />
                      <Route path="/compose" element={<Compose />} />
                      <Route path="/sent" element={<Sent />} />
                      <Route path="/outbox" element={<Outbox />} />
                      <Route path="/settings" element={<Settings />} />
                    </Routes>
                  </Layout>
                </ProtectedRoute>
              }
            />
          </Routes>
        </div>
        </Router>
      </KeyVaultProvider>
    </AuthProvider>
  );
};

export default App;