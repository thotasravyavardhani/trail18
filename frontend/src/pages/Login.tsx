import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Navigate, useSearchParams } from 'react-router-dom';

const Login: React.FC = () => {
  const { startOAuthLogin, completeOAuthLogin, localLogin, localRegister, isAuthenticated } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [searchParams] = useSearchParams();
  const [showLocalAuth, setShowLocalAuth] = useState(true);
  const [isRegistering, setIsRegistering] = useState(false);
  const [localFormData, setLocalFormData] = useState({
    email: '',
    password: ''
  });

  useEffect(() => {
    // Handle OAuth callback
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    
    if (code && state) {
      handleOAuthCallback(code, state);
    }
  }, [searchParams, completeOAuthLogin]);

  if (isAuthenticated) {
    return <Navigate to="/inbox" replace />;
  }

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setError('');
    
    try {
      const { authorization_url } = await startOAuthLogin();
      // Redirect to Google OAuth consent screen
      window.location.href = authorization_url;
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  };

  const handleOAuthCallback = async (code: string, state: string) => {
    setLoading(true);
    setError('');
    
    try {
      await completeOAuthLogin(code, state);
      // Navigation will be handled by the auth context
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLocalLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      await localLogin(localFormData.email, localFormData.password);
      // Navigation will be handled by the auth context
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLocalRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      await localRegister(localFormData.email, localFormData.password);
      setError('');
      setIsRegistering(false);
      // Auto-login after registration
      await localLogin(localFormData.email, localFormData.password);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setLocalFormData({
      ...localFormData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-xl shadow-lg">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">QuMail</h1>
          <p className="text-gray-600">Quantum-Secure Email Client</p>
          <div className="mt-4 flex justify-center space-x-2">
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
              🔐 OTP Encryption
            </span>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
              🛡️ AES-256-GCM
            </span>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
              ⚛️ PQC Ready
            </span>
          </div>
        </div>

        <div className="space-y-6">
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-md p-3">
              <p className="text-sm text-red-600">{error}</p>
            </div>
          )}

          {!showLocalAuth ? (
            <>
              {/* OAuth Sign In Section */}
              <div className="text-center">
                <p className="text-sm text-gray-600 mb-4">
                  Sign in with your Google account to access QuMail
                </p>
              </div>

              <button
                onClick={handleGoogleSignIn}
                disabled={loading}
                className="w-full flex items-center justify-center py-3 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-gray-600" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Connecting to Google...
                  </>
                ) : (
                  <>
                    <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                      <path fill="#4285f4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                      <path fill="#34a853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                      <path fill="#fbbc05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                      <path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Sign in with Google
                  </>
                )}
              </button>

              <div className="text-center">
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-white text-gray-500">Or</span>
                  </div>
                </div>
              </div>

              <button
                onClick={() => setShowLocalAuth(true)}
                className="w-full flex items-center justify-center py-3 px-4 border border-blue-300 rounded-md shadow-sm text-sm font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
                Local Login (email/password)
              </button>
            </>
          ) : (
            <>
              {/* Local Authentication Form */}
              <div className="text-center">
                <p className="text-sm text-gray-600 mb-4">
                  {isRegistering ? 'Create a new account' : 'Sign in with your existing account'}
                </p>
              </div>

              <form onSubmit={isRegistering ? handleLocalRegister : handleLocalLogin} className="space-y-4">
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                    Email address
                  </label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    required
                    value={localFormData.email}
                    onChange={handleInputChange}
                    className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                    placeholder="Enter your email"
                  />
                </div>

                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                    Password
                  </label>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete={isRegistering ? "new-password" : "current-password"}
                    required
                    value={localFormData.password}
                    onChange={handleInputChange}
                    className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                    placeholder={isRegistering ? "Create a password (min 6 characters)" : "Enter your password"}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex items-center justify-center py-3 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      {isRegistering ? 'Creating Account...' : 'Signing In...'}
                    </>
                  ) : (
                    isRegistering ? 'Create Account' : 'Sign In'
                  )}
                </button>
              </form>

              <div className="flex items-center justify-center space-x-4 text-sm">
                <button
                  onClick={() => setIsRegistering(!isRegistering)}
                  className="text-blue-600 hover:text-blue-500"
                >
                  {isRegistering ? 'Already have an account? Sign in' : 'Need an account? Register'}
                </button>
                <button
                  onClick={() => setShowLocalAuth(false)}
                  className="text-gray-600 hover:text-gray-500"
                >
                  Back to OAuth
                </button>
              </div>
            </>
          )}
        </div>

        <div className="text-center text-xs text-gray-500">
          <p>{showLocalAuth ? 'Local authentication for testing' : 'Secure OAuth 2.0 authentication with Google'}</p>
          <p className="mt-1">Your credentials are encrypted and protected</p>
        </div>
      </div>
    </div>
  );
};

export default Login;