import React, { useState, useEffect } from 'react';
import { emailAPI } from '../services/api';

interface Email {
  id: string;
  uid: string;
  sender: string;
  subject: string;
  body: string;
  date_received: string;
  encryption_mode: string;
  decryption_status: string;
  read: boolean;
}

const Inbox: React.FC = () => {
  const [emails, setEmails] = useState<Email[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [error, setError] = useState('');
  const [isAutoRefreshing, setIsAutoRefreshing] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState<NodeJS.Timeout | null>(null);

  useEffect(() => {
    fetchInbox();
    
    // Set up auto-refresh every 30 seconds
    if (isAutoRefreshing) {
      const interval = setInterval(() => {
        fetchInbox();
      }, 30000);
      setRefreshInterval(interval);
      
      return () => {
        if (interval) clearInterval(interval);
      };
    }
  }, [isAutoRefreshing]);
  
  // Cleanup interval on component unmount
  useEffect(() => {
    return () => {
      if (refreshInterval) clearInterval(refreshInterval);
    };
  }, [refreshInterval]);

  const fetchInbox = async (showLoading: boolean = true) => {
    try {
      if (showLoading) setLoading(true);
      const response = await emailAPI.getInbox();
      setEmails(response.data.emails || []);
      setError(''); // Clear error on successful fetch
    } catch (err: any) {
      setError('Failed to fetch inbox');
      console.error('Inbox fetch error:', err);
    } finally {
      if (showLoading) setLoading(false);
    }
  };
  
  const toggleAutoRefresh = () => {
    setIsAutoRefreshing(!isAutoRefreshing);
    if (refreshInterval) {
      clearInterval(refreshInterval);
      setRefreshInterval(null);
    }
  };
  
  const manualRefresh = () => {
    fetchInbox(false); // Don't show loading spinner for manual refresh
  };

  const getEncryptionBadge = (mode: string, status: string) => {
    if (status === 'error') {
      return (
        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
          🔴 Unreadable
        </span>
      );
    }

    switch (mode) {
      case 'OTP':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
            🔐 Level 1 - OTP
          </span>
        );
      case 'AES':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
            🛡️ Level 2 - AES
          </span>
        );
      case 'PQC':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
            ⚛️ Level 3 - PQC
          </span>
        );
      case 'NONE':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
            🔵 Level 4 - TLS
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
            ❓ Unknown
          </span>
        );
    }
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return 'Invalid date';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading encrypted emails...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="flex">
          <div className="text-red-400">⚠️</div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error</h3>
            <p className="text-sm text-red-700 mt-1">{error}</p>
            <button
              onClick={() => fetchInbox()}
              className="mt-2 text-sm text-red-600 hover:text-red-800 underline"
            >
              Try again
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full">
      {/* Email List */}
      <div className="w-1/2 border-r border-gray-200 overflow-auto">
        <div className="p-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Inbox</h2>
              <p className="text-sm text-gray-600">{emails.length} encrypted messages</p>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={toggleAutoRefresh}
                className={`px-3 py-1 text-xs rounded-full font-medium transition-colors ${
                  isAutoRefreshing 
                    ? 'bg-green-100 text-green-800 hover:bg-green-200' 
                    : 'bg-gray-100 text-gray-800 hover:bg-gray-200'
                }`}
              >
                {isAutoRefreshing ? '🟢 Auto-refresh ON' : '🔴 Auto-refresh OFF'}
              </button>
              <button
                onClick={manualRefresh}
                className="px-3 py-1 text-sm text-blue-600 hover:text-blue-800 hover:bg-blue-50 rounded-md transition-colors"
              >
                🔄 Refresh
              </button>
            </div>
          </div>
        </div>

        {emails.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <div className="text-4xl mb-4">📪</div>
            <p>Your secure inbox is empty</p>
            <p className="text-sm mt-2">Encrypted emails will appear here</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {emails.map((email) => (
              <div
                key={email.id || email.uid}
                onClick={() => setSelectedEmail(email)}
                className={`p-4 cursor-pointer hover:bg-gray-50 ${
                  selectedEmail?.id === email.id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
                } ${email.read ? '' : 'bg-blue-25 font-medium'}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2 mb-1">
                      <p className="text-sm font-medium text-gray-900 truncate">
                        {email.sender}
                      </p>
                      {getEncryptionBadge(email.encryption_mode, email.decryption_status)}
                    </div>
                    <p className="text-sm text-gray-900 mb-1 truncate">
                      {email.subject || 'No Subject'}
                    </p>
                    <p className="text-sm text-gray-600 truncate">
                      {email.decryption_status === 'success' 
                        ? email.body?.substring(0, 100) + '...'
                        : 'Encrypted content - click to decrypt'
                      }
                    </p>
                  </div>
                  <div className="ml-2 flex-shrink-0">
                    <p className="text-xs text-gray-500">
                      {formatDate(email.date_received)}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Email Content */}
      <div className="w-1/2 flex flex-col">
        {selectedEmail ? (
          <div className="flex-1 flex flex-col">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">
                    {selectedEmail.subject || 'No Subject'}
                  </h3>
                  <p className="text-sm text-gray-600 mt-1">
                    From: {selectedEmail.sender}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">
                    {formatDate(selectedEmail.date_received)}
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  {getEncryptionBadge(selectedEmail.encryption_mode, selectedEmail.decryption_status)}
                </div>
              </div>

              {selectedEmail.decryption_status === 'error' && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 mb-4">
                  <div className="flex">
                    <div className="text-yellow-400">⚠️</div>
                    <div className="ml-3">
                      <h4 className="text-sm font-medium text-yellow-800">Decryption Failed</h4>
                      <p className="text-sm text-yellow-700 mt-1">
                        This message could not be decrypted. It may be corrupted or use an unsupported encryption method.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="flex-1 p-6 overflow-auto">
              <div className="prose prose-sm max-w-none">
                {selectedEmail.decryption_status === 'success' ? (
                  <div className="whitespace-pre-wrap text-gray-900">
                    {selectedEmail.body}
                  </div>
                ) : (
                  <div className="text-center text-gray-500 py-8">
                    <div className="text-4xl mb-4">🔒</div>
                    <p>Encrypted content</p>
                    <p className="text-sm mt-2">
                      {selectedEmail.encryption_mode === 'OTP' && 'One-Time Pad encryption'}
                      {selectedEmail.encryption_mode === 'AES' && 'AES-256-GCM encryption'}
                      {selectedEmail.encryption_mode === 'PQC' && 'Post-Quantum Cryptography'}
                      {selectedEmail.encryption_mode === 'NONE' && 'Plaintext over TLS'}
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="p-4 border-t border-gray-200 bg-gray-50">
              <div className="flex space-x-2">
                <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm">
                  Reply
                </button>
                <button className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 text-sm">
                  Forward
                </button>
                <button className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 text-sm">
                  Archive
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-gray-500">
            <div className="text-center">
              <div className="text-6xl mb-4">📧</div>
              <p className="text-lg">Select an email to view</p>
              <p className="text-sm mt-2">Choose a message from your encrypted inbox</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Inbox;