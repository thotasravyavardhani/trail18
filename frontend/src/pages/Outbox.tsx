import React, { useState, useEffect } from 'react';
import { emailAPI } from '../services/api';

interface QueuedEmail {
  id: string;
  recipients: string;
  subject: string;
  encryption_mode: string;
  status: string;
  date_received: string;
}

const Outbox: React.FC = () => {
  const [emails, setEmails] = useState<QueuedEmail[]>([]);
  const [loading, setLoading] = useState(true);
  const [retrying, setRetrying] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchOutbox();
  }, []);

  const fetchOutbox = async () => {
    try {
      setLoading(true);
      const response = await emailAPI.getOutbox();
      setEmails(response.data.emails || []);
    } catch (err: any) {
      setError('Failed to fetch outbox');
      console.error('Outbox fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const retryOutbox = async () => {
    try {
      setRetrying(true);
      setError('');
      setSuccess('');
      
      const response = await emailAPI.retryOutbox();
      const { sent_count, total_queued } = response.data;
      
      if (sent_count > 0) {
        setSuccess(`Successfully sent ${sent_count} of ${total_queued} queued emails`);
        // Refresh outbox to show updated status
        await fetchOutbox();
      } else {
        setError('No emails could be sent. Check your connection and try again.');
      }
    } catch (err: any) {
      setError('Failed to retry sending emails');
      console.error('Retry outbox error:', err);
    } finally {
      setRetrying(false);
    }
  };

  const getEncryptionBadge = (mode: string) => {
    switch (mode) {
      case 'OTP':
      case 'AES':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
            🟢 Quantum-secure
          </span>
        );
      case 'PQC':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
            🟡 PQC Protected
          </span>
        );
      case 'NONE':
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
            🔵 TLS Only
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
          <p className="text-gray-600">Loading outbox...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white shadow rounded-lg">
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Outbox</h2>
            <p className="text-sm text-gray-600 mt-1">
              {emails.length} queued emails waiting to be sent
            </p>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={fetchOutbox}
              className="px-3 py-1 text-sm text-blue-600 hover:text-blue-800"
            >
              🔄 Refresh
            </button>
            {emails.length > 0 && (
              <button
                onClick={retryOutbox}
                disabled={retrying}
                className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
              >
                {retrying ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-1 h-3 w-3 text-white inline" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Retrying...
                  </>
                ) : (
                  '📤 Retry All'
                )}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Status Messages */}
      {success && (
        <div className="mx-6 mt-4 bg-green-50 border border-green-200 rounded-md p-3">
          <div className="flex">
            <div className="text-green-400">✅</div>
            <div className="ml-3">
              <p className="text-sm text-green-800">{success}</p>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="mx-6 mt-4 bg-red-50 border border-red-200 rounded-md p-3">
          <div className="flex">
            <div className="text-red-400">⚠️</div>
            <div className="ml-3">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          </div>
        </div>
      )}

      {emails.length === 0 ? (
        <div className="p-8 text-center text-gray-500">
          <div className="text-4xl mb-4">⏳</div>
          <p className="text-lg">Outbox is empty</p>
          <p className="text-sm mt-2">
            When you're offline, emails will be queued here until connection is restored
          </p>
          <div className="mt-4 p-4 bg-blue-50 rounded-md">
            <div className="flex items-center justify-center">
              <div className="text-blue-400 mr-2">💡</div>
              <div className="text-sm text-blue-800">
                <strong>Offline Mode:</strong> QuMail automatically queues encrypted emails when your connection is interrupted
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="overflow-hidden">
          <div className="p-4 bg-yellow-50 border-b border-yellow-200">
            <div className="flex items-center">
              <div className="text-yellow-600 mr-2">⚠️</div>
              <div className="text-sm text-yellow-800">
                <strong>Connection Issue:</strong> These encrypted emails are waiting to be sent. 
                Check your internet connection and click "Retry All" to attempt sending.
              </div>
            </div>
          </div>

          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Recipient
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Subject
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Encryption
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Queued
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {emails.map((email, index) => (
                <tr key={email.id || index} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900">
                      {email.recipients}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-900 max-w-xs truncate">
                      {email.subject || 'No Subject'}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getEncryptionBadge(email.encryption_mode)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDate(email.date_received)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                      ⏳ Queued
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Outbox;