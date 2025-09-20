import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { emailAPI } from '../services/api';

interface SentEmail {
  id: string;
  recipients: string | string[];
  subject: string;
  date_sent: string;
  encryption_mode: string;
  status: string;
}

const Sent: React.FC = () => {
  const navigate = useNavigate();
  const [emails, setEmails] = useState<SentEmail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchSentEmails();
  }, []);

  const fetchSentEmails = async () => {
    try {
      setLoading(true);
      const response = await emailAPI.getSent();
      setEmails(response.data.emails || []);
    } catch (err: any) {
      setError('Failed to fetch sent emails');
      console.error('Sent emails fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getEncryptionBadge = (mode: string) => {
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

  const formatRecipients = (recipients: string | string[]) => {
    if (Array.isArray(recipients)) {
      if (recipients.length === 1) {
        return recipients[0];
      } else if (recipients.length > 1) {
        return `${recipients[0]} +${recipients.length - 1} more`;
      }
      return 'No recipients';
    }
    return recipients || 'No recipients';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading sent emails...</p>
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
              onClick={fetchSentEmails}
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
    <div className="bg-white shadow rounded-lg">
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Sent Mail</h2>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => navigate('/compose')}
              className="px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors"
            >
              ✉️ Compose
            </button>
            <button
              onClick={fetchSentEmails}
              className="px-3 py-1 text-sm text-blue-600 hover:text-blue-800"
            >
              🔄 Refresh
            </button>
          </div>
        </div>
        <p className="text-sm text-gray-600 mt-1">{emails.length} encrypted emails sent</p>
      </div>

      {emails.length === 0 ? (
        <div className="p-8 text-center text-gray-500">
          <div className="text-4xl mb-4">📤</div>
          <p className="text-lg">No sent emails</p>
          <p className="text-sm mt-2">Emails you send will appear here</p>
        </div>
      ) : (
        <div className="overflow-hidden">
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
                  Date Sent
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
                      {formatRecipients(email.recipients)}
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
                    {formatDate(email.date_sent)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      email.status === 'sent' 
                        ? 'bg-green-100 text-green-800' 
                        : email.status === 'queued'
                        ? 'bg-yellow-100 text-yellow-800'
                        : 'bg-red-100 text-red-800'
                    }`}>
                      {email.status === 'sent' && '✅ Delivered'}
                      {email.status === 'queued' && '⏳ Queued'}
                      {email.status === 'failed' && '❌ Failed'}
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

export default Sent;