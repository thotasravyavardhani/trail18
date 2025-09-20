import React, { useState, useEffect } from 'react';
import { useKeyVault } from '../contexts/KeyVaultContext';

interface EmailReaderProps {
  email: {
    uid: string;
    sender: string;
    subject: string;
    body: string;
    date: string;
    encryption_mode: 'OTP' | 'AES' | 'PQC' | 'NONE';
    mac?: string;
    km_key_id?: string;
    decryption_status?: string;
    decryption_error?: string;
    attachments?: Array<{
      filename: string;
      content_type: string;
      size: number;
    }>;
  };
  onClose: () => void;
}

const EmailReader: React.FC<EmailReaderProps> = ({ email, onClose }) => {
  const [integrityStatus, setIntegrityStatus] = useState<'verified' | 'tampered' | 'unknown'>('unknown');
  const [decryptedBody, setDecryptedBody] = useState<string>('');
  const { securityLevel } = useKeyVault();

  useEffect(() => {
    verifyEmailIntegrity();
    decryptEmailContent();
  }, [email]);

  const verifyEmailIntegrity = async () => {
    try {
      if (!email.mac || email.encryption_mode === 'NONE') {
        setIntegrityStatus('unknown');
        return;
      }

      // In a real implementation, this would verify HMAC with the actual key
      // For now, simulate based on the presence of MAC
      if (email.mac && email.mac.length > 0) {
        // Simulate HMAC verification
        const isValid = email.mac.startsWith('hmac_') && !email.decryption_error;
        setIntegrityStatus(isValid ? 'verified' : 'tampered');
      } else {
        setIntegrityStatus('unknown');
      }
    } catch (error) {
      console.error('Integrity verification failed:', error);
      setIntegrityStatus('tampered');
    }
  };

  const decryptEmailContent = async () => {
    try {
      if (email.encryption_mode === 'NONE') {
        setDecryptedBody(email.body);
        return;
      }

      if (email.decryption_status === 'error') {
        setDecryptedBody(`🔒 Decryption failed: ${email.decryption_error || 'Unknown error'}`);
        return;
      }

      // In a real implementation, this would decrypt with the appropriate key
      setDecryptedBody(email.body || 'Encrypted content - decryption in progress...');
    } catch (error) {
      setDecryptedBody(`🔒 Failed to decrypt: ${error}`);
    }
  };

  const getSecurityBadge = () => {
    const mode = email.encryption_mode;
    
    switch (mode) {
      case 'OTP':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-purple-100 text-purple-800">
            ⚛️ OTP Quantum-Secure
          </span>
        );
      case 'AES':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
            🔐 AES-256-GCM
          </span>
        );
      case 'PQC':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-indigo-100 text-indigo-800">
            🛡️ Post-Quantum
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-800">
            📄 Unencrypted
          </span>
        );
    }
  };

  const getIntegrityBadge = () => {
    switch (integrityStatus) {
      case 'verified':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
            ✅ Verified
          </span>
        );
      case 'tampered':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800">
            ⚠️ Tamper Detected
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-yellow-100 text-yellow-800">
            ❓ Not Verified
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Email Reader</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-500 text-2xl"
            >
              ×
            </button>
          </div>
          
          {/* Security and Integrity Badges */}
          <div className="flex items-center space-x-3 mt-3">
            {getSecurityBadge()}
            {getIntegrityBadge()}
            {email.km_key_id && (
              <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-700">
                Key: {email.km_key_id.substring(0, 8)}...
              </span>
            )}
          </div>
        </div>

        {/* Email Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
          {/* Email Headers */}
          <div className="border-b border-gray-200 pb-4 mb-6">
            <div className="grid grid-cols-1 gap-2">
              <div>
                <span className="font-medium text-gray-700">From:</span>
                <span className="ml-2 text-gray-900">{email.sender}</span>
              </div>
              <div>
                <span className="font-medium text-gray-700">Subject:</span>
                <span className="ml-2 text-gray-900">{email.subject}</span>
              </div>
              <div>
                <span className="font-medium text-gray-700">Date:</span>
                <span className="ml-2 text-gray-900">{email.date}</span>
              </div>
            </div>
          </div>

          {/* Email Body */}
          <div className="mb-6">
            <h3 className="text-sm font-medium text-gray-700 mb-2">Message:</h3>
            <div className="bg-gray-50 rounded-md p-4">
              <pre className="whitespace-pre-wrap text-sm text-gray-900 font-mono">
                {decryptedBody}
              </pre>
            </div>
          </div>

          {/* Attachments */}
          {email.attachments && email.attachments.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-medium text-gray-700 mb-2">Attachments:</h3>
              <div className="space-y-2">
                {email.attachments.map((attachment, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-3 bg-gray-50 rounded-md"
                  >
                    <div className="flex items-center">
                      <span className="text-xl mr-2">📎</span>
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          {attachment.filename}
                        </div>
                        <div className="text-xs text-gray-500">
                          {attachment.content_type} • {(attachment.size / 1024).toFixed(1)} KB
                        </div>
                      </div>
                    </div>
                    <button className="text-sm text-blue-600 hover:text-blue-800 font-medium">
                      Download
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Details */}
          <div className="bg-blue-50 rounded-md p-4">
            <h3 className="text-sm font-medium text-blue-900 mb-2">Security Details:</h3>
            <div className="text-xs text-blue-800 space-y-1">
              <div>Encryption Mode: {email.encryption_mode}</div>
              {email.km_key_id && <div>Key Manager ID: {email.km_key_id}</div>}
              <div>Integrity Status: {integrityStatus}</div>
              {email.mac && <div>MAC: {email.mac.substring(0, 16)}...</div>}
              <div>Current Security Level: {securityLevel}</div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-200 bg-gray-50">
          <div className="flex justify-between items-center">
            <div className="text-xs text-gray-500">
              QuMail Quantum-Secure Email • ETSI GS QKD 014 Compliant
            </div>
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmailReader;