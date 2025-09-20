import React, { useState, useEffect, useCallback } from 'react';
import { useForm } from 'react-hook-form';
import { settingsAPI, healthAPI } from '../services/api';

interface SettingsFormData {
  default_encryption: string;
  km_endpoint: string;
  auto_decrypt: boolean;
}

const Settings: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [healthStatus, setHealthStatus] = useState<any>(null);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  const { register, handleSubmit, setValue, formState: { errors } } = useForm<SettingsFormData>();

  const loadSettings = useCallback(async () => {
    try {
      setLoading(true);
      const response = await settingsAPI.getSettings();
      const settings = response.data;
      
      setValue('default_encryption', settings.default_encryption);
      setValue('km_endpoint', settings.km_endpoint);
      setValue('auto_decrypt', settings.auto_decrypt);
    } catch (err: any) {
      setError('Failed to load settings');
      console.error('Settings load error:', err);
    } finally {
      setLoading(false);
    }
  }, [setValue]);

  useEffect(() => {
    loadSettings();
    checkHealth();
  }, [loadSettings]);

  const checkHealth = async () => {
    try {
      const response = await healthAPI.check();
      setHealthStatus(response.data);
    } catch (err) {
      console.error('Health check failed:', err);
    }
  };

  const onSubmit = async (data: SettingsFormData) => {
    setSaving(true);
    setError('');
    setSuccess('');

    try {
      const formData = new FormData();
      formData.append('default_encryption', data.default_encryption);
      formData.append('km_endpoint', data.km_endpoint);
      formData.append('auto_decrypt', data.auto_decrypt.toString());

      await settingsAPI.updateSettings(formData);
      setSuccess('Settings saved successfully');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const getEncryptionDescription = (mode: string) => {
    switch (mode) {
      case 'OTP':
        return {
          title: 'One-Time Pad (Highest Security)',
          description: 'Perfect forward secrecy using quantum-distributed keys. Unbreakable encryption when implemented correctly.',
          security: 'Maximum',
          color: 'text-green-600'
        };
      case 'AES':
        return {
          title: 'AES-256-GCM (Recommended)',
          description: 'Military-grade encryption with Key Manager integration. Excellent balance of security and performance.',
          security: 'High',
          color: 'text-blue-600'
        };
      case 'PQC':
        return {
          title: 'Post-Quantum Cryptography',
          description: 'Quantum-resistant algorithms (Kyber/Dilithium). Future-proof against quantum computer attacks.',
          security: 'Quantum-Resistant',
          color: 'text-purple-600'
        };
      case 'NONE':
        return {
          title: 'TLS Only (Compatibility Mode)',
          description: 'Standard transport layer security. Use only when QuMail encryption is not supported.',
          security: 'Basic',
          color: 'text-yellow-600'
        };
      default:
        return {
          title: 'Unknown',
          description: 'Unknown encryption mode',
          security: 'Unknown',
          color: 'text-gray-600'
        };
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Health Status */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">System Status</h2>
        {healthStatus ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center justify-between p-3 bg-green-50 rounded-md">
              <div>
                <p className="text-sm font-medium text-gray-900">Backend Server</p>
                <p className="text-xs text-gray-600">API Status</p>
              </div>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                🟢 {healthStatus.status}
              </span>
            </div>
            
            <div className="flex items-center justify-between p-3 bg-blue-50 rounded-md">
              <div>
                <p className="text-sm font-medium text-gray-900">Key Manager</p>
                <p className="text-xs text-gray-600">{healthStatus.km_status?.status || 'Unknown'}</p>
              </div>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                healthStatus.km_status?.status === 'healthy' 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-red-100 text-red-800'
              }`}>
                {healthStatus.km_status?.status === 'healthy' ? '🟢' : '🔴'} KM
              </span>
            </div>
            
            <div className="flex items-center justify-between p-3 bg-purple-50 rounded-md">
              <div>
                <p className="text-sm font-medium text-gray-900">Version</p>
                <p className="text-xs text-gray-600">QuMail {healthStatus.version}</p>
              </div>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                ✅ Latest
              </span>
            </div>
          </div>
        ) : (
          <div className="text-center py-4">
            <p className="text-gray-500">Unable to fetch system status</p>
            <button
              onClick={checkHealth}
              className="mt-2 text-sm text-blue-600 hover:text-blue-800 underline"
            >
              Retry
            </button>
          </div>
        )}
      </div>

      {/* Settings Form */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Security Settings</h2>
          <p className="text-sm text-gray-600 mt-1">Configure your quantum encryption preferences</p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-6">
          {/* Default Encryption Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">
              Default Encryption Level
            </label>
            <div className="space-y-3">
              {(['OTP', 'AES', 'PQC', 'NONE'] as const).map((mode) => {
                const info = getEncryptionDescription(mode);
                return (
                  <div key={mode} className="relative">
                    <label className="flex items-start space-x-3 p-4 border rounded-lg cursor-pointer hover:bg-gray-50">
                      <input
                        {...register('default_encryption', { required: 'Please select an encryption mode' })}
                        type="radio"
                        value={mode}
                        className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                      />
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <h4 className={`font-medium ${info.color}`}>
                            Level {mode === 'OTP' ? '1' : mode === 'AES' ? '2' : mode === 'PQC' ? '3' : '4'} - {info.title}
                          </h4>
                          <span className={`text-xs px-2 py-1 rounded-full ${
                            info.security === 'Maximum' ? 'bg-green-100 text-green-800' :
                            info.security === 'High' ? 'bg-blue-100 text-blue-800' :
                            info.security === 'Quantum-Resistant' ? 'bg-purple-100 text-purple-800' :
                            'bg-yellow-100 text-yellow-800'
                          }`}>
                            {info.security}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 mt-1">{info.description}</p>
                      </div>
                    </label>
                  </div>
                );
              })}
            </div>
            {errors.default_encryption && (
              <p className="mt-2 text-sm text-red-600">{errors.default_encryption.message}</p>
            )}
          </div>

          {/* Key Manager Configuration */}
          <div>
            <label htmlFor="km_endpoint" className="block text-sm font-medium text-gray-700">
              Key Manager Endpoint
            </label>
            <input
              {...register('km_endpoint', { 
                required: 'Key Manager endpoint is required',
                pattern: {
                  value: /^https?:\/\/.+/,
                  message: 'Please enter a valid URL'
                }
              })}
              type="url"
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
              placeholder="http://localhost:8001"
            />
            {errors.km_endpoint && (
              <p className="mt-1 text-sm text-red-600">{errors.km_endpoint.message}</p>
            )}
            <p className="mt-1 text-xs text-gray-500">
              URL of the ETSI QKD 014 compliant Key Manager service
            </p>
          </div>

          {/* Auto-decrypt Option */}
          <div className="flex items-start space-x-3">
            <input
              {...register('auto_decrypt')}
              type="checkbox"
              className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <div>
              <label className="text-sm font-medium text-gray-700">
                Auto-decrypt incoming emails
              </label>
              <p className="text-sm text-gray-600 mt-1">
                Automatically decrypt emails when viewing (requires valid KM session)
              </p>
            </div>
          </div>

          {/* Status Messages */}
          {success && (
            <div className="bg-green-50 border border-green-200 rounded-md p-3">
              <div className="flex">
                <div className="text-green-400">✅</div>
                <div className="ml-3">
                  <p className="text-sm text-green-800">{success}</p>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-md p-3">
              <div className="flex">
                <div className="text-red-400">⚠️</div>
                <div className="ml-3">
                  <p className="text-sm text-red-800">{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Save Button */}
          <div className="flex justify-end pt-4 border-t border-gray-200">
            <button
              type="submit"
              disabled={saving}
              className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Saving...
                </>
              ) : (
                'Save Settings'
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Information Panel */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h3 className="text-lg font-medium text-blue-900 mb-3">🔐 About QuMail Security</h3>
        <div className="prose prose-sm text-blue-800">
          <p>
            QuMail implements a four-tier encryption system designed to provide maximum security for your email communications:
          </p>
          <ul className="mt-3 space-y-2">
            <li><strong>Quantum Key Distribution:</strong> Uses the ETSI GS QKD 014 standard for secure key exchange</li>
            <li><strong>Forward Secrecy:</strong> All encryption keys are ephemeral and wiped after use</li>
            <li><strong>Integrity Verification:</strong> HMAC-SHA256 ensures message authenticity</li>
            <li><strong>Post-Quantum Ready:</strong> Resistant to attacks from quantum computers</li>
          </ul>
          <p className="mt-3">
            Your encryption preferences are stored locally and never transmitted to external servers.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Settings;