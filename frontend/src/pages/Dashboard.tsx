import React, { useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useKeyVault } from '../contexts/KeyVaultContext';

const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const { keyCount, isVaultReady, refreshKeyVault, securityLevel, setSecurityLevel } = useKeyVault();

  useEffect(() => {
    // Refresh key vault on dashboard load if needed
    if (keyCount < 5) {
      refreshKeyVault();
    }
  }, [keyCount, refreshKeyVault]);

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow p-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">
          Welcome to QuMail, {user?.email}
        </h1>
        <p className="text-gray-600 mb-6">
          Your quantum-secure email dashboard. All communications are protected with advanced encryption.
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-gradient-to-r from-green-400 to-green-600 rounded-lg p-6 text-white">
            <div className="flex items-center">
              <div className="text-3xl mr-4">🔐</div>
              <div>
                <h3 className="text-lg font-semibold">OTP Encryption</h3>
                <p className="text-green-100">Perfect forward secrecy</p>
              </div>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-blue-400 to-blue-600 rounded-lg p-6 text-white">
            <div className="flex items-center">
              <div className="text-3xl mr-4">🛡️</div>
              <div>
                <h3 className="text-lg font-semibold">AES-256-GCM</h3>
                <p className="text-blue-100">Military-grade encryption</p>
              </div>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-purple-400 to-purple-600 rounded-lg p-6 text-white">
            <div className="flex items-center">
              <div className="text-3xl mr-4">⚛️</div>
              <div>
                <h3 className="text-lg font-semibold">PQC Ready</h3>
                <p className="text-purple-100">Quantum-resistant</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Security Status</h2>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Key Manager Connection</span>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                🟢 Connected
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Email Server Connection</span>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                🟢 OAuth Secure
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Quantum Key Vault</span>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                isVaultReady && keyCount > 5 ? 'bg-green-100 text-green-800' : 
                keyCount > 0 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'
              }`}>
                {isVaultReady && keyCount > 5 ? '🟢' : keyCount > 0 ? '🟡' : '🔴'} {keyCount} keys available
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Security Level</span>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                securityLevel === 'OTP' ? 'bg-purple-100 text-purple-800' :
                securityLevel === 'AES' ? 'bg-blue-100 text-blue-800' :
                securityLevel === 'PQC' ? 'bg-indigo-100 text-indigo-800' :
                'bg-gray-100 text-gray-800'
              }`}>
                {securityLevel === 'OTP' ? '⚛️' : securityLevel === 'AES' ? '🔐' : securityLevel === 'PQC' ? '🛡️' : '🔒'} {securityLevel}
              </span>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
          
          {/* Security Level Selector */}
          <div className="mb-6 p-4 bg-gray-50 rounded-md">
            <h3 className="text-sm font-medium text-gray-900 mb-2">Security Level (ETSI GS QKD 014)</h3>
            <div className="grid grid-cols-4 gap-2">
              {(['OTP', 'AES', 'PQC', 'TLS'] as const).map((level) => (
                <button
                  key={level}
                  onClick={() => setSecurityLevel(level)}
                  className={`px-3 py-2 text-xs font-medium rounded-md border transition-colors ${
                    securityLevel === level
                      ? level === 'OTP' ? 'bg-purple-600 text-white border-purple-600'
                        : level === 'AES' ? 'bg-blue-600 text-white border-blue-600'
                        : level === 'PQC' ? 'bg-indigo-600 text-white border-indigo-600'
                        : 'bg-gray-600 text-white border-gray-600'
                      : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-100'
                  }`}
                >
                  {level === 'OTP' ? '⚛️' : level === 'AES' ? '🔐' : level === 'PQC' ? '🛡️' : '🔒'} {level}
                </button>
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              {securityLevel === 'OTP' ? 'One-Time Pad: Perfect secrecy with quantum keys'
               : securityLevel === 'AES' ? 'AES-256-GCM: Quantum-aided encryption'
               : securityLevel === 'PQC' ? 'Post-Quantum Cryptography: Quantum-resistant'
               : 'TLS Only: Standard transport encryption'}
            </p>
          </div>
          <div className="space-y-3">
            <button className="w-full text-left p-3 rounded-md bg-blue-50 hover:bg-blue-100 transition-colors">
              <div className="flex items-center">
                <span className="text-blue-600 text-xl mr-3">✏️</span>
                <div>
                  <div className="font-medium text-blue-900">Compose Secure Email</div>
                  <div className="text-sm text-blue-600">Send quantum-encrypted message</div>
                </div>
              </div>
            </button>
            
            <button className="w-full text-left p-3 rounded-md bg-green-50 hover:bg-green-100 transition-colors">
              <div className="flex items-center">
                <span className="text-green-600 text-xl mr-3">📥</span>
                <div>
                  <div className="font-medium text-green-900">Check Inbox</div>
                  <div className="text-sm text-green-600">View encrypted messages</div>
                </div>
              </div>
            </button>
            
            <button className="w-full text-left p-3 rounded-md bg-purple-50 hover:bg-purple-100 transition-colors">
              <div className="flex items-center">
                <span className="text-purple-600 text-xl mr-3">⚙️</span>
                <div>
                  <div className="font-medium text-purple-900">Security Settings</div>
                  <div className="text-sm text-purple-600">Configure encryption preferences</div>
                </div>
              </div>
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">About QuMail Encryption</h2>
        <div className="prose prose-sm text-gray-600">
          <p>
            QuMail uses a four-tier encryption system to ensure maximum security for your communications:
          </p>
          <ul className="mt-3 space-y-2">
            <li><strong>Level 1 - OTP (One-Time Pad):</strong> Uses quantum-distributed keys for perfect secrecy</li>
            <li><strong>Level 2 - AES-256-GCM:</strong> Military-grade encryption with key manager integration</li>
            <li><strong>Level 3 - PQC (Post-Quantum Cryptography):</strong> Quantum-resistant algorithms (Kyber/Dilithium)</li>
            <li><strong>Level 4 - TLS Only:</strong> Standard transport layer security</li>
          </ul>
          <p className="mt-3">
            All encryption keys are ephemeral and securely wiped from memory after use, ensuring forward secrecy.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;