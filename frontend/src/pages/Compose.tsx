import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useDropzone } from 'react-dropzone';
import { emailAPI } from '../services/api';

interface ComposeFormData {
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  body: string;
  encryption_mode: string;
}

const Compose: React.FC = () => {
  const [sending, setSending] = useState(false);
  const [attachments, setAttachments] = useState<File[]>([]);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  const { register, handleSubmit, reset, watch, formState: { errors } } = useForm<ComposeFormData>({
    defaultValues: {
      encryption_mode: 'AES',
      cc: '',
      bcc: '',
    }
  });

  const selectedEncryptionMode = watch('encryption_mode');

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: (acceptedFiles) => {
      setAttachments(prev => [...prev, ...acceptedFiles]);
    },
    multiple: true,
  });

  const removeAttachment = (index: number) => {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  };

  const onSubmit = async (data: ComposeFormData) => {
    setSending(true);
    setError('');
    setSuccess('');

    try {
      const formData = new FormData();
      formData.append('to', data.to);
      formData.append('cc', data.cc);
      formData.append('bcc', data.bcc);
      formData.append('subject', data.subject);
      formData.append('body', data.body);
      formData.append('encryption_mode', data.encryption_mode);

      // Add attachments
      attachments.forEach((file) => {
        formData.append('attachments', file);
      });

      const response = await emailAPI.composeEmail(formData);
      
      if (response.data.status === 'sent') {
        setSuccess('Email sent successfully with quantum encryption!');
        reset();
        setAttachments([]);
      } else {
        setSuccess('Email queued for sending when connection is restored.');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to send email');
    } finally {
      setSending(false);
    }
  };

  const getEncryptionDescription = (mode: string) => {
    switch (mode) {
      case 'OTP':
        return '🔐 One-Time Pad: Perfect forward secrecy using quantum-distributed keys';
      case 'AES':
        return '🛡️ AES-256-GCM: Military-grade encryption with Key Manager integration';
      case 'PQC':
        return '⚛️ Post-Quantum: Quantum-resistant cryptography (Kyber/Dilithium)';
      case 'NONE':
        return '🔵 TLS Only: Standard transport layer security';
      default:
        return 'Select encryption level';
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Compose Secure Email</h2>
          <p className="text-sm text-gray-600 mt-1">Send quantum-encrypted messages</p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-6">
          {/* Encryption Mode Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Encryption Level
            </label>
            <select
              {...register('encryption_mode', { required: 'Encryption mode is required' })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="OTP">Level 1 - One-Time Pad (Maximum Security)</option>
              <option value="AES">Level 2 - AES-256-GCM (Recommended)</option>
              <option value="PQC">Level 3 - Post-Quantum (Future-Proof)</option>
              <option value="NONE">Level 4 - TLS Only (Basic)</option>
            </select>
            <p className="mt-1 text-xs text-gray-600">
              {getEncryptionDescription(selectedEncryptionMode || 'OTP')}
            </p>
          </div>

          {/* Recipients */}
          <div className="space-y-4">
            <div>
              <label htmlFor="to" className="block text-sm font-medium text-gray-700">
                To <span className="text-red-500">*</span>
              </label>
              <input
                {...register('to', { 
                  required: 'Recipient is required',
                  pattern: {
                    value: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                    message: 'Invalid email address'
                  }
                })}
                type="email"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                placeholder="recipient@example.com"
              />
              {errors.to && (
                <p className="mt-1 text-sm text-red-600">{errors.to.message}</p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="cc" className="block text-sm font-medium text-gray-700">
                  CC
                </label>
                <input
                  {...register('cc')}
                  type="email"
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                  placeholder="cc@example.com"
                />
              </div>

              <div>
                <label htmlFor="bcc" className="block text-sm font-medium text-gray-700">
                  BCC
                </label>
                <input
                  {...register('bcc')}
                  type="email"
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                  placeholder="bcc@example.com"
                />
              </div>
            </div>
          </div>

          {/* Subject */}
          <div>
            <label htmlFor="subject" className="block text-sm font-medium text-gray-700">
              Subject <span className="text-red-500">*</span>
            </label>
            <input
              {...register('subject', { required: 'Subject is required' })}
              type="text"
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
              placeholder="Email subject"
            />
            {errors.subject && (
              <p className="mt-1 text-sm text-red-600">{errors.subject.message}</p>
            )}
          </div>

          {/* Message Body */}
          <div>
            <label htmlFor="body" className="block text-sm font-medium text-gray-700">
              Message <span className="text-red-500">*</span>
            </label>
            <textarea
              {...register('body', { required: 'Message body is required' })}
              rows={12}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
              placeholder="Compose your secure message..."
            />
            {errors.body && (
              <p className="mt-1 text-sm text-red-600">{errors.body.message}</p>
            )}
          </div>

          {/* File Attachments */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Attachments
            </label>
            <div
              {...getRootProps()}
              className={`border-2 border-dashed rounded-md p-6 text-center cursor-pointer transition-colors ${
                isDragActive 
                  ? 'border-blue-400 bg-blue-50' 
                  : 'border-gray-300 hover:border-gray-400'
              }`}
            >
              <input {...getInputProps()} />
              <div className="text-gray-600">
                <div className="text-2xl mb-2">📎</div>
                {isDragActive ? (
                  <p>Drop files here...</p>
                ) : (
                  <div>
                    <p>Drag & drop files here, or click to select</p>
                    <p className="text-sm text-gray-500 mt-1">Files will be encrypted with the same security level</p>
                  </div>
                )}
              </div>
            </div>

            {/* Attachment List */}
            {attachments.length > 0 && (
              <div className="mt-4 space-y-2">
                {attachments.map((file, index) => (
                  <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded-md">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">📄</span>
                      <span className="text-sm text-gray-900">{file.name}</span>
                      <span className="text-xs text-gray-500">
                        ({(file.size / 1024 / 1024).toFixed(2)} MB)
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => removeAttachment(index)}
                      className="text-red-600 hover:text-red-800 text-sm"
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>
            )}
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

          {/* Action Buttons */}
          <div className="flex items-center justify-between pt-4 border-t border-gray-200">
            <div className="text-sm text-gray-600">
              💡 All content will be encrypted before transmission
            </div>
            <div className="flex space-x-3">
              <button
                type="button"
                onClick={() => {
                  reset();
                  setAttachments([]);
                  setSuccess('');
                  setError('');
                }}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50"
              >
                Clear
              </button>
              <button
                type="submit"
                disabled={sending}
                className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {sending ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Encrypting & Sending...
                  </>
                ) : (
                  '🔐 Send Encrypted Email'
                )}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Compose;