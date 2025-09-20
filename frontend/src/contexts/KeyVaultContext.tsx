import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api } from '../services/api';

interface QuantumKey {
  key_id: string;
  key: string; // Base64 encoded
  expires_at: string;
}

interface KeyVaultContextType {
  keys: QuantumKey[];
  keyCount: number;
  isVaultReady: boolean;
  refreshKeyVault: () => Promise<void>;
  getKey: () => QuantumKey | null;
  releaseKeys: (usedKeyIds: string[]) => Promise<void>;
  securityLevel: 'OTP' | 'AES' | 'PQC' | 'TLS';
  setSecurityLevel: (level: 'OTP' | 'AES' | 'PQC' | 'TLS') => void;
}

const KeyVaultContext = createContext<KeyVaultContextType | undefined>(undefined);

const KEY_BATCH_SIZE = 15;
const LOW_KEY_THRESHOLD = 5;
const VAULT_STORAGE_KEY = 'qumail_key_vault';

export const useKeyVault = () => {
  const context = useContext(KeyVaultContext);
  if (context === undefined) {
    throw new Error('useKeyVault must be used within a KeyVaultProvider');
  }
  return context;
};

export const KeyVaultProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [keys, setKeys] = useState<QuantumKey[]>([]);
  const [securityLevel, setSecurityLevel] = useState<'OTP' | 'AES' | 'PQC' | 'TLS'>('AES');
  const [isVaultReady, setIsVaultReady] = useState(false);

  // Load keys from secure local storage on mount
  useEffect(() => {
    loadKeysFromStorage();
  }, []);

  // Auto-refresh keys when below threshold
  useEffect(() => {
    if (keys.length < LOW_KEY_THRESHOLD && keys.length > 0) {
      console.log('Key count below threshold, refreshing vault...');
      refreshKeyVault();
    }
  }, [keys.length]);

  const encryptData = (data: string): string => {
    // Simple encryption for demo - in production use proper encryption
    return btoa(data);
  };

  const decryptData = (encryptedData: string): string => {
    try {
      return atob(encryptedData);
    } catch {
      return '';
    }
  };

  const loadKeysFromStorage = () => {
    try {
      const storedData = localStorage.getItem(VAULT_STORAGE_KEY);
      if (storedData) {
        const decryptedData = decryptData(storedData);
        const parsedKeys = JSON.parse(decryptedData);
        
        // Filter out expired keys
        const validKeys = parsedKeys.filter((key: QuantumKey) => 
          new Date(key.expires_at) > new Date()
        );
        
        setKeys(validKeys);
        setIsVaultReady(validKeys.length > 0);
      }
    } catch (error) {
      console.error('Failed to load keys from storage:', error);
      localStorage.removeItem(VAULT_STORAGE_KEY);
    }
  };

  const saveKeysToStorage = (keysToSave: QuantumKey[]) => {
    try {
      const dataToEncrypt = JSON.stringify(keysToSave);
      const encryptedData = encryptData(dataToEncrypt);
      localStorage.setItem(VAULT_STORAGE_KEY, encryptedData);
    } catch (error) {
      console.error('Failed to save keys to storage:', error);
    }
  };

  const refreshKeyVault = async () => {
    try {
      const response = await api.get(`/keys/batch?batch_size=${KEY_BATCH_SIZE}`);
      const newKeys: QuantumKey[] = response.data.key_batch.keys || [];
      
      // Merge with existing keys and remove duplicates
      const updatedKeys = [...keys];
      newKeys.forEach(newKey => {
        if (!updatedKeys.find(k => k.key_id === newKey.key_id)) {
          updatedKeys.push(newKey);
        }
      });
      
      setKeys(updatedKeys);
      saveKeysToStorage(updatedKeys);
      setIsVaultReady(true);
      
      console.log(`Key vault refreshed: ${updatedKeys.length} total keys available`);
    } catch (error) {
      console.error('Failed to refresh key vault:', error);
      setIsVaultReady(false);
    }
  };

  const getKey = (): QuantumKey | null => {
    // Filter valid (non-expired) keys
    const validKeys = keys.filter(key => new Date(key.expires_at) > new Date());
    
    if (validKeys.length === 0) {
      console.warn('No valid keys available in vault');
      return null;
    }
    
    // Return the first available key (FIFO)
    const selectedKey = validKeys[0];
    
    // Remove the selected key from available keys
    const remainingKeys = keys.filter(key => key.key_id !== selectedKey.key_id);
    setKeys(remainingKeys);
    saveKeysToStorage(remainingKeys);
    
    return selectedKey;
  };

  const releaseKeys = async (usedKeyIds: string[]) => {
    try {
      await api.post('/keys/release', { used_key_ids: usedKeyIds });
      console.log(`Released ${usedKeyIds.length} used keys to KM`);
    } catch (error) {
      console.error('Failed to release keys:', error);
    }
  };

  const value = {
    keys,
    keyCount: keys.length,
    isVaultReady,
    refreshKeyVault,
    getKey,
    releaseKeys,
    securityLevel,
    setSecurityLevel,
  };

  return <KeyVaultContext.Provider value={value}>{children}</KeyVaultContext.Provider>;
};