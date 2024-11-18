import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { Buffer } from 'buffer';
import { Account, GlobalMeta, SuietBackup, TokenTool } from './core';
import { decryptMnemonic, decryptPrivateKey } from './core/crypto';
import { SignatureScheme, SupportedEncoding } from './core/SuiKeypairUtil';
import { SuiKeypairUtil } from './core/SuiKeypairUtil';
import suietLogo from "./assets/suiet-logo.svg";

async function validateToken(token: Buffer, meta: GlobalMeta): Promise<boolean> {
  if (!token || !meta) {
    return false;
  }

  if (
    !TokenTool.validateToken(token, meta.cipher)
  ) {
    return false;
  }
  return true;
}

function App() {
  const [count, setCount] = useState(0)
  const [backupJson, setBackupJson] = useState('')
  const [password, setPassword] = useState('')
  const [recoveryOutput, setRecoveryOutput] = useState('')
  const [copySuccess, setCopySuccess] = useState(false)
  const [isRecovering, setIsRecovering] = useState(false)

  const extractDbBackupFromBackupJson = (backupJson: Record<string, any>) => {
    const backupDataMap: Record<string, SuietBackup> = {};
    for (const key of Object.keys(backupJson)) {
      if (key.startsWith('DB_BACKUP_')) {
        try {
          backupDataMap[key] = JSON.parse(backupJson[key]) as SuietBackup;
        } catch (error) {
          console.error(`Failed to parse backup [${key}], ignore it. `, error);
        }
      }
    }
    if (Object.keys(backupDataMap).length === 0) {
      throw new Error('No db backup found from backup JSON');
    }
    return backupDataMap;
  }

  const recoverWalletDataFromOneBackup = async (backup: SuietBackup, password: string) => {
    const meta = backup.meta;
    if (!meta) {
      throw new Error('No recovery metadata found from backup');
    }
    if (!backup.wallets || backup.wallets.length === 0) {
      throw new Error('No wallets found from backup');
    }
    if (!backup.accounts || backup.accounts.length === 0) {
      throw new Error('No accounts found from backup');
    }
    const token = TokenTool.loadTokenWithPassword(meta, password);
    let isValid = await validateToken(token, meta);
    if (!isValid) {
      throw new Error('Invalid token');
    }

    const walletMap: Record<string, any> = {};
    for (const wallet of backup.wallets) {
      let mnemonic: string | null = null;
      if (wallet.encryptedMnemonic) {
        console.warn(`No encrypted mnemonic found from wallet ${wallet.id}, skip it.`);
        mnemonic = decryptMnemonic(token, wallet.encryptedMnemonic);
      } else {
        console.warn(`Non-recoverable wallet ${wallet.id}, no encrypted mnemonic or private key found from backup`);
      }

      const accounts: Record<string, any> = {};
      for (const account of backup.accounts) {
        const walletId = account.id.split('--')[0];
        if (walletId !== wallet.id) {
          continue;
        }
        let privateKey: string | null = null;
        let hdPath: string | null = null;

        if (wallet.isImported) {
          if (account.encryptedPrivateKey) {
            const keyPair = decryptPrivateKey(token, account.encryptedPrivateKey);
            if (keyPair) {
              privateKey = SuiKeypairUtil.encodePrivateKey(
                keyPair.getSecret(),
                SignatureScheme.ED25519,
                SupportedEncoding.BECH32
              );
            } else {
              console.warn(`Non-recoverable account ${account.id}, invalid private key found from backup`);
            }
          } else {
            console.warn(`Non-recoverable account ${account.id}, no encrypted private key found from backup`);
          }
        }

        if (account.hdPath) {
          hdPath = account.hdPath;
        }

        accounts[account.id] = {
          privateKey: privateKey,
          address: account.address,
          hdPath: hdPath,
        }
      }

      walletMap[wallet.id] = {
        name: wallet.name,
        type: wallet.type,
        mnemonic: mnemonic,
        accounts: accounts,
      }
    }
    return walletMap;
  }

  const recoverAccountInfo = async (backupJson: Record<string, any>, password: string) => {
    const dbBackupMap = extractDbBackupFromBackupJson(backupJson);

    const dbBackupKeysByLatest = Object.keys(dbBackupMap).sort((a, b) => {
      return b.localeCompare(a); // Sort descending
    });
    const latestDbBackupKey = dbBackupKeysByLatest[0];
    console.log('Latest db backup key:', latestDbBackupKey);

    for (const key of dbBackupKeysByLatest) {
      try {
        const walletMap = await recoverWalletDataFromOneBackup(dbBackupMap[key], password);
        console.log(`Successfully recovered from backup [${key}]:`, walletMap);
        return [key, walletMap];
      } catch (error) {
        console.error(`Failed to recover from backup [${key}]: `, error);
      }
    }
    return null;
  }

  const handleRecover = async (dbBackupJson: string, password: string) => {
    try {
      setIsRecovering(true)
      setRecoveryOutput('')
      const backup = JSON.parse(dbBackupJson) as SuietBackup;
      await new Promise(resolve => setTimeout(resolve, 1000));
      const result = await recoverAccountInfo(backup, password);
      if (result) {
        const [backupKey, walletMap] = result;
        let timestamp = backupKey.split('_')?.[2];
        console.log('timestamp', timestamp);
        timestamp = new Date(parseInt(timestamp)).toLocaleString();

        const outputText = JSON.stringify({backupDate: timestamp, backupKey: backupKey, wallets: walletMap}, null, 2);
        setRecoveryOutput(outputText);
        alert(`Successfully recovered from backup [${backupKey}], check the output below!`);
      } else {
        setRecoveryOutput('No valid backup found');
        alert('No valid backup found');
      }
    } catch (error) {
      console.error(error);
      setRecoveryOutput(`Error: ${error}`);
      alert('Failed to recover from backup: ' + error);
    } finally {
      setIsRecovering(false)
    }
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(recoveryOutput)
      .then(() => {
        setCopySuccess(true)
        setTimeout(() => setCopySuccess(false), 2000) // Reset after 2 seconds
      })
      .catch(err => {
        console.error('Failed to copy:', err)
        alert('Failed to copy to clipboard')
      })
  }

  return (
    <>
      <div>
        <a href="https://github.com/suiet/wallet-kit" target="_blank">
          <img src={suietLogo} className="logo" alt="Suiet logo" />
        </a>
      </div>
      <h1>Suiet Backup Recovery</h1>
      <p style={{ color: 'red', fontWeight: 'bold', maxWidth: '600px', margin: '0 auto' }}>
        ⚠️ CAUTION: Don't open this page from untrusted sources, only download from our <a href="https://github.com/suiet/recovery-tools" target="_blank">offical github repository</a>! ⚠️
      </p>
      <p style={{ color: 'red', fontWeight: 'bold', maxWidth: '600px', margin: '0 auto' }}>
        ⚠️ CAUTION: Don't share your backup data, password and mnemonic with anyone! ⚠️
      </p>
      <br />
      <p style={{ maxWidth: '600px', margin: '0 auto', fontWeight: 'bold' }}>How to get Suiet Backup JSON?</p>
      <p style={{ maxWidth: '600px', margin: '0 auto' }}>
        1. Open your Suiet wallet extesion, right click the Suiet Extension UI and select "Inspect" to open Developer Tools
      </p>
      <p style={{ maxWidth: '600px', margin: '0 auto' }}>
        2. Find outputs that contain "DB_BACKUP_..." (maybe folded as "Object"), right click besides the small toggle, and then select "Copy Object".
      </p>
      <p style={{ maxWidth: '600px', margin: '0 auto' }}>
        3. Paste the JSON data below, and input your password to start recovering.
      </p>
      <div className="card">
        <textarea 
          value={backupJson}
          onChange={(e) => setBackupJson(e.target.value)}
          placeholder="Suiet Backup JSON" 
          rows={10}
          style={{ width: '100%', minHeight: '200px', marginBottom: '10px' }}
        />
        <input 
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password" 
          style={{ marginBottom: '10px', width: '100%' }}
        />
        <button 
          onClick={() => handleRecover(backupJson, password)}
          style={{ 
            marginBottom: '10px', 
            width: '100%',
            opacity: isRecovering ? 0.7 : 1,
            cursor: isRecovering ? 'not-allowed' : 'pointer',
            color: isRecovering ? '#ccc' : 'inherit'
          }}
          disabled={isRecovering}
        >
          {isRecovering ? 'Recovering...' : 'Recover'}
        </button>
        <textarea 
          value={recoveryOutput}
          readOnly
          placeholder="Recovery output will appear here..."
          rows={10}
          style={{ 
            width: '100%', 
            minHeight: '200px',
            backgroundColor: '#f5f5f5',
            fontFamily: 'monospace',
            marginBottom: recoveryOutput ? '10px' : '0' // Add margin only when there's output
          }}
        />
        {recoveryOutput && (
          <button 
            onClick={handleCopy}
            style={{ 
              width: '100%',
              backgroundColor: copySuccess ? '#4CAF50' : undefined 
            }}
          >
            {copySuccess ? 'Copied!' : 'Copy Output'}
          </button>
        )}
      </div>
    </>
  )
}

export default App
