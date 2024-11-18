import { useState } from "react";
import "./App.css";
import { Buffer } from "buffer";
import { GlobalMeta, SuietBackup, TokenTool } from "./core";
import { decryptMnemonic, decryptPrivateKey } from "./core/crypto";
import { SignatureScheme, SupportedEncoding } from "./core/SuiKeypairUtil";
import { SuiKeypairUtil } from "./core/SuiKeypairUtil";
import suietLogo from "./assets/suiet-logo.svg";

async function validateToken(
  token: Buffer,
  meta: GlobalMeta
): Promise<boolean> {
  if (!token || !meta) {
    return false;
  }

  if (!TokenTool.validateToken(token, meta.cipher)) {
    return false;
  }
  return true;
}

interface RecoveryResult {
  backupKey: string;
  backupDate: string;
  wallets: Record<string, any>;
}

function App() {
  const [backupJson, setBackupJson] = useState("");
  const [password, setPassword] = useState("");
  const [recoveryResults, setRecoveryResults] = useState<RecoveryResult[]>([]);
  const [copySuccess, setCopySuccess] = useState<Record<string, boolean>>({});
  const [isRecovering, setIsRecovering] = useState(false);

  const extractDbBackupFromBackupJson = (backupJson: Record<string, any>) => {
    const backupDataMap: Record<string, SuietBackup> = {};
    for (const key of Object.keys(backupJson)) {
      if (key.startsWith("DB_BACKUP_")) {
        try {
          backupDataMap[key] = JSON.parse(backupJson[key]) as SuietBackup;
        } catch (error) {
          console.error(`Failed to parse backup [${key}], ignore it. `, error);
        }
      }
    }
    if (Object.keys(backupDataMap).length === 0) {
      throw new Error("No db backup found from backup JSON");
    }
    return backupDataMap;
  };

  const recoverWalletDataFromOneBackup = async (
    backup: SuietBackup,
    password: string
  ) => {
    const meta = backup.meta;
    if (!meta) {
      throw new Error("No recovery metadata found from backup");
    }
    if (!backup.wallets || backup.wallets.length === 0) {
      throw new Error("No wallets found from backup");
    }
    if (!backup.accounts || backup.accounts.length === 0) {
      throw new Error("No accounts found from backup");
    }
    const token = TokenTool.loadTokenWithPassword(meta, password);
    let isValid = await validateToken(token, meta);
    if (!isValid) {
      throw new Error("Invalid token");
    }

    const walletMap: Record<string, any> = {};
    for (const wallet of backup.wallets) {
      let mnemonic: string | null = null;
      if (wallet.encryptedMnemonic) {
        mnemonic = decryptMnemonic(token, wallet.encryptedMnemonic);
      } else {
        console.warn(
          `[wallet ${wallet.id}]: no encrypted mnemonic`
        );
      }

      const accounts: Record<string, any> = {};
      for (const account of backup.accounts) {
        const walletId = account.id.split("--")[0];
        if (walletId !== wallet.id) {
          continue;
        }
        let privateKey: string | null = null;
        let hdPath: string | null = null;

        if (wallet.isImported) {
          if (account.encryptedPrivateKey) {
            const keyPair = decryptPrivateKey(
              token,
              account.encryptedPrivateKey
            );
            if (keyPair) {
              privateKey = SuiKeypairUtil.encodePrivateKey(
                keyPair.getSecret(),
                SignatureScheme.ED25519,
                SupportedEncoding.BECH32
              );
            } else {
              console.warn(
                `[account ${account.id}]: invalid private key`
              );
            }
          } else {
            console.warn(
              `[account ${account.id}]: no encrypted private key`
            );
          }
        }

        if (account.hdPath) {
          hdPath = account.hdPath;
        }

        accounts[account.id] = {
          privateKey: privateKey,
          address: account.address,
          hdPath: hdPath,
        };
      }

      walletMap[wallet.id] = {
        name: wallet.name,
        type: wallet.type,
        mnemonic: mnemonic,
        accounts: accounts,
      };
    }
    return walletMap;
  };

  const handleCopy = (backupKey: string, content: string) => {
    navigator.clipboard.writeText(content)
      .then(() => {
        setCopySuccess(prev => ({ ...prev, [backupKey]: true }))
        setTimeout(() => {
          setCopySuccess(prev => ({ ...prev, [backupKey]: false }))
        }, 2000)
      })
      .catch(err => {
        console.error('Failed to copy:', err)
        alert('Failed to copy to clipboard')
      })
  }

  const handleRecover = async (dbBackupJson: string, password: string) => {
    try {
      setIsRecovering(true)
      setRecoveryResults([])
      const backup = JSON.parse(dbBackupJson) as SuietBackup
      const dbBackupMap = extractDbBackupFromBackupJson(backup)
      
      const results: RecoveryResult[] = []
      
      // Sort backup keys by date (newest first)
      const dbBackupKeys = Object.keys(dbBackupMap).sort((a, b) => b.localeCompare(a))
      
      for (const key of dbBackupKeys) {
        try {
          const walletMap = await recoverWalletDataFromOneBackup(dbBackupMap[key], password)
          let timestamp = key.split('_')?.[2]
          const date = new Date(parseInt(timestamp)).toLocaleString()
          
          results.push({
            backupKey: key,
            backupDate: date,
            wallets: walletMap
          })
          
          console.log(`Successfully recovered from backup [${key}]:`, walletMap)
        } catch (error) {
          console.error(`Failed to recover from backup [${key}]: `, error)
          // Continue to next backup even if this one fails
        }
      }
      
      if (results.length > 0) {
        setRecoveryResults(results)
        alert(`Successfully recovered ${results.length} backups! Check the output below.`)
      } else {
        alert('No valid backups found')
      }
    } catch (error) {
      console.error(error)
      alert('Failed to recover from backup: ' + error)
    } finally {
      setIsRecovering(false)
    }
  }

  return (
    <>
      <div>
        <a href="https://github.com/suiet/wallet-kit" target="_blank">
          <img
            src={suietLogo}
            className="logo"
            alt="Suiet logo"
            style={{ padding: "12px 0" }}
          />
        </a>
      </div>
      <h1 style={{ margin: "12px auto" }}>Suiet Backup Recovery</h1>
      <section
        style={{
          maxWidth: "1200px",
          margin: "0 auto",
          padding: "10px",
          border: "2px solid red",
          borderRadius: "4px",
        }}
      >
        <p style={{ color: "red", fontWeight: "bold" }}>
          ⚠️ CAUTION: Don't open this page from untrusted sources, only download
          from our{" "}
          <a href="https://github.com/suiet/recovery-tools" target="_blank">
            offical github repository
          </a>
          !
        </p>
        <p
          style={{
            color: "red",
            fontWeight: "bold",
          }}
        >
          ⚠️ CAUTION: Don't share your backup data, password and mnemonic with
          anyone!
        </p>
      </section>
      <br />
      <p style={{ maxWidth: "600px", margin: "0 auto", fontWeight: "bold" }}>
        How to recover your wallet data?
      </p>
      <p style={{ maxWidth: "600px", margin: "0 auto" }}>
        1. Open your Suiet wallet extesion, right click the Suiet Extension UI
        and select "Inspect" to open Developer Tools, then choose "Console" tab.
      </p>
      <p style={{ maxWidth: "600px", margin: "0 auto" }}>
        2. Manually type (paste wouldn't work) the command at the bottom of the console and press Enter:
        <br/>
        <code style={{ fontWeight: "bold" , backgroundColor: "#f5f5f5"}}>await chrome.storage.local.get()</code>
        <br/>
        then right click the output and select "Copy Object", paste the JSON data below.
      </p>
      <p
        style={{
          maxWidth: "600px",
          margin: "0 auto",
          color: "red",
          fontWeight: "bold",
          backgroundColor: "#ffebee",
        }}
      >
        3. ⚠️ TURN OFF YOUR NETWORK CONNECTION!!! The recovery must be done
        offline for security!
      </p>
      <p style={{ maxWidth: "600px", margin: "0 auto" }}>
        4. Input your PASSWORD to start recovering. The recovery result will be
        shown below.
      </p>
      <p style={{ 
        maxWidth: "600px", 
        margin: "0 auto",
        color: "red",
        fontWeight: "bold",
        backgroundColor: "#ffebee",
      }}>
        5. ⚠️ Save your recovered wallet data to a ABSOLUTELY SAFE place, then CLOSE this page!
        You can import the wallet data to a new Suiet wallet extension later.
      </p>
      <p style={{ maxWidth: "600px", margin: "0 auto" }}>
        6. If you have any questions, please contact us via{" "}
        <a href="https://discord.gg/KU3cR4zR" target="_blank">
          Discord
        </a>{" "}
        or{" "}
        <a
          href="https://github.com/suiet/recovery-tools/issues"
          target="_blank"
        >
          Github Issue
        </a>
        .
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
            cursor: isRecovering ? 'not-allowed' : 'pointer'
          }}
          disabled={isRecovering}
        >
          {isRecovering ? 'Recovering...' : 'Recover'}
        </button>

        {recoveryResults.map((result, index) => (
          <div 
            key={result.backupKey}
            style={{ 
              marginBottom: '20px',
              padding: '10px',
              border: '1px solid #ccc',
              borderRadius: '4px'
            }}
          >
            <h3 style={{ margin: '0 0 10px 0' }}>
              Backup #{index + 1} - {result.backupDate}
            </h3>
            <textarea 
              value={JSON.stringify(result, null, 2)}
              readOnly
              rows={10}
              style={{ 
                width: '100%', 
                minHeight: '200px',
                backgroundColor: '#f5f5f5',
                fontFamily: 'monospace',
                marginBottom: '10px'
              }}
            />
            <button 
              onClick={() => handleCopy(result.backupKey, JSON.stringify(result, null, 2))}
              style={{ 
                width: '100%',
                backgroundColor: copySuccess[result.backupKey] ? '#4CAF50' : undefined 
              }}
            >
              {copySuccess[result.backupKey] ? 'Copied!' : 'Copy Output'}
            </button>
          </div>
        ))}
      </div>
    </>
  )
}

export default App;
