# Suiet Wallet Recovery Tool

A secure offline tool to recover your Suiet wallet data from backup. This tool helps you extract your wallet's mnemonic phrases and private keys from an encrypted backup.

## ⚠️ Security Warnings

1. **ONLY download the tool from our official GitHub releases**
   - Go to [Releases](https://github.com/suiet/recovery-tools/releases)
   - Download `suiet-recovery-tool.zip` from the latest release
   - Do NOT trust any other sources

2. **Use the tool OFFLINE**
   - Disconnect your internet before using the tool
   - Your sensitive data should never leave your computer

## How to Use

1. **Download and Extract**
   - Download `suiet-recovery-tool.zip` from GitHub releases
   - Extract the ZIP file to a folder

2. **Open the Tool**
   - Recommended: Use VSCode with "Live Server" extension
     1. Install [VSCode](https://code.visualstudio.com/)
     2. Install [Live Server extension](https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer)
     3. Open the extracted folder in VSCode
     4. Right-click `index.html` and select "Open with Live Server"
   
   - Alternative: Use any local HTTP server
     - Python: `python -m http.server`
     - Node.js: `npx serve`
     - DO NOT open the HTML file directly (it won't work due to browser security)

3. **Get Your Backup Data**
   1. Open your Suiet wallet extension
   2. Right-click and select "Inspect" to open Developer Tools
   3. Find outputs containing "DB_BACKUP_..."
   4. Right-click and select "Copy Object"

4. **Recover Your Wallet**
   1. **DISCONNECT YOUR INTERNET**
   2. Paste the backup data into the tool
   3. Enter your wallet password
   4. Click "Recover"
   5. Save the recovered data securely
   6. Close the tool

## Support

- Join our [Discord](https://discord.gg/KU3cR4zR)
- Report issues on [GitHub](https://github.com/suiet/recovery-tools/issues)

## Development

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev

# Build for production
pnpm build
```

## License

MIT
