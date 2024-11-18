export type NextWalletsIDs = {
  software: { nextWalletId: number };
  ledger: { nextWalletId: number };
  onekey: { nextWalletId: number };
  keystone: { nextWalletId: number };
  social: { nextWalletId: number };
};

export type GlobalMeta = {
  nextWalletsIds: NextWalletsIDs;
  cipher: Cipher;
  clientId?: string;
  biometricData?: BiometricData;
  dataVersion: number;
  tokenVersion?: number;
};

export type BiometricData = {
  credentialIdBase64: string;
  publicKeyBase64: string;
  encryptedToken: string;
};

export type Cipher = {
  data: string;
  salt: string;
};

export type Wallet = {
  id: string;
  name: string;
  type: string;
  accounts: AccountInWallet[];
  nextAccountId: number;
  avatar?: string;
  encryptedMnemonic?: string;
  avatarPfp?: AvatarPfp;
  isImported: boolean;
  hardwareInfo?: HardwareInfo;
};
export type AccountInWallet = {
  id: string;
  address: string;
};
export type AvatarPfp = {
  objectId: string;
  name: string;
  uri: string;
  mime: string;
  expiresAt: number;
};
export type HardwareInfo = {
  hardwareDeviceId: string;
  hardwareDeviceName: string;
  xfp?: string;
};
export type Account = {
  id: string;
  name: string;
  pubkey: string;
  address: string;
  hdPath?: string;
  encryptedPrivateKey?: string;
};

export type SuietBackup = {
  meta: GlobalMeta;
  wallets: Wallet[];
  accounts: Account[];
}