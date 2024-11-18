import { Buffer } from "buffer";
import { ModeOfOperation } from 'aes-js';

import { wordlist as czWordlist } from '@scure/bip39/wordlists/czech';
import { wordlist as enWordlist } from '@scure/bip39/wordlists/english';
import { wordlist as frWordlist } from '@scure/bip39/wordlists/french';
import { wordlist as itWordlist } from '@scure/bip39/wordlists/italian';
import { wordlist as jpWordlist } from '@scure/bip39/wordlists/japanese';
import { wordlist as krWordlist } from '@scure/bip39/wordlists/korean';
import { wordlist as szhWordlist } from '@scure/bip39/wordlists/simplified-chinese';
import { wordlist as spWordlist } from '@scure/bip39/wordlists/spanish';
import { wordlist as tzhWordlist } from '@scure/bip39/wordlists/traditional-chinese';
import * as bip39 from '@scure/bip39';
import elliptic from 'elliptic';

export const BIP32_ALL_WORDLISTS = [
  czWordlist,
  enWordlist,
  frWordlist,
  itWordlist,
  jpWordlist,
  krWordlist,
  szhWordlist,
  spWordlist,
  tzhWordlist,
];

export function validateMnemonic(mnemonic: string): boolean {
  for (const wl of BIP32_ALL_WORDLISTS) {
    if (bip39.validateMnemonic(mnemonic, wl)) {
      return true;
    }
  }

  return false;
}

export function decryptMnemonic(
  token: Buffer,
  encryptedMnemonic: string
): string {
  const aesCtr = new ModeOfOperation.ctr(token);
  const encryptedBytes = Buffer.from(encryptedMnemonic, 'hex');
  const mnemonicBytes = aesCtr.decrypt(encryptedBytes);
  const mnemonic = new TextDecoder().decode(mnemonicBytes);
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid password');
  }
  return mnemonic;
}

export function decryptPrivateKey(
  token: Buffer,
  encryptedPrivate: string
): elliptic.eddsa.KeyPair {
  const aesCtr = new ModeOfOperation.ctr(token);
  const encryptedBytes = Buffer.from(encryptedPrivate, 'hex');
  const privateBytes = aesCtr.decrypt(encryptedBytes);
  let keyPair;
  try {
    keyPair = new elliptic.eddsa('ed25519').keyFromSecret(
      Buffer.from(privateBytes)
    );
  } catch (e) {
    throw new Error('Invalid password');
  }
  return keyPair;
}