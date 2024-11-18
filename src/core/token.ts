import randomBytes from 'randombytes';
import { Buffer } from 'buffer';
import { ModeOfOperation } from 'aes-js';
import CryptoJS from 'crypto-js';
import { Cipher, GlobalMeta } from './types';
import { Sha256, Pbkdf2HmacSha256 } from 'asmcrypto.js';

const PBKDF2_NUM_OF_ITERATIONS = 600_000;
const PBKDF2_NUM_OF_ITERATIONS_LEGACY = 5000;
const PBKDF2_KEY_LENGTH = 32;
const WALLET_MASTER_SECRET = 'suiet wallet';

export type Token = {
  token: Buffer;
  cipher: Cipher;
};

export class TokenTool {
  static validateToken(token: Uint8Array, cipher: Cipher): boolean {
    const aesCtr = new ModeOfOperation.ctr(Buffer.from(token));
    const data = Buffer.from(cipher.data, 'hex');
    const secretBytes = aesCtr.decrypt(data);
    const secret = new TextDecoder().decode(secretBytes);
    return secret === WALLET_MASTER_SECRET;
  }

  static uint8ArrayToWordArray(u8Array: Uint8Array) {
    const words = [];
    let i = 0;
    const len = u8Array.length;

    while (i < len) {
      words.push(
        (u8Array[i++] << 24) |
          (u8Array[i++] << 16) |
          (u8Array[i++] << 8) |
          u8Array[i++]
      );
    }

    return CryptoJS.lib.WordArray.create(words, len);
  }

  static wordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray) {
    return new Uint8Array(
      wordArray.words
        .map((word) => [
          (word >> 24) & 0xff,
          (word >> 16) & 0xff,
          (word >> 8) & 0xff,
          word & 0xff,
        ])
        .flat()
    );
  }

  static password2Token(
    password: string,
    salt: Uint8Array,
  ) {
    const hash = new Sha256().process(Buffer.from(password, 'utf8')).finish()
    .result as Uint8Array;
  return Buffer.from(
    Pbkdf2HmacSha256(hash, salt, PBKDF2_NUM_OF_ITERATIONS, PBKDF2_KEY_LENGTH)
  );
  }

  static password2TokenLegacy(password: string, salt: Uint8Array) {
    const hash = new Sha256().process(Buffer.from(password, 'utf8')).finish()
    .result as Uint8Array;
  return Buffer.from(
    Pbkdf2HmacSha256(
      hash,
      salt,
      PBKDF2_NUM_OF_ITERATIONS_LEGACY,
      PBKDF2_KEY_LENGTH
    )
  );
  }

  static createToken(password: string): Token {
    const salt = randomBytes(32); 
    const token = TokenTool.password2Token(password, salt);
    const aesCtr = new ModeOfOperation.ctr(token);
    const secretBytes = new TextEncoder().encode(WALLET_MASTER_SECRET);
    return {
      token,
      cipher: {
        data: Buffer.from(aesCtr.encrypt(secretBytes)).toString('hex'),
        salt: salt.toString('hex'),
      },
    };
  }

  public static loadTokenWithPassword(meta: GlobalMeta, password: string): Buffer {
    if (!meta) {
      throw new Error('No metadata found');
    }
    const t = Date.now();
    const salt = Buffer.from(meta.cipher.salt, 'hex');
    if (!meta.tokenVersion) {
      // Update token with new iteration.
      const tokenLegacy = TokenTool.password2TokenLegacy(password, salt);
      if (!TokenTool.validateToken(tokenLegacy, meta.cipher)) {
        throw new Error('Invalid password');
      }
      const { token, cipher } = TokenTool.createToken(password);
      meta.cipher = cipher;
      meta.tokenVersion = 1;
      return token;
    } else if (meta.tokenVersion !== 1) {
      throw new Error('DataCorruptedError: Unsupported token version');
    }
    const token = TokenTool.password2Token(password, salt);
    console.log('password2Token', Date.now() - t);
    if (!TokenTool.validateToken(token, meta.cipher)) {
      throw new Error('Invalid password');
    }
    console.log('validateToken', Date.now() - t);
    return token;
  }
}
