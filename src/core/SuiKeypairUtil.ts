import {
  ParsedKeypair,
  PRIVATE_KEY_SIZE,
  SIGNATURE_FLAG_TO_SCHEME,
  SUI_PRIVATE_KEY_PREFIX,
} from '@mysten/sui/cryptography';
import { bech32 } from 'bech32';
import { Buffer } from 'buffer';

const SIGNATURE_SCHEME_TO_FLAG = {
  ED25519: 0,
  Secp256k1: 1,
  Secp256r1: 2,
  MultiSig: 3,
  ZkLogin: 5,
};

export enum SignatureScheme {
  'ED25519' = 'ED25519',
}

export enum SupportedEncoding {
  BASE64 = 'base64',
  HEX = 'hex',
  BECH32 = 'bech32',
}

export function isBase64(input: string): boolean {
  // Base64 encoded strings only contain characters from the Base64 alphabet
  const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
  return base64Regex.test(input);
}

export function isHex(input: string): boolean {
  // Hex encoded strings only contain characters from the hexadecimal alphabet
  const hexRegex = /^[0-9a-fA-F]+$/;
  return hexRegex.test(input);
}

export function isSuiBech32(input: string): boolean {
  // Bech32 encoded strings only contain characters from the Bech32 alphabet
  const bech32Prefix = SUI_PRIVATE_KEY_PREFIX;
  return input.startsWith(bech32Prefix);
}



export class SuiKeypairUtil {
  static isSupportedEncoding(encoding: string) {
    return Object.values(SupportedEncoding).includes(
      encoding as SupportedEncoding
    );
  }
  static getSupportedEncodings() {
    return Object.values(SupportedEncoding);
  }

  static encodePrivateKey(
    privateKeyBuffer: Uint8Array,
    signatureScheme: SignatureScheme,
    encoding: string
  ): string {
    if (!SuiKeypairUtil.isSupportedEncoding(encoding)) {
      throw new Error(
        `Unsupported encoding: ${encoding}, valid encodings are: ${SuiKeypairUtil.getSupportedEncodings().join(
          ', '
        )}`
      );
    }

    if (encoding === SupportedEncoding.BECH32) {
      return SuiKeypairUtil.encodeSuiPrivateKeyInBech32(
        privateKeyBuffer,
        signatureScheme
      );
    } else if (encoding === SupportedEncoding.HEX) {
      return Buffer.from(privateKeyBuffer).toString('hex');
    } else if (encoding === SupportedEncoding.BASE64) {
      return Buffer.from(privateKeyBuffer).toString('base64');
    } else {
      throw new Error(`Unsupported encoding: ${encoding}`);
    }
  }

  static validateLengthOfSerializedPrivateKey(privateKeyStr: string) {
    if (privateKeyStr.startsWith('0x')) {
      privateKeyStr = privateKeyStr.slice(2);
    }

    const encoding = SuiKeypairUtil.detectSerializedPrivateKeyEncoding(
      privateKeyStr
    ) as SupportedEncoding;

    switch (encoding) {
      case SupportedEncoding.BECH32:
        return privateKeyStr.length === 70;
      case SupportedEncoding.HEX:
        return privateKeyStr.length === 64;
      default:
        return false;
    }
  }

  static decodePrivateKey(
    privateKeyStr: string,
    encoding?: string
  ): ParsedKeypair {
    if (privateKeyStr.startsWith('0x')) {
      privateKeyStr = privateKeyStr.slice(2);
    }

    if (!encoding) {
      // if encoding is not provided, try to detect it
      encoding = SuiKeypairUtil.detectSerializedPrivateKeyEncoding(
        privateKeyStr
      ) as SupportedEncoding;
    }

    let decodedPrivateKey: Uint8Array;

    if (encoding === SupportedEncoding.BECH32) {
      const parsedKey =
        SuiKeypairUtil.decodeSuiPrivateKeyInBech32(privateKeyStr);
      if (parsedKey.schema !== SignatureScheme.ED25519) {
        throw new Error(
          `Unsupported signature scheme: ${parsedKey.schema}, Suiet only supports ${SignatureScheme.ED25519} for now`
        );
      }
      decodedPrivateKey = parsedKey.secretKey;
    } else if (
      encoding === SupportedEncoding.HEX ||
      encoding === SupportedEncoding.BASE64
    ) {
      decodedPrivateKey = Buffer.from(privateKeyStr, encoding);
    } else {
      throw new Error(`Unsupported encoding: ${encoding}`);
    }

    return {
      schema: SignatureScheme.ED25519,
      secretKey: decodedPrivateKey,
    };
  }

  static detectSerializedPrivateKeyEncoding(serializedPrvKey: string) {
    if (!serializedPrvKey) {
      throw new Error('Required string input');
    }
    if (isSuiBech32(serializedPrvKey)) {
      return SupportedEncoding.BECH32;
    }
    // hex detection must be before base64 detection!
    if (isHex(serializedPrvKey)) {
      return SupportedEncoding.HEX;
    }
    if (isBase64(serializedPrvKey)) {
      return SupportedEncoding.BASE64;
    }
    throw new Error('Unsupported encoding');
  }

  /**
   * This returns an ParsedKeypair object based by validating the
   * 33-byte Bech32 encoded string starting with `suiprivkey`, and
   * parse out the signature scheme and the private key in bytes.
   */
  static decodeSuiPrivateKeyInBech32(value: string): ParsedKeypair {
    const { prefix, words } = bech32.decode(value);
    if (prefix !== SUI_PRIVATE_KEY_PREFIX) {
      throw new Error('invalid private key prefix');
    }
    const extendedSecretKey = new Uint8Array(bech32.fromWords(words));
    const secretKey = extendedSecretKey.slice(1);
    const signatureScheme =
      SIGNATURE_FLAG_TO_SCHEME[
        extendedSecretKey[0] as keyof typeof SIGNATURE_FLAG_TO_SCHEME
      ];
    return {
      schema: signatureScheme,
      secretKey: secretKey,
    };
  }

  /**
   * This returns a Bech32 encoded string starting with `suiprivkey`,
   * encoding 33-byte `flag || bytes` for the given the 32-byte private
   * key and its signature scheme.
   */
  static encodeSuiPrivateKeyInBech32(
    bytes: Uint8Array,
    scheme: SignatureScheme
  ): string {
    if (bytes.length !== PRIVATE_KEY_SIZE) {
      throw new Error('Invalid bytes length');
    }
    const flag = SIGNATURE_SCHEME_TO_FLAG[scheme];
    const privKeyBytes = new Uint8Array(bytes.length + 1);
    privKeyBytes.set([flag]);
    privKeyBytes.set(bytes, 1);
    return bech32.encode(SUI_PRIVATE_KEY_PREFIX, bech32.toWords(privKeyBytes));
  }
}
