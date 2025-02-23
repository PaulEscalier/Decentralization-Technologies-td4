import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // extractable
      ["encrypt", "decrypt"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey('spki', key);
  return arrayBufferToBase64(exported);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
    key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!key) return null;
  const exported = await webcrypto.subtle.exportKey('pkcs8', key);
  return arrayBufferToBase64(exported);
}

// Import a base64 string public key to its native format
export async function importPubKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
      'spki',
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
  );
}

// Import a base64 string private key to its native format
export async function importPrvKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
      'pkcs8',
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["decrypt"]
  );
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
    b64Data: string,
    strPublicKey: string
): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const dataBuffer = base64ToArrayBuffer(b64Data);
  const encryptedBuffer = await webcrypto.subtle.encrypt(
      {
        name: "RSA-OAEP"
      },
      publicKey,
      dataBuffer
  );
  return arrayBufferToBase64(encryptedBuffer);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
    data: string,
    privateKey: webcrypto.CryptoKey
): Promise<string> {
  const encryptedBuffer = base64ToArrayBuffer(data);
  const decryptedBuffer = await webcrypto.subtle.decrypt(
      {
        name: "RSA-OAEP"
      },
      privateKey,
      encryptedBuffer
  );
  return new TextDecoder().decode(decryptedBuffer);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256
      },
      true, // extractable
      ["encrypt", "decrypt"]
  );
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(exported);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
      'raw',
      keyBuffer,
      {
        name: "AES-GCM"
      },
      true,
      ["encrypt", "decrypt"]
  );
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
    key: webcrypto.CryptoKey,
    data: string
): Promise<string> {
  const encodedData = new TextEncoder().encode(data);
  const iv = webcrypto.getRandomValues(new Uint8Array(12)); // AES-GCM requires a 12-byte IV
  const encryptedBuffer = await webcrypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      key,
      encodedData
  );
  const combinedBuffer = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combinedBuffer.set(iv, 0);
  combinedBuffer.set(new Uint8Array(encryptedBuffer), iv.length);
  return arrayBufferToBase64(combinedBuffer.buffer);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
    key: webcrypto.CryptoKey,
    encryptedData: string
): Promise<string> {
  const encryptedBuffer = base64ToArrayBuffer(encryptedData);
  const iv = new Uint8Array(encryptedBuffer.slice(0, 12));
  const dataBuffer = encryptedBuffer.slice(12);
  const decryptedBuffer = await webcrypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      key,
      dataBuffer
  );
  return new TextDecoder().decode(decryptedBuffer);
}