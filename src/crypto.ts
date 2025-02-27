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
    const buff = Buffer.from(base64, "base64");
    return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

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
        true,
        ["encrypt", "decrypt"]
    );
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
    const exported = await webcrypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(exported);
}

export async function exportPrvKey(key: webcrypto.CryptoKey): Promise<string> {
    const exported = await webcrypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToBase64(exported);
}

export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const keyBuffer = base64ToArrayBuffer(strKey);
    return webcrypto.subtle.importKey(
        "spki",
        keyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );
}

export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const keyBuffer = base64ToArrayBuffer(strKey);
    return webcrypto.subtle.importKey(
        "pkcs8",
        keyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );
}

export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
    const publicKey = await importPubKey(strPublicKey);
    const encrypted = await webcrypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        new TextEncoder().encode(atob(b64Data))
    );
    return arrayBufferToBase64(encrypted);
}

export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
    const decrypted = await webcrypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        base64ToArrayBuffer(data)
    );
    return new TextDecoder().decode(decrypted);
}

// ######################
// ### Symmetric keys ###
// ######################

export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
    return await webcrypto.subtle.generateKey(
        { name: "AES-CBC", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
    const exported = await webcrypto.subtle.exportKey("raw", key);
    return arrayBufferToBase64(exported);
}

export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const keyBuffer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey("raw", keyBuffer, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
}

export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
    const iv = webcrypto.getRandomValues(new Uint8Array(16)); // Generate a 16-byte IV
    const encrypted = await webcrypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        key,
        new TextEncoder().encode(data)
    );
    return `${arrayBufferToBase64(iv)}.${arrayBufferToBase64(encrypted)}`;
}

export async function symDecrypt(key: webcrypto.CryptoKey, encryptedData: string): Promise<string> {
    if (!encryptedData) {
        throw new Error("The encrypted data is undefined or empty." + encryptedData);
    }

    const [ivBase64, encryptedBase64] = encryptedData.split(".");
    if (!ivBase64 || !encryptedBase64) {
        throw new Error("The encrypted data format is invalid." + encryptedData);
    }

    const iv = base64ToArrayBuffer(ivBase64);
    const encryptedBuffer = base64ToArrayBuffer(encryptedBase64);
    const decrypted = await webcrypto.subtle.decrypt(
        { name: "AES-CBC", iv: new Uint8Array(iv) },
        key,
        encryptedBuffer
    );
    return new TextDecoder().decode(decrypted);
}