export type Payload = Record<string, string | number | undefined>;

const enc = new TextEncoder();
const WEB_APP_DATA = enc.encode("WebAppData");

export async function checkSignature(
    token: string,
    { hash, ...data }: Payload,
) {
    const secretKey = await sha256(token);
    if (!hash) return false;
    return compareHmac(secretKey, `${hash}`, data);
}

export async function validateWebAppData(
    token: string,
    initData: URLSearchParams,
) {
    const secretKey = await hmacSha256(WEB_APP_DATA, token);
    const { hash, ...data } = Object.fromEntries(initData.entries());
    return compareHmac(secretKey, hash, data);
}

async function compareHmac(secretKey: Uint8Array, hash: string, data: Payload) {
    const dataCheckString = Object.keys(data)
        .filter((k) => typeof data[k] !== "undefined")
        .sort()
        .map((k) => `${k}=${data[k]}`)
        .join("\n");

    const expected = hexToBytes(hash);
    return compareHashes(
        expected,
        await hmacSha256(secretKey, dataCheckString),
    );
}

async function sha256(payload: string) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        enc.encode(payload),
    );
    return new Uint8Array(digest);
}

async function hmacSha256(key: Uint8Array, msg: string) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        new Uint8Array(key),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const signature = await crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        enc.encode(msg),
    );
    return new Uint8Array(signature);
}

/** timing-safe byte array equality */
function compareHashes(expected: Uint8Array, actual: Uint8Array) {
    if (expected.length !== actual.length) {
        return false;
    }
    let hasDifference = 0;
    // always iterate all bytes
    for (let i = 0; i < actual.length; i++) {
        hasDifference |= expected[i] ^ actual[i];
    }
    return hasDifference === 0;
}

/** convert hex string to Uint8Array */
function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 != 0) return new Uint8Array(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Number.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
