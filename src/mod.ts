import { hmacSha256, hmacSha256Hex, sha256, hmacSha256Async, hmacSha256AsyncHex, sha256Async } from "./deps.deno.ts";

export function checkSignature(
    token: string,
    { hash, ...data }: Record<string, string>,
) {
    const secretKey = sha256(token);
    return compareHmac(secretKey, hash, data);
}

export function validateWebAppData(token: string, initData: URLSearchParams) {
    const secretKey = hmacSha256("WebAppData", token);
    const { hash, ...data } = Object.fromEntries(initData.entries());
    return compareHmac(secretKey, hash, data);
}

function compareHmac (
    secretKey: string | Uint8Array,
    hash: string,
    data: Record<string, string>,
) {
    const dataCheckString = Object.keys(data)
        .sort()
        .map((k) => `${k}=${data[k]}`)
        .join("\n");
    return hash === hmacSha256Hex(secretKey, dataCheckString);
}

export async function checkSignatureAsync (
    token: string,
    { hash, ...data }: Record<string, string>,
) {
    const secretKey = await sha256Async(token)
    return compareHmacAsync(secretKey, hash, data)
}

export async function validateWebAppDataAsync (token: string, initData: URLSearchParams) {
    const secretKey = await hmacSha256Async("WebAppData", token)
    const { hash, ...data } = Object.fromEntries(initData.entries())
    return compareHmacAsync(secretKey, hash, data)
}

async function compareHmacAsync (
    secretKey: string | Uint8Array,
    hash: string,
    data: Record<string, string>,
) {
    const dataCheckString = Object.keys(data)
        .sort()
        .map((k) => `${k}=${data[k]}`)
        .join("\n")
    return hash === await hmacSha256AsyncHex(secretKey, dataCheckString)
}
