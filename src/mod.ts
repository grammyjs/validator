import { hmacSha256, hmacSha256Hex, sha256 } from "./deps.deno.ts";

export interface AuthData {
    hash: string;
    [key: string]: string;
}

export function checkSignature(token: string, authData: AuthData) {
    const secretKey = sha256(token);
    return compareHmac(secretKey, authData);
}

export function validateWebAppData(token: string, authData: AuthData) {
    const secretKey = hmacSha256(token, "WebAppData");
    return compareHmac(secretKey, authData);
}

function compareHmac(
    secretKey: string | Uint8Array,
    { hash, ...data }: AuthData,
) {
    const dataCheckString = Object.keys(data)
        .sort()
        .map((k) => `${k}=${data[k]}`)
        .join("\n");
    return hash === hmacSha256Hex(secretKey, dataCheckString);
}
