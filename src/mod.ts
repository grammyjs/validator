import { hmacSha256, hmacSha256Hex, sha256 } from "./deps.deno.ts";

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

function compareHmac(
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
