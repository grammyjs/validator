import { hmac } from "https://deno.land/x/hmac@v2.0.1/mod.ts";

export { sha256 } from "https://denopkg.com/chiefbiiko/sha256@v2.0.0/mod.ts";

export function hmacSha256(key: string | Uint8Array, msg: string) {
    return hmac("sha256", key, msg);
}

export function hmacSha256Hex(key: string | Uint8Array, msg: string) {
    return hmac("sha256", key, msg, "utf8", "hex");
}
