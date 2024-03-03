import { hmacSha256, hmacSha256Hex, sha256 } from "./deps.deno.ts";

export type Payload = Record<string, string | number | undefined>;

const payloadKeys = ["id", "hash", "auth_date", "username", "last_name", "photo_url", "first_name"];

export function checkSignature(token: string, { hash, ...data }: Payload) {
  const secretKey = sha256(token);
  if (!hash) return false;
  return compareHmac(secretKey, `${hash}`, data);
}

/**
 * @param maxAge Maximum time in seconds passed since `auth_date` in order to
 * consider the `initData` valid. Use `0` to disable.
 */
export function validateWebAppData(token: string, initData: URLSearchParams, maxAge: number) {
  const secretKey = hmacSha256("WebAppData", token);
  const { hash, ...data } = Object.fromEntries(initData.entries());

  if (maxAge) {
    const authDate = Number(data.auth_date);
    if (isNaN(authDate)) return false;
    const age = (Date.now() / 1000) - authDate;
    if (age > maxAge) return false;
  }

  return compareHmac(secretKey, hash, data);
}

function compareHmac(secretKey: string | Uint8Array, hash: string, data: Payload) {
  const dataCheckString = Object.keys(data)
    // only the keys we care about and not undefined
    .filter((k) => payloadKeys.includes(k) && typeof data[k] !== "undefined")
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join("\n");

  return hash === hmacSha256Hex(secretKey, dataCheckString);
}
