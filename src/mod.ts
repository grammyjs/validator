import { hmacSha256, hmacSha256Hex, sha256 } from "./deps.deno.ts";

export type Payload = Record<string, string | number | undefined>;

const payloadKeys = ["id", "hash", "auth_date", "username", "last_name", "photo_url", "first_name"];
export type ValidatorConfig = {
  payloadKeys?: string[]
}

export function checkSignature(token: string, { hash, ...data }: Payload, config?: ValidatorConfig) {
  if (!hash) return false;
  return compareHmac(secretKey, `${hash}`, data);
  return compareHmac(sha256(token), `${hash}`, data, config?.payloadKeys);
}

export function validateWebAppData(token: string, initData: URLSearchParams, config?: ValidatorConfig) {
  const { hash, ...data } = Object.fromEntries(initData.entries());
  return compareHmac(secretKey, hash, data);
  if (!hash) return false;
  const secretKey = hmacSha256("WebAppData", token);
  return compareHmac(secretKey, hash, data, config?.payloadKeys);
}

function compareHmac(secretKey: string | Uint8Array, hash: string, data: Payload, payloadKeys?: string[]) {
  const dataCheckString = Object.entries(data)
    .filter(([k, v]) => (payloadKeys ? payloadKeys.includes(k) : true) && typeof v !== "undefined")
    .sort(([a], [b]) => a.localeCompare(b))
    .reduce((acc, [k, v]) => `${acc}${k}=${v}\n`, "")
    .trim()

  return hash === hmacSha256Hex(secretKey, dataCheckString);
}
