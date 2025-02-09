import { hmacSha256, hmacSha256Hex, sha256 } from "./deps.deno.ts";

export type Payload = Record<string, string | number | undefined>;

export type ValidatorConfig = {
  payloadKeys?: string[]
  maxAge?: number
}

export function checkSignature(token: string, { hash, ...data }: Payload, config?: ValidatorConfig) {
  if (!hash) return false;

  if (!compareAge(data, config)) return false;

  return compareHmac(sha256(token), `${hash}`, data, config?.payloadKeys);
}

export function validateWebAppData(token: string, initData: URLSearchParams, config?: ValidatorConfig) {
  const { hash, ...data } = Object.fromEntries(initData.entries());
  if (!hash) return false;

  if (!compareAge(data, config)) return false;

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

function compareAge(data: Payload, config?: ValidatorConfig) {
  if (!config?.maxAge) return true;

  const authDate = Number(data.auth_date);
  if (!authDate || isNaN(authDate)) return false;

  const age = (Date.now() / 1000) - authDate;
  return age <= config.maxAge;
}
