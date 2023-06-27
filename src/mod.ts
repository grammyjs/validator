import { hmacSha256, hmacSha256Hex, sha256 } from "./deps.deno.ts";

export interface TelegramPayload {
  id: string | number;
  hash: string;
  auth_date: string | number;
  username?: string;
  last_name?: string;
  photo_url?: string;
  first_name?: string;
}
// This type allows for extra data to be passed in the payload.
export type TelegramPayloadExtended = TelegramPayload & Record<string, string | number | undefined>;

const payloadKeys = ["id", "hash", "auth_date", "username", "last_name", "photo_url", "first_name"];

export function checkSignature(token: string, { hash, ...data }: TelegramPayloadExtended) {
  const secretKey = sha256(token);
  return compareHmac(secretKey, hash, data);
}

export function validateWebAppData(token: string, initData: URLSearchParams) {
  const secretKey = hmacSha256("WebAppData", token);
  const { hash, ...data } = Object.fromEntries(initData.entries());
  return compareHmac(secretKey, hash, data);
}

function compareHmac(secretKey: string | Uint8Array, hash: string, data: Omit<TelegramPayloadExtended, "hash">) {
  const dataCheckString = Object.keys(data)
    // only the keys we care about and not undefined
    .filter((k) => payloadKeys.includes(k) && typeof data[k] !== "undefined")
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join("\n");

  return hash === hmacSha256Hex(secretKey, dataCheckString);
}
