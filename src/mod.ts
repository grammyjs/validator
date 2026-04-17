import { hmacSha256, hmacSha256Hex, sha256 } from "./deps.deno.ts";

export type Payload = Record<string, string | number | undefined>;

const payloadKeys = [
    "id",
    "hash",
    "auth_date",
    "username",
    "last_name",
    "photo_url",
    "first_name",
];

export function checkSignature(token: string, { hash, ...data }: Payload) {
    const secretKey = sha256(token);
    if (!hash) return false;
    return compareHmac(secretKey, `${hash}`, data);
}

export function validateWebAppData(token: string, initData: URLSearchParams) {
    const secretKey = hmacSha256("WebAppData", token);
    const { hash, ...data } = Object.fromEntries(initData.entries());
    return compareHmac(secretKey, hash, data);
}

function compareHmac(
    secretKey: string | Uint8Array,
    hash: string,
    data: Payload,
) {
    const dataCheckString = Object.keys(data)
        // only the keys we care about and not undefined
        .filter((k) =>
            payloadKeys.includes(k) && typeof data[k] !== "undefined"
        )
        .sort()
        .map((k) => `${k}=${data[k]}`)
        .join("\n");

    return hash === hmacSha256Hex(secretKey, dataCheckString);
}

// === Third-party Mini App initData validation (Ed25519) ===
// https://core.telegram.org/bots/webapps#validating-data-for-third-party-use

/** Telegram's Ed25519 public key for the production environment (raw, hex). */
export const TELEGRAM_PUBLIC_KEY_PRODUCTION =
    "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d";

/** Telegram's Ed25519 public key for the test environment (raw, hex). */
export const TELEGRAM_PUBLIC_KEY_TEST =
    "40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec";

/**
 * Validates Mini App `initData` for third-party use, without the bot token.
 *
 * Telegram signs `initData` with Ed25519 using an environment-wide keypair, so
 * any third party that knows the bot's numeric id and Telegram's public key can
 * verify the data. This is the algorithm described at
 * https://core.telegram.org/bots/webapps#validating-data-for-third-party-use.
 *
 * Returns `true` when the signature is valid and the data originated from
 * Telegram. Returns `false` when the signature is missing or invalid. Does not
 * check `auth_date` freshness — the caller should compare it against the
 * current time to reject stale data.
 *
 * @param botId Numeric identifier of the bot (the one from `initDataUnsafe.bot?.id` or the token prefix)
 * @param initData Parsed `Telegram.WebApp.initData` query string
 * @param options.test Set to `true` to validate data from the test environment
 */
export async function validateThirdPartyWebAppData(
    botId: number | string,
    initData: URLSearchParams,
    options: { test?: boolean } = {},
): Promise<boolean> {
    const signature = initData.get("signature");
    if (!signature) return false;

    const dataCheckString = [`${botId}:WebAppData`]
        .concat(
            [...initData.entries()]
                .filter(([k]) => k !== "hash" && k !== "signature")
                .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
                .map(([k, v]) => `${k}=${v}`),
        )
        .join("\n");

    const publicKeyHex = options.test
        ? TELEGRAM_PUBLIC_KEY_TEST
        : TELEGRAM_PUBLIC_KEY_PRODUCTION;

    const key = await crypto.subtle.importKey(
        "raw",
        hexToBytes(publicKeyHex),
        { name: "Ed25519" },
        false,
        ["verify"],
    );
    try {
        return await crypto.subtle.verify(
            "Ed25519",
            key,
            base64UrlDecode(signature),
            new TextEncoder().encode(dataCheckString),
        );
    } catch {
        // Malformed base64url in `signature`, etc.
        return false;
    }
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function base64UrlDecode(s: string): Uint8Array<ArrayBuffer> {
    const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad));
    const bytes = new Uint8Array(new ArrayBuffer(bin.length));
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}
