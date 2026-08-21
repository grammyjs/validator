export type Payload = Record<string, string | number | undefined>;

export interface ValidationOptions {
    maxAgeSeconds?: number;
}

export interface ThirdPartyValidationOptions extends ValidationOptions {
    environment?: "prod" | "test";
}

const enc = new TextEncoder();
const WEB_APP_DATA = enc.encode("WebAppData");
const SHA256_HEX = /^[0-9a-f]{64}$/i;
const ED25519_SIGNATURE_BASE64URL = /^[A-Za-z0-9_-]{85}[AQgw](?:==)?$/;
const TELEGRAM_PUBLIC_KEYS = {
    prod: hexToBytes(
        "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d",
    )!,
    test: hexToBytes(
        "40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec",
    )!,
} as const;
type ThirdPartyEnvironment = keyof typeof TELEGRAM_PUBLIC_KEYS;
const telegramPublicKeyPromises: Partial<
    Record<ThirdPartyEnvironment, Promise<CryptoKey>>
> = {};

export interface Validator {
    checkSignature(
        payload: Payload,
        options?: ValidationOptions,
    ): Promise<boolean>;
    validateWebAppData(
        initData: URLSearchParams,
        options?: ValidationOptions,
    ): Promise<boolean>;
}

export function createValidator(token: string): Validator {
    return {
        checkSignature: (...args) => checkSignature(token, ...args),
        validateWebAppData: (...args) => validateWebAppData(token, ...args),
    };
}

export async function checkSignature(
    token: string,
    { hash, ...data }: Payload,
    options: ValidationOptions = {},
) {
    const expected = hexToBytes(hash);
    if (!expected) return false;
    const secretKey = await sha256(token);
    if (!await compareHmac(secretKey, expected, data)) return false;
    return validateMaxAge(data.auth_date, options.maxAgeSeconds);
}

export async function validateWebAppData(
    token: string,
    initData: URLSearchParams,
    options: ValidationOptions = {},
) {
    const { hash, ...data } = Object.fromEntries(initData.entries());
    const expected = hexToBytes(hash);
    if (!expected) return false;
    const secretKey = await hmacSha256(WEB_APP_DATA, token);
    if (!await compareHmac(secretKey, expected, data)) return false;
    return validateMaxAge(data.auth_date, options.maxAgeSeconds);
}

export interface ThirdPartyValidator {
    validateWebAppData(
        initData: URLSearchParams,
        options?: ThirdPartyValidationOptions,
    ): Promise<boolean>;
}

export function createThirdPartyValidator(botId: number): ThirdPartyValidator {
    return {
        validateWebAppData: (...args) =>
            validateWebAppDataThirdParty(botId, ...args),
    };
}

export async function validateWebAppDataThirdParty(
    botId: number,
    initData: URLSearchParams,
    options: ThirdPartyValidationOptions = {},
) {
    const environment = options.environment ?? "prod";
    const { hash: _, signature, ...data } = Object.fromEntries(
        initData.entries(),
    );
    const signatureBytes = base64UrlToBytes(signature);
    if (!signatureBytes) return false;

    const message = `${botId}:WebAppData\n${dataCheckString(data)}`;
    const publicKey = await getTelegramPublicKey(environment);
    const valid = await crypto.subtle.verify(
        { name: "Ed25519" },
        publicKey,
        signatureBytes,
        enc.encode(message),
    );
    if (!valid) return false;
    return validateMaxAge(data.auth_date, options.maxAgeSeconds);
}

function validateMaxAge(
    authDate: string | number | undefined,
    maxAgeSeconds: number | undefined,
) {
    if (maxAgeSeconds === undefined) return true;

    if (
        (typeof authDate === "string" && !/^\d+$/.test(authDate)) ||
        (typeof authDate !== "string" && typeof authDate !== "number")
    ) {
        return false;
    }
    const timestamp = Number(authDate);
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) return false;

    const now = Math.floor(Date.now() / 1000);
    return timestamp <= now && now <= timestamp + maxAgeSeconds;
}

async function compareHmac(
    secretKey: Uint8Array<ArrayBuffer>,
    expected: Uint8Array,
    data: Payload,
) {
    return compareHashes(
        expected,
        await hmacSha256(secretKey, dataCheckString(data)),
    );
}

function dataCheckString(data: Payload) {
    return Object.keys(data)
        .filter((k) => typeof data[k] !== "undefined")
        .sort()
        .map((k) => `${k}=${data[k]}`)
        .join("\n");
}

function getTelegramPublicKey(environment: ThirdPartyEnvironment) {
    return telegramPublicKeyPromises[environment] ??= crypto.subtle.importKey(
        "raw",
        TELEGRAM_PUBLIC_KEYS[environment],
        { name: "Ed25519" },
        false,
        ["verify"],
    );
}

function base64UrlToBytes(value: unknown): Uint8Array<ArrayBuffer> | undefined {
    if (typeof value !== "string" || !ED25519_SIGNATURE_BASE64URL.test(value)) {
        return undefined;
    }

    const unpadded = value.endsWith("==") ? value.slice(0, -2) : value;
    const base64 = unpadded.replaceAll("-", "+").replaceAll("_", "/") +
        "==";
    try {
        const binary = atob(base64);
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        return bytes.length === 64 ? bytes : undefined;
    } catch {
        return undefined;
    }
}

async function sha256(payload: string) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        enc.encode(payload),
    );
    return new Uint8Array(digest);
}

async function hmacSha256(key: Uint8Array<ArrayBuffer>, msg: string) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
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
function hexToBytes(hex: unknown): Uint8Array<ArrayBuffer> | undefined {
    if (typeof hex !== "string" || !SHA256_HEX.test(hex)) return undefined;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Number.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
