import { assert, assertEquals } from "@std/assert";
import {
    checkSignature,
    type Payload,
    validateWebAppData,
    validateWebAppDataThirdParty,
    type ValidationOptions,
} from "../src/mod.ts";

const TOKEN = "123456:ABC-DEF";
const WEB_APP_HASH =
    "9dc8130af32fc091679f737ac7531bfd321296e2e7761519e088cfa93a6978ef";
const LOGIN_HASH =
    "9020da6dd66cb89313866c863f7c4f0163113038d0a58701df4e5b91999247ea";

function webAppData(hash?: string) {
    const initData = new URLSearchParams({
        auth_date: "1700000000",
        query_id: "AAEAAAE",
        user: '{"id":1,"first_name":"Test"}',
    });
    if (hash !== undefined) initData.set("hash", hash);
    return initData;
}

function loginData(hash: string | number | undefined) {
    return {
        id: 1,
        first_name: "Test",
        username: "test_user",
        auth_date: 1700000000,
        hash,
    };
}

Deno.test("accepts valid lowercase and uppercase hashes", async () => {
    assertEquals(
        await validateWebAppData(TOKEN, webAppData(WEB_APP_HASH)),
        true,
        "lowercase hash",
    );
    assertEquals(
        await validateWebAppData(TOKEN, webAppData(WEB_APP_HASH.toUpperCase())),
        true,
        "uppercase hash",
    );
    assertEquals(
        await checkSignature(TOKEN, loginData(LOGIN_HASH)),
        true,
        "login hash",
    );
});

Deno.test("rejects missing, empty, and non-string hashes", async () => {
    assertEquals(
        await validateWebAppData(TOKEN, webAppData()),
        false,
        "missing hash",
    );
    assertEquals(
        await validateWebAppData(TOKEN, webAppData("")),
        false,
        "empty hash",
    );
    assertEquals(
        await checkSignature(TOKEN, loginData(undefined)),
        false,
        "missing login hash",
    );
    assertEquals(
        await checkSignature(TOKEN, loginData(123)),
        false,
        "non-string login hash",
    );
});

Deno.test("rejects hashes with invalid lengths", async () => {
    for (
        const [name, hash] of [
            ["odd", "a".repeat(63)],
            ["short", "a".repeat(62)],
            ["long", "a".repeat(66)],
        ]
    ) {
        assertEquals(
            await validateWebAppData(TOKEN, webAppData(hash)),
            false,
            `${name} hash`,
        );
    }
});

Deno.test("rejects malformed and incorrect hashes", async () => {
    const partiallyParseableWebHash = WEB_APP_HASH.replace("0a", "ag");
    const partiallyParseableLoginHash = LOGIN_HASH.replace("01", "1g");

    assertEquals(partiallyParseableWebHash.length, 64, "web hash length");
    assertEquals(partiallyParseableLoginHash.length, 64, "login hash length");
    assertEquals(
        await validateWebAppData(TOKEN, webAppData(partiallyParseableWebHash)),
        false,
        "partially parseable web hash",
    );
    assertEquals(
        await checkSignature(TOKEN, loginData(partiallyParseableLoginHash)),
        false,
        "partially parseable login hash",
    );
    assertEquals(
        await validateWebAppData(TOKEN, webAppData("z".repeat(64))),
        false,
        "non-hexadecimal hash",
    );
    assertEquals(
        await validateWebAppData(
            TOKEN,
            webAppData(`8${WEB_APP_HASH.substring(1)}`),
        ),
        false,
        "well-formed incorrect hash",
    );
});

const enc = new TextEncoder();
const WEB_APP_DATA = enc.encode("WebAppData");

async function sha256(value: string) {
    return new Uint8Array(
        await crypto.subtle.digest("SHA-256", enc.encode(value)),
    );
}

async function hmacSha256(key: Uint8Array<ArrayBuffer>, value: string) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    return new Uint8Array(
        await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(value)),
    );
}

function dataCheckString(data: Payload) {
    return Object.keys(data)
        .filter((key) => data[key] !== undefined)
        .sort()
        .map((key) => `${key}=${data[key]}`)
        .join("\n");
}

function toHex(value: Uint8Array) {
    return Array.from(value, (byte) => byte.toString(16).padStart(2, "0"))
        .join("");
}

async function loginPayload(authDate?: string | number) {
    const data: Payload = {
        id: "424242424242",
        first_name: "John",
        auth_date: authDate,
    };
    const secretKey = await sha256(TOKEN);
    const hash = toHex(await hmacSha256(secretKey, dataCheckString(data)));
    return { ...data, hash };
}

async function signedWebAppData(authDate?: string | number) {
    const data: Payload = {
        query_id: "AAHdF6IQAAAAAN0XohDhrOrc",
        auth_date: authDate,
    };
    const secretKey = await hmacSha256(WEB_APP_DATA, TOKEN);
    const hash = toHex(await hmacSha256(secretKey, dataCheckString(data)));
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(data)) {
        if (value !== undefined) params.set(key, String(value));
    }
    params.set("hash", hash);
    return params;
}

type Fixture = {
    name: string;
    create(authDate?: string | number): Promise<Payload | URLSearchParams>;
    validate(
        data: Payload | URLSearchParams,
        options?: ValidationOptions,
    ): Promise<boolean>;
    tamper(data: Payload | URLSearchParams): void;
};

const fixtures: Fixture[] = [
    {
        name: "Login Widget",
        create: loginPayload,
        validate: (data, options) =>
            checkSignature(TOKEN, data as Payload, options),
        tamper: (data) => {
            const payload = data as Payload;
            const hash = String(payload.hash);
            payload.hash = `${hash.slice(0, -1)}${
                hash.endsWith("0") ? "1" : "0"
            }`;
        },
    },
    {
        name: "Web App",
        create: signedWebAppData,
        validate: (data, options) =>
            validateWebAppData(TOKEN, data as URLSearchParams, options),
        tamper: (data) => {
            const params = data as URLSearchParams;
            const hash = params.get("hash")!;
            params.set(
                "hash",
                `${hash.slice(0, -1)}${hash.endsWith("0") ? "1" : "0"}`,
            );
        },
    },
];

for (const fixture of fixtures) {
    Deno.test(`${fixture.name} accepts fresh authorization data`, async () => {
        const now = Math.floor(Date.now() / 1000);
        const data = await fixture.create(now);
        assert(await fixture.validate(data, { maxAgeSeconds: 60 }));
    });

    Deno.test(`${fixture.name} rejects expired authorization data`, async () => {
        const expired = Math.floor(Date.now() / 1000) - 61;
        const data = await fixture.create(expired);
        assertEquals(
            await fixture.validate(data, { maxAgeSeconds: 60 }),
            false,
        );
    });

    Deno.test(`${fixture.name} rejects future authorization data`, async () => {
        const future = Math.floor(Date.now() / 1000) + 60;
        const data = await fixture.create(future);
        assertEquals(
            await fixture.validate(data, { maxAgeSeconds: 60 }),
            false,
        );
    });

    Deno.test(`${fixture.name} requires a valid auth_date when checking age`, async () => {
        for (
            const authDate of [
                undefined,
                "invalid",
                "-1",
                "1.5",
                -1,
                1.5,
                Number.NaN,
            ]
        ) {
            const data = await fixture.create(authDate);
            assertEquals(
                await fixture.validate(data, { maxAgeSeconds: 60 }),
                false,
            );
        }
    });

    Deno.test(`${fixture.name} preserves validation without an age limit`, async () => {
        const data = await fixture.create(undefined);
        assert(await fixture.validate(data));
    });

    Deno.test(`${fixture.name} rejects a tampered signature with a fresh timestamp`, async () => {
        const now = Math.floor(Date.now() / 1000);
        const data = await fixture.create(now);
        fixture.tamper(data);
        assertEquals(
            await fixture.validate(data, { maxAgeSeconds: 60 }),
            false,
        );
    });
}

const THIRD_PARTY_BOT_ID = 7342037359;
const THIRD_PARTY_INIT_DATA =
    "user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%20%2B%20-%20%3F%20%5C%2F%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2F4FPEE4tmP3ATHa57u6MqTDih13LTOiMoKoLDRG4PnSA.svg%22%7D&chat_instance=8134722200314281151&chat_type=private&auth_date=1733584787&hash=2174df5b000556d044f3f020384e879c8efcab55ddea2ced4eb752e93e7080d6&signature=zL-ucjNyREiHDE8aihFwpfR9aggP2xiAo3NSpfe-p7IbCisNlDKlo7Kb6G4D0Ao2mBrSgEk4maLSdv6MLIlADQ";

function thirdPartyInitData() {
    return new URLSearchParams(THIRD_PARTY_INIT_DATA);
}

Deno.test("validates third-party Mini App data with the prod key", async () => {
    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID,
            thirdPartyInitData(),
        ),
        true,
    );
    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID,
            thirdPartyInitData(),
            { environment: "prod" },
        ),
        true,
    );
});

Deno.test("accepts padded and unpadded base64url signatures", async () => {
    const padded = thirdPartyInitData();
    padded.set("signature", `${padded.get("signature")}==`);

    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID,
            thirdPartyInitData(),
        ),
        true,
        "unpadded",
    );
    assertEquals(
        await validateWebAppDataThirdParty(THIRD_PARTY_BOT_ID, padded),
        true,
        "padded",
    );
});

Deno.test("rejects third-party data that does not match the signature", async () => {
    const alteredData = thirdPartyInitData();
    alteredData.set("chat_type", "group");

    const alteredSignature = thirdPartyInitData();
    const signature = alteredSignature.get("signature")!;
    alteredSignature.set(
        "signature",
        `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`,
    );

    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID + 1,
            thirdPartyInitData(),
        ),
        false,
        "bot ID",
    );
    assertEquals(
        await validateWebAppDataThirdParty(THIRD_PARTY_BOT_ID, alteredData),
        false,
        "signed field",
    );
    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID,
            alteredSignature,
        ),
        false,
        "signature",
    );
    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID,
            thirdPartyInitData(),
            { environment: "test" },
        ),
        false,
        "environment",
    );
});

Deno.test("excludes hash from third-party signature verification", async () => {
    const data = thirdPartyInitData();
    data.set("hash", "not-used-by-third-party-validation");
    assertEquals(
        await validateWebAppDataThirdParty(THIRD_PARTY_BOT_ID, data),
        true,
    );
});

Deno.test("rejects missing and malformed Ed25519 signatures", async () => {
    const signature = thirdPartyInitData().get("signature")!;
    const invalidSignatures = [
        undefined,
        "",
        signature.slice(0, -1),
        `${signature}=`,
        `${signature}===`,
        `${signature.slice(0, -1)}!`,
        `${signature.slice(0, -1)}B`,
    ];

    for (const invalidSignature of invalidSignatures) {
        const data = thirdPartyInitData();
        if (invalidSignature === undefined) data.delete("signature");
        else data.set("signature", invalidSignature);
        assertEquals(
            await validateWebAppDataThirdParty(THIRD_PARTY_BOT_ID, data),
            false,
            String(invalidSignature),
        );
    }
});

Deno.test("rejects invalid bot IDs", async () => {
    for (
        const botId of [
            0,
            -1,
            1.5,
            Number.NaN,
            Number.POSITIVE_INFINITY,
            Number.MAX_SAFE_INTEGER + 1,
        ]
    ) {
        assertEquals(
            await validateWebAppDataThirdParty(botId, thirdPartyInitData()),
            false,
            String(botId),
        );
    }
});

Deno.test("third-party validation supports maxAgeSeconds", async () => {
    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID,
            thirdPartyInitData(),
        ),
        true,
        "age check omitted",
    );
    assertEquals(
        await validateWebAppDataThirdParty(
            THIRD_PARTY_BOT_ID,
            thirdPartyInitData(),
            { maxAgeSeconds: 0 },
        ),
        false,
        "historical data",
    );
});
