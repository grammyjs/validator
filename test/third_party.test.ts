// deno-lint-ignore-file no-import-prefix
import {
    assertEquals,
    assertStrictEquals,
} from "https://deno.land/std@0.211.0/assert/mod.ts";
import { validateThirdPartyWebAppData } from "../src/mod.ts";

// Generates an Ed25519 keypair, signs a data-check-string with the same layout
// Telegram uses, and verifies the round-trip against a monkey-patched
// `crypto.subtle.importKey` that returns our test public key.
async function withKeypair<T>(
    fn: (tools: {
        sign: (
            botId: number | string,
            params: URLSearchParams,
        ) => Promise<string>;
    }) => Promise<T>,
): Promise<T> {
    const pair = await crypto.subtle.generateKey("Ed25519", true, [
        "sign",
        "verify",
    ]) as CryptoKeyPair;
    const origImportKey = crypto.subtle.importKey.bind(crypto.subtle);
    // Every call inside validateThirdPartyWebAppData asks for the Telegram public
    // key; swap it for ours for the duration of the test.
    crypto.subtle.importKey = ((...args: Parameters<typeof origImportKey>) => {
        const [, , algorithm] = args;
        if (
            typeof algorithm === "object" && algorithm &&
            "name" in algorithm &&
            (algorithm as { name: string }).name === "Ed25519"
        ) {
            return Promise.resolve(pair.publicKey);
        }
        return origImportKey(...args);
    }) as typeof origImportKey;
    try {
        const sign = async (
            botId: number | string,
            params: URLSearchParams,
        ) => {
            const dataCheckString = [`${botId}:WebAppData`]
                .concat(
                    [...params.entries()]
                        .filter(([k]) => k !== "hash" && k !== "signature")
                        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
                        .map(([k, v]) => `${k}=${v}`),
                )
                .join("\n");
            const sig = new Uint8Array(
                await crypto.subtle.sign(
                    "Ed25519",
                    pair.privateKey,
                    new TextEncoder().encode(dataCheckString),
                ),
            );
            let bin = "";
            for (const b of sig) bin += String.fromCharCode(b);
            return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(
                /=+$/,
                "",
            );
        };
        return await fn({ sign });
    } finally {
        crypto.subtle.importKey = origImportKey;
    }
}

Deno.test("validateThirdPartyWebAppData accepts a valid signature", async () => {
    await withKeypair(async ({ sign }) => {
        const botId = 1234567890;
        const params = new URLSearchParams();
        params.set("auth_date", "1712000000");
        params.set("query_id", "AAE");
        params.set("user", '{"id":42,"first_name":"Ada"}');
        params.set("hash", "deadbeef"); // ignored by third-party path
        params.set("signature", await sign(botId, params));

        assertStrictEquals(
            await validateThirdPartyWebAppData(botId, params),
            true,
        );
    });
});

Deno.test("validateThirdPartyWebAppData rejects a tampered payload", async () => {
    await withKeypair(async ({ sign }) => {
        const botId = 1234567890;
        const params = new URLSearchParams();
        params.set("auth_date", "1712000000");
        params.set("query_id", "AAE");
        params.set("user", '{"id":42,"first_name":"Ada"}');
        params.set("signature", await sign(botId, params));
        // Mutate a field after signing.
        params.set("user", '{"id":99,"first_name":"Mallory"}');

        assertStrictEquals(
            await validateThirdPartyWebAppData(botId, params),
            false,
        );
    });
});

Deno.test("validateThirdPartyWebAppData rejects a wrong bot id", async () => {
    await withKeypair(async ({ sign }) => {
        const params = new URLSearchParams();
        params.set("auth_date", "1712000000");
        params.set("user", '{"id":42}');
        params.set("signature", await sign(1234567890, params));

        assertStrictEquals(
            await validateThirdPartyWebAppData(9999999999, params),
            false,
        );
    });
});

Deno.test("validateThirdPartyWebAppData returns false when signature is missing", async () => {
    const params = new URLSearchParams();
    params.set("auth_date", "1712000000");
    params.set("user", '{"id":42}');
    assertEquals(await validateThirdPartyWebAppData(1, params), false);
});

Deno.test("validateThirdPartyWebAppData returns false on malformed signature", async () => {
    const params = new URLSearchParams();
    params.set("auth_date", "1712000000");
    params.set("signature", "!!!not-base64url!!!");
    assertEquals(await validateThirdPartyWebAppData(1, params), false);
});
