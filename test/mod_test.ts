import { assertEquals } from "@std/assert/equals";
import { checkSignature, validateWebAppData } from "../src/mod.ts";

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
