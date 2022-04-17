# <h1 align="center">grammY validator</h1>

---

## What is this

This package solves two problems at once:

- [Validating data received via **Web Apps for a Telegram Bot**](https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app)
- [Checking authorization data for **Telegram Login Widget**](https://core.telegram.org/widgets/login#checking-authorization)

## How to use

**Deno**: import from this URL: `https://deno.land/x/grammy_validator/mod.ts`

**Node.js**: `npm install @grammyjs/validator`

### Web Bots: Validation

Web Bots can get access to `window.Telegram.WebApp.initData` which must be sent to the server for validation.
The string value of `initData` is a query string that you can simply append to a URL to fetch.
Example:

```ts
const url = "https://grammy.dev?" + window.Telegram.WebApp.initData;
await fetch(url);
```

This library helps you validate the resulting search query in the backend.

```ts
import { validateWebAppData } from "./src/mod.ts";

const token = ""; // <-- put your bot token here
const url = ctx.request.url; // get `URL` object from your web framework

if (validateWebAppData(token, url.searchParams)) { // pass `URLSearchParams` object
    // data is from Telegram
}
```

### Login Widget: Authorization

You can also check the signature if you are using a Telegram Login Widget.

```ts
import { checkSignature } from "./src/mod.ts";

const token = ""; // <-- put your bot token here

const payload = {
    id: "424242424242",
    first_name: "John",
    last_name: "Doe",
    username: "username",
    photo_url: "https://t.me/i/userpic/320/username.jpg",
    auth_date: "1519400000",
    hash: "87e5a7e644d0ee362334d92bc8ecc981ca11ffc11eca809505",
};

if (checkSignature(token, payload)) {
    // data is from Telegram
}
```
