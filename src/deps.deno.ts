import { createHash, createHmac } from "https://deno.land/std@0.160.0/node/crypto.ts"

export function sha256 (payload: string) {
    return createHash("sha256").update(payload).digest() as Uint8Array
}

export function hmacSha256 (key: string | Uint8Array, msg: string) {
    return createHmac("sha256", key).update(msg).digest() as Uint8Array
}

export function hmacSha256Hex (key: string | Uint8Array, msg: string) {
    return createHmac("sha256", key).update(msg).digest("hex") as string
}

export function sha256Async (payload: string) {
    return new Promise<Uint8Array>((resolve, reject) => {
        const hash = createHash("sha256")
        hash.on("readable", () => {
            const data = hash.read()
            if (data) resolve(data)
        })
        hash.on("error", (error) => reject(error))
        hash.write(payload)
        hash.end()
    })
}

function hmacSha256AsyncBase (key: string | Uint8Array, msg: string, digest: null): Promise<Uint8Array>
function hmacSha256AsyncBase (key: string | Uint8Array, msg: string, digest: 'utf-8' | 'hex' | 'base64'): Promise<string>
function hmacSha256AsyncBase (key: string | Uint8Array, msg: string, digest: 'utf-8' | 'hex' | 'base64' | null): Promise<Uint8Array | string> {
    return new Promise<Uint8Array>((resolve, reject) => {
        const hash = createHmac("sha256", key)
        hash.on("readable", () => {
            const data = hash.read()
            if (data) {
                if (digest) {
                    return resolve(data.toString(digest))
                }
                return resolve(data)
            }
        })
        hash.on("error", (error) => reject(error))
        hash.write(msg)
        hash.end()
    })
}

export function hmacSha256Async (key: string | Uint8Array, msg: string) {
    return hmacSha256AsyncBase(key, msg, null)
}

export function hmacSha256AsyncHex (key: string | Uint8Array, msg: string) {
    return hmacSha256AsyncBase(key, msg, 'hex')
}

